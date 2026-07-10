#!/usr/bin/env bash
# Publish the wedge-rp relying-party SDKs to their package registries.
# Usage: ./publish-sdks.sh [-p|--publish]
#
# Each SDK carries its own semver (independent of the app's VERSION), so this is
# a separate tool from build.sh — it reads the version from each package's own
# manifest and publishes THAT.
#
# Default is a DRY RUN: it builds the Python package, runs `npm publish
# --dry-run`, reports whether each version is already live, and prints the
# Packagist procedure — without uploading anything. Pass -p / --publish to
# actually push to PyPI and npm.
#
# Registries:
#   - Python  wedge-rp          -> PyPI      (twine upload)      [automated]
#   - Node    wedge-rp          -> npm       (npm publish)       [automated]
#   - PHP     wedge/wedge-rp    -> Packagist (git tag + submit)  [instructions]
#
# PHP is instructions-only: public Packagist reads composer.json from a repo
# ROOT, but this package's manifest lives at sdk/php/, so it cannot be published
# from the monorepo — it needs a one-time split into a standalone repo (below).
#
# -p / --publish requires: a clean committed tree, the tools each registry needs
# (twine + `python -m build` for PyPI, npm for npm), and registry credentials
# (twine: ~/.pypirc or TWINE_*; npm: `npm login` / ~/.npmrc). An already-live
# version is skipped, not re-uploaded (registries reject re-publishing).
set -euo pipefail
cd "$(dirname "$0")"

PUBLISH=0
for a in "$@"; do
  case "$a" in
    -p|--publish) PUBLISH=1 ;;
    -h|--help) sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown flag: $a (usage: ./publish-sdks.sh [-p|--publish])" >&2; exit 1 ;;
  esac
done

mode() { [ "$PUBLISH" = 1 ] && echo "PUBLISH" || echo "dry-run"; }
echo "wedge-rp SDK publish ($(mode))"
echo

# Preflight everything before any upload, so a missing tool can't leave a
# partial publish (PyPI up, npm aborted). Mirrors build.sh's fail-fast block.
if [ "$PUBLISH" = 1 ]; then
  git diff-index --quiet HEAD -- || {
    echo "publish needs a clean tree — commit first (published artifacts must match committed code)" >&2
    exit 1
  }
  missing=()
  command -v twine >/dev/null 2>&1 || missing+=("twine (pipx install twine) — with PyPI creds in ~/.pypirc or TWINE_*")
  ( cd sdk/python && python3 -m build --version >/dev/null 2>&1 ) || missing+=("python build (pip install build)")
  command -v npm >/dev/null 2>&1 || missing+=("npm — logged in (npm login / ~/.npmrc)")
  if [ "${#missing[@]}" -gt 0 ]; then
    echo "publish is missing:" >&2
    printf '  - %s\n' "${missing[@]}" >&2
    exit 1
  fi
fi

# Fresh build dir per run, auto-removed — never re-uploads a stale artifact.
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# pypi_has_version NAME VERSION -> 0 live, 1 not published, 2 undetermined.
pypi_has_version() {
  python3 - "$1" "$2" <<'PY'
import sys, urllib.request, urllib.error
name, ver = sys.argv[1], sys.argv[2]
try:
    with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{ver}/json", timeout=10) as r:
        sys.exit(0 if r.status == 200 else 1)
except urllib.error.HTTPError as e:
    sys.exit(1 if e.code == 404 else 2)
except Exception:
    sys.exit(2)
PY
}

# ---- Python -> PyPI ----------------------------------------------------------
publish_python() {
  local dir="sdk/python" name version
  name="$(python3 -c "import tomllib;print(tomllib.load(open('$dir/pyproject.toml','rb'))['project']['name'])")"
  version="$(python3 -c "import tomllib;print(tomllib.load(open('$dir/pyproject.toml','rb'))['project']['version'])")"
  echo "== PyPI: $name $version"

  # Check the tool from inside sdk/python — the repo-root `build/` dir (icons)
  # would otherwise shadow the PyPI `build` package and give a false positive.
  if ! ( cd "$dir" && python3 -m build --version >/dev/null 2>&1 ); then
    local msg="python 'build' tool missing — pip install build (and twine)"
    [ "$PUBLISH" = 1 ] && { echo "  $msg" >&2; return 1; } || { echo "  skip: $msg"; return 0; }
  fi
  ( cd "$dir" && python3 -m build --outdir "$TMP/py" ) >/dev/null
  echo "  built: $(cd "$TMP/py" && echo *)"
  command -v twine >/dev/null 2>&1 && twine check "$TMP/py"/* >/dev/null && echo "  twine check: ok"

  case "$(pypi_has_version "$name" "$version"; echo $?)" in
    0) echo "  already on PyPI — skipping"; return 0 ;;
    2) echo "  (could not reach PyPI to check for an existing $version)" ;;
  esac

  if [ "$PUBLISH" = 1 ]; then
    command -v twine >/dev/null 2>&1 || { echo "  twine missing — pipx install twine" >&2; return 1; }
    twine upload "$TMP/py"/*
    echo "  uploaded to PyPI"
  else
    echo "  would upload to PyPI (rerun with --publish)"
  fi
}

# ---- Node -> npm -------------------------------------------------------------
publish_node() {
  local dir="sdk/node" name version
  name="$(python3 -c "import json;print(json.load(open('$dir/package.json'))['name'])")"
  version="$(python3 -c "import json;print(json.load(open('$dir/package.json'))['version'])")"
  echo "== npm: $name $version"

  if ! command -v npm >/dev/null 2>&1; then
    [ "$PUBLISH" = 1 ] && { echo "  npm missing" >&2; return 1; } || { echo "  skip: npm missing"; return 0; }
  fi
  if [ -n "$(npm view "$name@$version" version 2>/dev/null)" ]; then
    echo "  already on npm — skipping"; return 0
  fi

  if [ "$PUBLISH" = 1 ]; then
    ( cd "$dir" && npm publish )
    echo "  published to npm"
  else
    ( cd "$dir" && npm publish --dry-run )
    echo "  (dry run — rerun with --publish)"
  fi
}

# ---- PHP -> Packagist (instructions only) ------------------------------------
publish_php() {
  echo "== Packagist: wedge/wedge-rp"
  cat <<'EOF'
  Not automated: public Packagist reads composer.json from a repo ROOT, but
  this package's manifest is at sdk/php/. Publish it once, out of band:
    1. Split sdk/php/ into a standalone repo with composer.json at its root
       (git subtree split -P sdk/php -b php-split, push that branch to a new
       public repo — a Dan decision; adds a public remote).
    2. Tag it with the SemVer (e.g. v0.2.0) and push the tag.
    3. Submit the repo URL once at https://packagist.org/packages/submit
       (claims the unused 'wedge' vendor); a webhook auto-updates it thereafter.
EOF
}

publish_python
echo
publish_node
echo
publish_php
echo
echo "done ($(mode))."
