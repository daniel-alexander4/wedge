# wedge

**SSH-key web authentication.** wedge lets you sign in to websites with the
SSH keys already in your ssh-agent: a site shows a "Sign in with wedge"
button, your wedge app asks for one tap, `ssh-keygen` signs a per-login
challenge through your agent, and the site verifies it the same way `sshd`
would. No passwords, no WebAuthn ceremony, no cloud — your keys never leave
your machine, and every signature is bound to one origin.

wedge is a single Go binary that serves its own UI over a loopback HTTP
server and opens it in a chromeless browser window. Websites reach it through
the `wedge://` protocol handler. It also doubles as a launcher: the same
sites list opens web apps in your browser and `ssh://` hosts in your
terminal or your file manager (SFTP), with per-site tunnels and jump hosts,
all keyed to the one agent keyring — from the settings window or straight
from the system tray — and it can populate itself from the `Host` aliases
in your `~/.ssh/config`.

## Install

Linux (builds a `.deb` and installs it, including the menu entry and the
`wedge://` handler):

```bash
./install.sh
```

Or run from source: `make run` (`WEDGE_NO_BROWSER=1` for headless).
Release artifacts for all platforms: `./build.sh`. macOS/Windows `wedge://`
handler registration is currently manual — see `docs/wedge-protocol.md` §9.

## The protocol

The wire protocol is specified in **[docs/wedge-spec-v1.md](docs/wedge-spec-v1.md)** —
a normative, RFC-2119 spec written for relying-party implementers, covering
the browser-initiated Core flow, the optional app-initiated flow, schemas,
and the security model (origin-bound namespaces, single-use challenges,
browser binding, mandatory user presence).

## Add "Sign in with wedge" to your site

Drop-in relying-party middleware, ~10 minutes each, zero runtime
dependencies (the only external requirement is the `ssh-keygen` binary,
OpenSSH 8.1+):

| Language | Package | Adapter(s) | Where |
|---|---|---|---|
| Python | `wedge-rp` (pip) | Flask blueprint | [`sdk/python/`](sdk/python/) |
| Node | `wedge-rp` (npm) | Express router | [`sdk/node/`](sdk/node/) |
| Go | `.../sdk/go/wedgerp` | `net/http` handler | [`sdk/go/`](sdk/go/) |
| PHP | `wedge/wedge-rp` (Composer) | vanilla PHP, PSR-15, Laravel | [`sdk/php/`](sdk/php/) |

Each package implements every RP requirement of the spec, ships a runnable
demo, and carries a conformance test suite kept test-for-test in lockstep
with the others. Each README is the integration guide.

To verify any RP — one of these or your own — against the spec over the wire,
run the conformance harness: `go run ./cmd/wedge-conform --target <origin>`
(see [`docs/wedge-conformance.md`](docs/wedge-conformance.md)). It drives the
RP as an authenticator would and checks every wire-observable RP requirement.

Maintainers publish the SDKs with `./publish-sdks.sh` (dry run; `--publish` to
push). Each SDK carries its own semver, so this is separate from the app
release (`build.sh`). It automates **PyPI** (`wedge-rp`) and **npm**
(`wedge-rp`); the **Go** package is `go get`-able straight from the release git
tag; **Packagist** (`wedge/wedge-rp`) needs a one-time split of `sdk/php/` into
a standalone repo (the script prints the steps).

## Repo layout

- `cmd/wedge/`, `internal/`, `web/` — the wedge app (Go + embedded UI)
- `cmd/wedge-conform/` — the black-box RP conformance harness
- `docs/wedge-spec-v1.md` — the normative protocol spec;
  `docs/wedge-protocol.md` — app implementation notes;
  `docs/wedge-conformance.md` — the conformance harness
- `sdk/{python,node,go,php}/` — the relying-party middleware
- `build/` — packaging (nfpm, desktop entry, icon set)

## License

MIT (see `LICENSE`).

---

# Legacy: browser extension

wedge began as a cross-browser WebExtension (this repo, pre-rebrand:
`sshkey-web-auth-extension`, started the week of Feb 15, 2026 on PTO). The
extension (`src/`, `native-host/`, `manifests/`) still works and is retired
in Phase 3; its documentation below remains valid until then. It reads login
challenge fields from a compatible `/login` form, asks a native host to sign
with `ssh-keygen -Y sign`, and submits the signed challenge to your backend
verifier.

## Supported Browsers

- Chrome
- Edge
- Firefox
- Safari (via Safari Web Extension packaging)

## Quick Setup (Linux)

If you just want to get up and running:

```bash
./setup.sh
```

This will:
1. Install npm dependencies and build the extension
2. Compute the deterministic Chrome extension ID from `dist/chrome`
3. Install native messaging hosts for Chrome and Firefox

After it finishes, load the extension in your browser and configure origin mappings in the popup. If the native host is not connected, the popup will show the install command with your extension ID pre-filled.

## Developer Install (10-15 Minutes)

Use this path if you want to run the extension locally while developing.

### Prerequisites

- Node.js 20+
- npm
- Python 3
- `ssh-keygen` available on your `PATH`
- A usable SSH private key (default expected path: `~/.ssh/id_ed25519`)

### 1) Build the extension

```bash
npm install
npm run typecheck
npm run test
npm run build:all
```

Build output:
- Chromium browsers: `dist/chrome`
- Firefox: `dist/firefox`

### Install from packaged artifacts

If you already have packaged files (for example from `dist/artifacts`):
- `sshkey-web-auth-<version>-chromium.zip`
- `sshkey-web-auth-<version>-firefox.xpi`

Chromium (Chrome/Edge/Brave/Chromium):
1. Unzip `sshkey-web-auth-<version>-chromium.zip` to a folder.
2. Open your extensions page:
   - Chrome: `chrome://extensions`
   - Edge: `edge://extensions`
   - Brave: `brave://extensions`
3. Enable Developer mode.
4. Click Load unpacked and select the unzipped folder.

Firefox:
1. Open `about:debugging#/runtime/this-firefox`.
2. Click Load Temporary Add-on.
3. Select `sshkey-web-auth-<version>-firefox.xpi` (or `manifest.json` from an extracted package).

Note: unsigned `.xpi` builds are for local development/testing. Permanent install on stable Firefox requires AMO signing.

### 2) Load the extension in your browser

Chromium (Chrome/Edge/Brave/Chromium):
1. Open the extensions page:
   - Chrome: `chrome://extensions`
   - Edge: `edge://extensions`
   - Brave: `brave://extensions`
2. Enable Developer mode
3. Click Load unpacked and select `dist/chrome`
4. Copy the extension ID (required for native host setup)

Firefox:
1. Open `about:debugging#/runtime/this-firefox`
2. Click Load Temporary Add-on
3. Select `dist/firefox/manifest.json`

### 3) Install native messaging host

From repo root, run one of the following.

Linux:
```bash
cd native-host
./install-linux.sh --chrome --extension-id <CHROMIUM_EXTENSION_ID> --firefox
```

macOS:
```bash
cd native-host
./install-macos.sh --firefox
./install-macos.sh --chrome --extension-id <CHROMIUM_EXTENSION_ID>
```

Windows (PowerShell):
```powershell
cd native-host
.\install-windows.ps1 -Firefox
.\install-windows.ps1 -Chrome -ExtensionId <CHROMIUM_EXTENSION_ID>
```

Firefox-only setup (any OS):
- Linux: `./install-linux.sh --firefox`
- macOS: `./install-macos.sh --firefox`
- Windows: `.\install-windows.ps1 -Firefox`

### 4) Configure extension settings

Open the extension popup/options and set:
- `Native host name`: `com.pubkey.auth`
- `SSH private key path`: path to your private key
- `Origin mappings`: `<origin> <namespace>` or `<origin> <company> <namespace>`
  - allowed origins are derived from these mappings

### 5) Verify end-to-end locally

1. Open your `/login` page.
2. Submit with the extension enabled.
3. Confirm `signature` is populated and `/auth/verify` succeeds.

If it fails:
- Re-run the OS installer script.
- Confirm your Chromium extension ID in native host manifests.
- Rebuild with `DEBUG=true npm run build:all` and inspect extension logs.

Optional environment overrides:

```bash
export PUBKEY_AUTH_KEY_PATH=~/.ssh/id_ed25519
export SSH_KEYGEN_PATH=/usr/bin/ssh-keygen
export PUBKEY_AUTH_SIGN_TIMEOUT_SECONDS=10
```

## Development Setup

```bash
npm install
npm run typecheck
npm run test
npm run dev:chrome
```

Debug build logging:

```bash
DEBUG=true npm run build:all
```

With `DEBUG=true`, extension logs are emitted from popup/content/background with a `[sshkey-web-auth:*]` prefix.

## Extension Settings

Configure in popup/options:
- `Native host name` (default `com.pubkey.auth`)
- `SSH private key path`
- `Origin mappings` (one line: `<origin> <namespace>` or `<origin> <company> <namespace>`)
  - allowed origins are derived from these mappings

Both origin and namespace must exactly match what your website uses.

## Website Integration Contract

Extension triggers only when all are true:
- path: `/login`
- form id: `auth-verify-form`
- submit button id: `login-submit-btn`
- method: `POST`
- action: `/auth/verify` (same origin)

Required form fields:
- `input[name="username"]`
- `textarea[name="signature"]`
- `input[name="ssh_challenge"]`
- `input[name="ssh_namespace"]`
- optional: `input[name="ssh_company"]`

The strict `auth-verify-form` and `login-submit-btn` selectors are intentional. The extension only binds on this exact login structure as a security boundary.

Example:

```html
<form id="auth-verify-form" method="post" action="/auth/verify">
  <input name="username" autocomplete="username" />
  <textarea name="signature" hidden></textarea>
  <input type="hidden" name="ssh_challenge" value="BASE64URL_CHALLENGE" />
  <input type="hidden" name="ssh_company" value="mycompany" />
  <input type="hidden" name="ssh_namespace" value="myapp" />
  <button id="login-submit-btn" type="submit">Login</button>
</form>
```

Backend requirements:
- issue one-time challenge per login
- enforce challenge format and expiration
- verify SSH signature
- verify username <-> public key association
- reject replayed challenges

## Timeout Behavior

- Native host signing timeout defaults to `10s` (`PUBKEY_AUTH_SIGN_TIMEOUT_SECONDS`).
- Signing requests from the content script wait for native host completion and therefore follow `PUBKEY_AUTH_SIGN_TIMEOUT_SECONDS`.
- Popup/options runtime requests use a `12s` guard timeout for settings/status interactions.

## Troubleshooting

- Native host not found:
  - Verify native host manifests exist under browser-specific native messaging directories.
  - Re-run the installer for your OS (`install-linux.sh`, `install-macos.sh`, or `install-windows.ps1`).
- Signing times out:
  - Confirm `ssh-keygen` is available and executable.
  - Set `PUBKEY_AUTH_SIGN_TIMEOUT_SECONDS` to a larger value and retry.
- Key permission failures:
  - Run `chmod 600 <key-path>`.
  - Ensure the key file is owned by your user.
- Debug extension logs:
  - Rebuild with `DEBUG=true npm run build:all`, reload extension, then inspect browser extension console logs.

## Native Host Install (macOS/Windows)

Scripts are provided:
- macOS: `native-host/install-macos.sh`
- Windows: `native-host/install-windows.ps1`

For production packaging checklists, see `store-listings/shared/release-checklist.md`.

## Contributing

See `CONTRIBUTING.md` for local workflow and required checks.

## Security Notes

- Signing is restricted by configured origins and namespace mapping.
- Use TLS in real deployments.
- Keep private keys and API tokens out of source control.
