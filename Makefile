# Convenience wrapper over the cross-compile / packaging scripts. build.sh,
# install.sh, and bump.sh remain the source of truth; this just gives the usual
# `make` entry points.

.PHONY: build dist release publish-sdks install test vet run clean bump-patch bump-minor bump-major

# Quick local dev build into ./dist/wedge (this machine only).
build:
	go build -o ./dist/wedge ./cmd/wedge

# Cross-compile every platform + build the .deb packages into dist/.
dist:
	./build.sh

# Build everything, push main, and publish dist/ as GitHub release v<VERSION>.
# Needs gh + nfpm + a clean tree.
release:
	./build.sh --publish

# Publish the RP SDKs to PyPI + npm (dry run; `./publish-sdks.sh --publish` to
# push). Each SDK has its own semver, so this is separate from `release`.
publish-sdks:
	./publish-sdks.sh

# Build the .deb for this machine and install it (Debian/Ubuntu, sudo).
install:
	./install.sh

test:
	go test ./...

vet:
	go vet ./...

# Run the app locally (opens a chromeless app-mode window).
run:
	go run ./cmd/wedge

clean:
	rm -rf dist

# Bump the semantic version (X.Y.Z) in VERSION — see bump.sh.
# patch = a fix/minor change, minor = a major feature, major = a breaking release.
bump-patch:
	./bump.sh patch
bump-minor:
	./bump.sh minor
bump-major:
	./bump.sh major
