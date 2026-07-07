# Convenience wrapper over the Go toolchain and build.sh for the wedge app.
.PHONY: build test vet run clean

build:
	./build.sh

test:
	go test ./...

vet:
	go vet ./...

# Run the app locally (opens a chromeless app-mode window).
run:
	go run ./cmd/wedge

clean:
	rm -rf dist
