# Build the gateway from the wedge module root.
# Build context is the repo root: docker build -f sdk/go/examples/forgejo/Dockerfile .
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /forgejo-wedge ./sdk/go/examples/forgejo

FROM alpine:3.20
# The gateway shells out to ssh-keygen to verify signatures (the RP kernel).
RUN apk add --no-cache openssh-keygen
COPY --from=build /forgejo-wedge /usr/local/bin/forgejo-wedge
# Public keys are mounted at /keys; --user names them at runtime (see compose).
ENTRYPOINT ["/usr/local/bin/forgejo-wedge"]
