# syntax=docker/dockerfile:1

# Build stage. Current stable Go image; go.mod requires Go 1.26.3 or newer, so
# any image at or above that toolchain works. Build on the build host and
# cross-compile with the TARGET* args, so a multi-arch image does not run Go
# under QEMU.
FROM --platform=$BUILDPLATFORM golang:1.27 AS build

WORKDIR /src

# Cache the module graph before copying the sources.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/gost-mcp ./cmd/gost-mcp

# Runtime stage. distroless/static carries CA certificates and tzdata, which
# the HTTPS tools and the wisp relay need, and has no shell.
FROM gcr.io/distroless/static:nonroot

COPY --from=build /out/gost-mcp /gost-mcp

# Default config path. Mount a real gost-mcp.yml over this file:
#   -v "$PWD/gost-mcp.yml:/etc/gost-mcp/gost-mcp.yml:ro"
COPY --from=build /src/gost-mcp.example.yml /etc/gost-mcp/gost-mcp.yml

USER nonroot:nonroot
ENTRYPOINT ["/gost-mcp"]
