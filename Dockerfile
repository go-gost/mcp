# syntax=docker/dockerfile:1

# Build stage. go.mod requires Go 1.26.3, so 1.27 is the first stable image
# that can build the module.
FROM golang:1.27 AS build

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
