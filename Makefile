BINARY  := gost-mcp
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test race check lint clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/gost-mcp

test:
	go test ./...

race:
	CGO_ENABLED=1 go test -race ./...

check: build
	./$(BINARY) --config internal/config/testdata/egress.yml --check

lint:
	@files="$$(gofmt -l .)"; if [ -n "$$files" ]; then echo "gofmt needed:"; echo "$$files"; exit 1; fi
	go vet ./...

clean:
	rm -f $(BINARY)
	rm -rf dist
