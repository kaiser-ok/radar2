VERSION := 2.0.0
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X main.version=$(VERSION) -X main.buildDate=$(BUILD_DATE)

.PHONY: build run test clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/radar ./cmd/radar/

collector:
	go build -ldflags "$(LDFLAGS)" -o bin/collector ./cmd/collector/

# Cross-compile collector for Windows (useful for remote sites)
collector-windows:
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/collector.exe ./cmd/collector/

run: build
	./bin/radar

test:
	go test ./...

clean:
	rm -rf bin/ radar.db captures/

deps:
	go mod tidy
