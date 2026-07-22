.PHONY: fmt vet build check docker-build

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './.git/*')

vet:
	go vet ./...

build:
	go build -o bin/auth-cli ./cmd/cli

check: fmt vet build

docker-build:
	docker build -t auth-cli:local .
