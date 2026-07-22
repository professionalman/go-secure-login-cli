.PHONY: generate fmt test vet build check docker-build

generate:
	go generate ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './.git/*')

test:
	go test ./...

vet:
	go vet ./...

build:
	go build -o bin/auth-cli ./cmd/cli

check: fmt test vet build

docker-build:
	docker build -t auth-cli:local .
