.PHONY: test lint lint-all lint-examples tools

GOLANGCI_LINT_VERSION ?= v1.45.2

test:
	go test *.go

lint:
	golangci-lint run -v

tools:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/$(GOLANGCI_LINT_VERSION)/install.sh \
		| sh -s -- -b $(GOPATH)/bin $(GOLANGCI_LINT_VERSION)
