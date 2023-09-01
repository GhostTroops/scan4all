# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOMOD=$(GOCMD) mod
GOTEST=$(GOCMD) test
GOFLAGS := -v 
LDFLAGS := -s -w

ifneq ($(shell go env GOOS),darwin)
LDFLAGS := -extldflags "-static"
endif
    
all: build
build:
	$(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "cdncheck" cmd/cdncheck/main.go
test: 
	$(GOTEST) $(GOFLAGS) ./...
functional:
	cd cmd/functional-test; bash run.sh
integration:
	cd integration_tests; bash run.sh
tidy:
	$(GOMOD) tidy
