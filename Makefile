PWD := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
OUT_DIR ?= $(PWD)out

.PHONY: help
help:
	@echo Supported targets:
	@cat $(MAKEFILE_LIST) | grep -e "^[\.a-zA-Z0-9_-]*: *.*## *" | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-35s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help

.PHONY: client
client: ## run client
	go run cmd/client/main.go

.PHONY: server
server: ## run server
	go run cmd/server/main.go

.PHONY: test
test: clean ## run tests
	go test ./... -v -cover -coverprofile=$(OUT_DIR)/cover.txt -bench=. && \
	go tool cover -html=$(OUT_DIR)/cover.txt -o $(OUT_DIR)/cover.html

.PHONY: clean
clean: ## clean output folder
	mkdir -p $(OUT_DIR)
	rm -rf $(OUT_DIR)/*