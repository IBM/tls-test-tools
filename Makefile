##@ General

all:	help

# NOTE: Help stolen from operator-sdk auto-generated makfile!
.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-\\.]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: test
test: ## Run the unit tests
	./scripts/run_tests.sh

.PHONY: test.develop
test.develop:	develop.build ## Run the unit tests in the develop shell
	./scripts/develop.sh ./scripts/run_tests.sh

.PHONY: fmt
fmt: ## Run code formatting
	./scripts/fmt.sh

.PHONY: wheel
wheel: ## Build release wheels
	./scripts/build_wheel.sh

##@ Develop

PYTHON_VERSION ?= 3.8

.PHONY: develop.build
develop.build: ## Build the development environment container
	docker build . --target=base -t tls-test-tools-develop --build-arg PYTHON_VERSION=${PYTHON_VERSION}

.PHONY: develop
develop:	develop.build ## Run the develop shell with the local codebase mounted
	./scripts/develop.sh
