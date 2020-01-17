.PHONY: build tests
.DEFAULT_GOAL: build

SHELL := /bin/bash
UUID := $(shell uuidgen | sed 's/-//g')
PWD := $(shell echo $$PWD)
USER_ID := $(shell id -u)
GROUP_ID := $(shell id -g)
UNAME_S := $(shell uname -s)

build:
	rm -rf artifacts
ifeq ($(UNAME_S),Linux)
	./scripts/build-with-container "prod" "x86_64"
else
	./scripts/build-real
endif
	mkdir artifacts
	find target/release -maxdepth 1 -type f -exec cp '{}' artifacts \;

build-mock:
	rm -rf artifacts
ifeq ($(UNAME_S),Linux)
	./scripts/build-with-container "dev" "x86_64-dev"
else
	./scripts/build-mock
endif
	mkdir artifacts
	find target/release -maxdepth 1 -type f -exec cp '{}' artifacts \;

package-build-artifacts:
ifndef SCL_BUILD_BRANCH
	@echo "A branch or PR reference must be provided."
	@echo "Please set SCL_BUILD_BRANCH to a valid branch or PR reference."
	@exit 1
endif
ifndef SCL_BUILD_NUMBER
	@echo "A build number must be supplied for build artifact packaging."
	@echo "Please set SCL_BUILD_NUMBER to a valid build number."
	@exit 1
endif
ifndef SCL_BUILD_TYPE
	@echo "A true or false value must be supplied indicating whether the build uses mocking."
	@echo "Please set SCL_BUILD_TYPE to true or false."
	@exit 1
endif
ifndef SCL_BUILD_TARGET
	@echo "A value must be supplied for SCL_BUILD_TARGET."
	@exit 1
endif
	$(eval ARCHIVE_NAME := ${SCL_BUILD_BRANCH}-${SCL_BUILD_NUMBER}-scl-${SCL_BUILD_TYPE}-${SCL_BUILD_TARGET}.tar.gz)
	tar -C artifacts -zcvf ${ARCHIVE_NAME} .
	rm artifacts/**
	mv ${ARCHIVE_NAME} artifacts

package-versioned-deploy-artifacts:
	@rm -rf deploy
	./scripts/package-runner "versioned"

package-commit_hash-deploy-artifacts:
	@rm -rf deploy
	./scripts/package-runner "commit_hash"

package-nightly-deploy-artifacts:
	@rm -rf deploy
	./scripts/package-runner "nightly"
	find . -name "*.zip" -exec rm "{}" \;

test-with-mock-vault-file:
ifeq ($(UNAME_S),Darwin)
	rm -rf artifacts
	./scripts/test-with-mock-vault-file
	make copy-artifacts
else
	@echo "Tests against the mock vault file are run only on OS X."
	@exit 1
endif

copy-artifacts:
	rm -rf artifacts
	mkdir artifacts
	find target/release -maxdepth 1 -type f -exec cp '{}' artifacts \;
