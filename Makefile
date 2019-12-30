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

clippy:
ifeq ($(UNAME_S),Linux)
	docker run --rm -v "${PWD}":/usr/src/safe_client_libs:Z \
		-u ${USER_ID}:${GROUP_ID} \
		-e CARGO_TARGET_DIR=/target \
		maidsafe/safe-client-libs-build:x86_64-mock \
		scripts/clippy-all
else
	./scripts/clippy-all
endif

rustfmt:
ifeq ($(UNAME_S),Linux)
	docker run --rm -v "${PWD}":/usr/src/safe_client_libs:Z \
		-u ${USER_ID}:${GROUP_ID} \
		-e CARGO_TARGET_DIR=/target \
		maidsafe/safe-client-libs-build:x86_64-mock \
		scripts/rustfmt
else
	./scripts/rustfmt
endif

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

test-artifacts-binary:
ifndef SCL_BCT_PATH
	@echo "A value must be supplied for the previous binary compatibility test suite."
	@echo "Please set SCL_BCT_PATH to the location of the previous binary compatibility test suite."
	@echo "Re-run this target as 'make SCL_BCT_PATH=/home/user/.cache/binary-compat-tests test-artifacts-binary'."
	@echo "Note that SCL_BCT_PATH must be an absolute path, with any references like '~' expanded to their full value."
	@exit 1
endif
	docker run --rm -v "${PWD}":/usr/src/safe_client_libs:Z \
		-v "${SCL_BCT_PATH}":/bct/tests:Z \
		-u ${USER_ID}:${GROUP_ID} \
		-e CARGO_TARGET_DIR=/target \
		-e COMPAT_TESTS=/bct/tests \
		-e SCL_TEST_SUITE=binary \
		maidsafe/safe-client-libs-build:x86_64 \
		scripts/test-runner-container

tests:
	rm -rf artifacts
ifeq ($(UNAME_S),Linux)
	rm -rf target/
	docker run --name "safe_app_tests-${UUID}" \
		-v "${PWD}":/usr/src/safe_client_libs \
		-u ${USER_ID}:${GROUP_ID} \
		-e CARGO_TARGET_DIR=/target \
		maidsafe/safe-client-libs-build:x86_64-mock \
		scripts/build-and-test-mock
	docker cp "safe_app_tests-${UUID}":/target .
	docker rm -f "safe_app_tests-${UUID}"
else
	./scripts/build-mock
	./scripts/test-mock
endif
	make copy-artifacts

test-with-mock-vault-file:
ifeq ($(UNAME_S),Darwin)
	rm -rf artifacts
	./scripts/test-with-mock-vault-file
	make copy-artifacts
else
	@echo "Tests against the mock vault file are run only on OS X."
	@exit 1
endif

tests-integration:
	rm -rf target/
	docker run --rm -v "${PWD}":/usr/src/safe_client_libs \
		-u ${USER_ID}:${GROUP_ID} \
		-e CARGO_TARGET_DIR=/target \
		maidsafe/safe-client-libs-build:x86_64-mock \
		scripts/test-integration

debug:
	docker run --rm -v "${PWD}":/usr/src/crust maidsafe/safe-client-libs-build:x86_64 /bin/bash

copy-artifacts:
	rm -rf artifacts
	mkdir artifacts
	find target/release -maxdepth 1 -type f -exec cp '{}' artifacts \;
