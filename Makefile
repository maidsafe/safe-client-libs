.PHONY: build
.DEFAULT_GOAL: build

SHELL := /bin/bash
SAFE_APP_VERSION := $(shell cat safe_app/Cargo.toml | grep "^version" | head -n 1 | awk '{ print $$3 }' | sed 's/\"//g')
PWD := $(shell echo $$PWD)
USER_ID := $(shell id -u)
GROUP_ID := $(shell id -g)
COMMIT_MESSAGE := $(shell git log -1 --pretty=%B | head -n 1)

build-container:
	rm -rf target/
	docker rmi -f maidsafe/safe-client-libs-build:${SAFE_APP_VERSION}
	docker build -f scripts/Dockerfile.build -t maidsafe/safe-client-libs-build:${SAFE_APP_VERSION} .

push-container:
	docker push maidsafe/safe-client-libs-build:${SAFE_APP_VERSION}

clean:
	@if docker ps -a | grep safe_app_build &> /dev/null; then \
		docker rm -f safe_app_build; \
	fi
	@rm -rf artifacts
	@rm -rf target

build: clean
	docker run --name safe_app_build \
		-v "${PWD}":/usr/src/safe_client_libs \
		-u ${USER_ID}:${GROUP_ID} \
		-e CARGO_TARGET_DIR=/target \
		maidsafe/safe-client-libs-build:${SAFE_APP_VERSION} \
		scripts/build-real
	docker cp safe_app_build:/target .
	docker rm -f safe_app_build
	mkdir artifacts
	find target/release -maxdepth 1 -type f -exec cp '{}' artifacts \;

build-mock: clean
	docker run --name safe_app_build \
		-v "${PWD}":/usr/src/safe_client_libs \
		-u ${USER_ID}:${GROUP_ID} \
		-e CARGO_TARGET_DIR=/target \
		maidsafe/safe-client-libs-build:${SAFE_APP_VERSION} \
		scripts/build-mock
	docker cp safe_app_build:/target .
	docker rm -f safe_app_build
	mkdir artifacts
	find target/release -maxdepth 1 -type f -exec cp '{}' artifacts \;

tests: clean
	rm -rf target/
	docker run --name safe_app_build \
		-v "${PWD}":/usr/src/safe_client_libs \
		-u ${USER_ID}:${GROUP_ID} \
		-e CARGO_TARGET_DIR=/target \
		maidsafe/safe-client-libs-build:${SAFE_APP_VERSION} \
		scripts/test-mock
	docker cp safe_app_build:/target .
	docker rm -f safe_app_build

test-artifacts-mock:
	docker run --rm -v "${PWD}":/usr/src/safe_client_libs \
		-u ${USER_ID}:${GROUP_ID} \
		-e CARGO_TARGET_DIR=/target \
		-e SCL_TEST_SUITE=mock \
		maidsafe/safe-client-libs-build:${SAFE_APP_VERSION} \
		scripts/test-runner-container

test-artifacts-integration:
	docker run --rm -v "${PWD}":/usr/src/safe_client_libs \
		-u ${USER_ID}:${GROUP_ID} \
		-e CARGO_TARGET_DIR=/target \
		-e SCL_TEST_SUITE=integration \
		maidsafe/safe-client-libs-build:${SAFE_APP_VERSION} \
		scripts/test-runner-container

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
		maidsafe/safe-client-libs-build:${SAFE_APP_VERSION} \
		scripts/test-runner-container

package-artifacts:
	@rm -rf deploy
	docker run --rm -v "${PWD}":/usr/src/safe_client_libs:Z \
		-u ${USER_ID}:${GROUP_ID} \
		maidsafe/safe-client-libs-build:${SAFE_APP_VERSION} \
		scripts/package-runner-container "${COMMIT_MESSAGE}"

debug:
	docker run -it --rm -v "${PWD}":/usr/src/safe_client_libs \
		-u ${USER_ID}:${GROUP_ID} \
		-e CARGO_TARGET_DIR=/target \
		maidsafe/safe-client-libs-build:${SAFE_APP_VERSION} \
		/bin/bash
