.PHONY: build
.DEFAULT_GOAL: build

SHELL := /bin/bash
SAFE_APP_VERSION := $(shell cat safe_app/Cargo.toml | grep "^version" | head -n 1 | awk '{ print $$3 }' | sed 's/\"//g')
PWD := $(shell echo $$PWD)
USER_ID := $(shell id -u)
GROUP_ID := $(shell id -g)

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

build:
ifeq ($(OS),Windows_NT)
	./scripts/build-real
	mkdir artifacts
	find target/release -maxdepth 1 -type f -exec cp '{}' artifacts \;
else
	./scripts/build-with-container "real"
	mkdir artifacts
	find target/release -maxdepth 1 -type f -exec cp '{}' artifacts \;
endif

build-mock:
ifeq ($(OS),Windows_NT)
	./scripts/build-mock
	mkdir artifacts
	find target/release -maxdepth 1 -type f -exec cp '{}' artifacts \;
else
	./scripts/build-with-container "mock"
	mkdir artifacts
	find target/release -maxdepth 1 -type f -exec cp '{}' artifacts \;
endif

package-build-artifacts:
ifndef SCL_BUILD_NUMBER
	@echo "A build number must be supplied for build artifact packaging."
	@echo "Please set SCL_BUILD_NUMBER to a valid build number."
	@exit 1
endif
ifndef SCL_BUILD_MOCK
	@echo "A true or false value must be supplied indicating whether the build uses mocking."
	@echo "Please set SCL_BUILD_MOCK to true or false."
	@exit 1
endif
ifndef SCL_BUILD_OS
	@echo "A value must be supplied for SCL_BUILD_OS."
	@echo "Valid values are 'linux' or 'osx'."
	@exit 1
endif
ifeq ($(SCL_BUILD_MOCK),true)
	$(eval ARCHIVE_NAME := ${SCL_BUILD_NUMBER}-scl-mock-${SCL_BUILD_OS}-x86_64.tar.gz)
else
	$(eval ARCHIVE_NAME := ${SCL_BUILD_NUMBER}-scl-${SCL_BUILD_OS}-x86_64.tar.gz)
endif
	tar -C artifacts -zcvf ${ARCHIVE_NAME} .
	rm artifacts/**
	mv ${ARCHIVE_NAME} artifacts

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

debug:
	docker run --rm -v "${PWD}":/usr/src/crust maidsafe/safe-client-libs-build:${SAFE_APP_VERSION} /bin/bash
