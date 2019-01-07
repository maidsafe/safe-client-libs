.PHONY: safe_app
.DEFAULT_GOAL: safe_app

SHELL:=/bin/bash
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

safe_app: clean
	rm -rf target/
	docker run --name safe_app_build \
		-v "${PWD}":/usr/src/safe_client_libs \
		-u ${USER_ID}:${GROUP_ID} \
		-e CARGO_TARGET_DIR=/target \
		maidsafe/safe-client-libs-build:${SAFE_APP_VERSION} \
		scripts/build-real
	docker cp safe_app_build:/target .
	docker rm -f safe_app_build

safe_app_mock: clean
	rm -rf target/
	docker run --name safe_app_build \
		-v "${PWD}":/usr/src/safe_client_libs \
		-u ${USER_ID}:${GROUP_ID} \
		-e CARGO_TARGET_DIR=/target \
		maidsafe/safe-client-libs-build:${SAFE_APP_VERSION} \
		scripts/build-mock
	docker cp safe_app_build:/target .
	docker rm -f safe_app_build

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
