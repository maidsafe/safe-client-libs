SHELL:=/bin/bash
SAFE_APP_VERSION := $(shell cat safe_app/Cargo.toml | grep "^version" | head -n 1 | awk '{ print $$3 }' | sed 's/\"//g')
PWD := $(shell echo $$PWD)

build-container:
	rm -rf target/
	docker rmi -f maidsafe/safe-client-libs-build:${SAFE_APP_VERSION}
	docker build -f scripts/Dockerfile.build -t maidsafe/safe-client-libs-build:${SAFE_APP_VERSION} .
