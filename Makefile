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

test-with-mock-node-file:
ifeq ($(UNAME_S),Darwin)
	rm -rf artifacts
	./scripts/test-with-mock-node-file
	make copy-artifacts
else
	@echo "Tests against the mock node file are run only on OS X."
	@exit 1
endif

copy-artifacts:
	rm -rf artifacts
	mkdir artifacts
	find target/release -maxdepth 1 -type f -exec cp '{}' artifacts \;
