.PHONY: build
.DEFAULT_GOAL: build

SHELL := /bin/bash
SAFE_APP_VERSION := $(shell cat safe_app/Cargo.toml | grep "^version" | head -n 1 | awk '{ print $$3 }' | sed 's/\"//g')
PWD := $(shell echo $$PWD)
USER_ID := $(shell id -u)
GROUP_ID := $(shell id -g)
COMMIT_MESSAGE := $(shell git log -1 --pretty=%B | head -n 1)
UNAME_S := $(shell uname -s)

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
ifeq ($(UNAME_S),Darwin)
	mkdir artifacts
	find target/release -maxdepth 1 -type f -exec cp '{}' artifacts \;
endif
ifeq ($(SCL_BUILD_MOCK),true)
	$(eval ARCHIVE_NAME := ${SCL_BUILD_NUMBER}-scl-mock-${SCL_BUILD_OS}-x86_64.tar.gz)
else
	$(eval ARCHIVE_NAME := ${SCL_BUILD_NUMBER}-scl-${SCL_BUILD_OS}-x86_64.tar.gz)
endif
	tar -C artifacts -zcvf ${ARCHIVE_NAME} .; \
	rm artifacts/**
	mv ${ARCHIVE_NAME} artifacts

retrieve-build-artifacts:
ifndef SCL_BUILD_NUMBER
	@echo "A valid build number must be supplied for the artifacts to be retrieved."
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
	rm -rf artifacts && mkdir artifacts
	aws s3 cp \
		--no-sign-request \
		--region eu-west-2 \
		s3://safe-client-libs-jenkins/travis-artifacts/${ARCHIVE_NAME} .
	tar -C artifacts -xvf ${ARCHIVE_NAME}
	rm ${ARCHIVE_NAME}

retrieve-all-build-artifacts:
ifndef SCL_BUILD_NUMBER
	@echo "A valid build number must be supplied for the artifacts to be retrieved."
	@echo "Please set SCL_BUILD_NUMBER to a valid build number."
	@exit 1
endif
	rm -rf artifacts
	mkdir -p artifacts/linux/real/release
	mkdir -p artifacts/linux/mock/release
	mkdir -p artifacts/osx/real/release
	mkdir -p artifacts/osx/mock/release
	aws s3 cp --no-sign-request --region eu-west-2 s3://safe-client-libs-jenkins/travis-artifacts/${SCL_BUILD_NUMBER}-scl-linux-x86_64.tar.gz .
	aws s3 cp --no-sign-request --region eu-west-2 s3://safe-client-libs-jenkins/travis-artifacts/${SCL_BUILD_NUMBER}-scl-mock-linux-x86_64.tar.gz .
	aws s3 cp --no-sign-request --region eu-west-2 s3://safe-client-libs-jenkins/travis-artifacts/${SCL_BUILD_NUMBER}-scl-osx-x86_64.tar.gz .
	aws s3 cp --no-sign-request --region eu-west-2 s3://safe-client-libs-jenkins/travis-artifacts/${SCL_BUILD_NUMBER}-scl-mock-osx-x86_64.tar.gz .
	tar -C artifacts/linux/real/release -xvf ${SCL_BUILD_NUMBER}-scl-linux-x86_64.tar.gz
	tar -C artifacts/linux/mock/release -xvf ${SCL_BUILD_NUMBER}-scl-mock-linux-x86_64.tar.gz
	tar -C artifacts/osx/real/release -xvf ${SCL_BUILD_NUMBER}-scl-osx-x86_64.tar.gz
	tar -C artifacts/osx/mock/release -xvf ${SCL_BUILD_NUMBER}-scl-mock-osx-x86_64.tar.gz
	rm ${SCL_BUILD_NUMBER}-scl-linux-x86_64.tar.gz
	rm ${SCL_BUILD_NUMBER}-scl-mock-linux-x86_64.tar.gz
	rm ${SCL_BUILD_NUMBER}-scl-osx-x86_64.tar.gz
	rm ${SCL_BUILD_NUMBER}-scl-mock-osx-x86_64.tar.gz

package-deploy-artifacts:
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
