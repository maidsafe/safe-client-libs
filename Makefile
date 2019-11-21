.PHONY: build tests
.DEFAULT_GOAL: build

SHELL := /bin/bash
UUID := $(shell uuidgen | sed 's/-//g')
SAFE_APP_VERSION := $(shell grep "^version" < safe_app/Cargo.toml | head -n 1 | awk '{ print $$3 }' | sed 's/\"//g')
SAFE_AUTH_VERSION := $(shell grep "^version" < safe_authenticator/Cargo.toml | head -n 1 | awk '{ print $$3 }' | sed 's/\"//g')
PWD := $(shell echo $$PWD)
USER_ID := $(shell id -u)
GROUP_ID := $(shell id -g)
UNAME_S := $(shell uname -s)
S3_BUCKET := safe-jenkins-build-artifacts
GITHUB_REPO_OWNER := maidsafe
GITHUB_REPO_NAME := safe_client_libs

build-container:
ifndef SAFE_CLIENT_LIBS_CONTAINER_TYPE
	@echo "A container type must be specified."
	@echo "Please set SAFE_CLIENT_LIBS_CONTAINER_TYPE to 'dev' or 'prod'."
	@exit 1
endif
ifndef SAFE_CLIENT_LIBS_CONTAINER_TARGET
	@echo "A build target must be specified."
	@echo "Please set SAFE_CLIENT_LIBS_CONTAINER_TARGET to a valid Rust 'target triple', e.g. 'x86_64-unknown-linux-gnu'."
	@exit 1
endif
	./scripts/build-container.sh \
		"${SAFE_CLIENT_LIBS_CONTAINER_TARGET}" \
		"${SAFE_CLIENT_LIBS_CONTAINER_TYPE}"

push-container:
ifndef SAFE_CLIENT_LIBS_CONTAINER_TYPE
	@echo "A container type must be specified."
	@echo "Please set SAFE_CLIENT_LIBS_CONTAINER_TYPE to 'dev' or 'prod'."
	@exit 1
endif
ifndef SAFE_CLIENT_LIBS_CONTAINER_TARGET
	@echo "A build target must be specified."
	@echo "Please set SAFE_CLIENT_LIBS_CONTAINER_TARGET to a valid Rust 'target triple', e.g. 'x86_64-unknown-linux-gnu'."
	@exit 1
endif
	docker push \
		maidsafe/safe-client-libs-build:${SAFE_CLIENT_LIBS_CONTAINER_TARGET}-${SAFE_CLIENT_LIBS_CONTAINER_TYPE}

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

build-ios-aarch64:
	( \
		cd safe_app; \
		cargo build --release --target=aarch64-apple-ios; \
	)
	( \
		cd safe_authenticator; \
		cargo build --release --target=aarch64-apple-ios; \
	)
	rm -rf artifacts
	mkdir artifacts
	find target/aarch64-apple-ios/release -maxdepth 1 -type f -exec cp '{}' artifacts \;

build-ios-mock-aarch64:
	( \
		cd safe_app; \
		cargo build --release --target=aarch64-apple-ios --features="mock-network"; \
	)
	( \
		cd safe_authenticator; \
		cargo build --release --target=aarch64-apple-ios --features="mock-network"; \
	)
	rm -rf artifacts
	mkdir artifacts
	find target/aarch64-apple-ios/release -maxdepth 1 -type f -exec cp '{}' artifacts \;

build-ios-x86_64:
	( \
		cd safe_app; \
		cargo build --release --target=x86_64-apple-ios; \
	)
	( \
		cd safe_authenticator; \
		cargo build --release --target=x86_64-apple-ios; \
	)
	rm -rf artifacts
	mkdir artifacts
	find target/x86_64-apple-ios/release -maxdepth 1 -type f -exec cp '{}' artifacts \;

build-ios-mock-x86_64:
	( \
		cd safe_app; \
		cargo build --release --target=x86_64-apple-ios --features="mock-network"; \
	)
	( \
		cd safe_authenticator; \
		cargo build --release --target=x86_64-apple-ios --features="mock-network"; \
	)
	rm -rf artifacts
	mkdir artifacts
	find target/x86_64-apple-ios/release -maxdepth 1 -type f -exec cp '{}' artifacts \;

.ONESHELL:
build-android:
ifndef SAFE_CLIENT_LIBS_CONTAINER_TYPE
	@echo "A container type must be specified."
	@echo "Please set SAFE_CLIENT_LIBS_CONTAINER_TYPE to 'dev' or 'prod'."
	@exit 1
endif
ifndef SAFE_CLIENT_LIBS_CONTAINER_TARGET
	@echo "A build target must be specified."
	@echo "Please set SAFE_CLIENT_LIBS_CONTAINER_TARGET to a valid Rust 'target triple', e.g. 'x86_64-unknown-linux-gnu'."
	@exit 1
endif
	rm -rf artifacts
	container_name="build-$$(uuidgen | sed 's/-//g')"
	build_command="cargo build --release --manifest-path=safe_app/Cargo.toml --target=${SAFE_CLIENT_LIBS_CONTAINER_TARGET}"
	[[ ${SAFE_CLIENT_LIBS_CONTAINER_TYPE} == 'dev' ]] && build_command="$$build_command --features=mock-network"
	docker run --name "$$container_name" \
	  -v $$(pwd):/usr/src/safe_client_libs:Z \
	  -u $$(id -u):$$(id -g) \
	  maidsafe/safe-client-libs-build:${SAFE_CLIENT_LIBS_CONTAINER_TARGET}-${SAFE_CLIENT_LIBS_CONTAINER_TYPE} \
	  bash -c "$$build_command"
	docker cp "$$container_name":/target .
	docker rm "$$container_name"
	mkdir artifacts
	find "target/${SAFE_CLIENT_LIBS_CONTAINER_TARGET}/release" \
		-maxdepth 1 -type f -exec cp '{}' artifacts \;

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

strip-artifacts:
ifeq ($(OS),Windows_NT)
	find artifacts -name "*.dll" -exec strip -x '{}' \;
else ifeq ($(UNAME_S),Darwin)
	find artifacts -name "*.dylib" -exec strip -x '{}' \;
else
	find artifacts -name "*.so" -exec strip '{}' \;
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
	# The cargo-script installation can be removed when Jenkins is decommissioned.
	# It's just being done because it's too late to update the build slave
	# at this point.
	cargo install cargo-script --force
	./scripts/package-runner "versioned"

package-commit_hash-deploy-artifacts:
	@rm -rf deploy
	# We still need the container for use with Jenkins.
	# BRANCH_NAME is a variable Jenkins provides.
	# This can be removed when Jenkins is decommissioned.
ifdef BRANCH_NAME
	docker run --rm -v "${PWD}":/usr/src/safe_client_libs:Z \
		-u ${USER_ID}:${GROUP_ID} \
		maidsafe/safe-client-libs-build:x86_64 \
		scripts/package-runner-container "commit_hash"
else
	./scripts/package-runner "commit_hash"
endif

package-nightly-deploy-artifacts:
	@rm -rf deploy
	./scripts/package-runner "nightly"
	find . -name "*.zip" -exec rm "{}" \;

retrieve-cache:
ifndef SCL_BUILD_BRANCH
	@echo "A branch reference must be provided."
	@echo "Please set SCL_BUILD_BRANCH to a valid branch reference."
	@exit 1
endif
ifeq ($(OS),Windows_NT)
	aws s3 cp \
		--no-sign-request \
		--region eu-west-2 \
		s3://${S3_BUCKET}/scl-${SCL_BUILD_BRANCH}-windows-cache.tar.gz .
endif
	mkdir target
	tar -C target -xvf scl-${SCL_BUILD_BRANCH}-windows-cache.tar.gz
	rm scl-${SCL_BUILD_BRANCH}-windows-cache.tar.gz

universal-ios-lib: retrieve-ios-build-artifacts
ifneq ($(UNAME_S),Darwin)
	@echo "This target can only be run on macOS"
	@exit 1
endif
ifndef SCL_BUILD_BRANCH
	@echo "A branch or PR reference must be provided."
	@echo "Please set SCL_BUILD_BRANCH to a valid branch or PR reference."
	@exit 1
endif
ifndef SCL_BUILD_NUMBER
	@echo "A valid build number must be supplied for the artifacts to be retrieved."
	@echo "Please set SCL_BUILD_NUMBER to a valid build number."
	@exit 1
endif
	mkdir -p artifacts/prod/universal
	mkdir -p artifacts/dev/universal
	mkdir -p artifacts/prod/universal
	mkdir -p artifacts/dev/universal
	lipo -create -output artifacts/prod/universal/libsafe_app.a \
		artifacts/prod/x86_64-apple-ios/release/libsafe_app.a \
		artifacts/prod/aarch64-apple-ios/release/libsafe_app.a
	lipo -create -output artifacts/prod/universal/libsafe_authenticator.a \
		artifacts/prod/x86_64-apple-ios/release/libsafe_authenticator.a \
		artifacts/prod/aarch64-apple-ios/release/libsafe_authenticator.a
	lipo -create -output artifacts/dev/universal/libsafe_app.a \
		artifacts/dev/x86_64-apple-ios/release/libsafe_app.a \
		artifacts/dev/aarch64-apple-ios/release/libsafe_app.a
	lipo -create -output artifacts/dev/universal/libsafe_authenticator.a \
		artifacts/dev/x86_64-apple-ios/release/libsafe_authenticator.a \
		artifacts/dev/aarch64-apple-ios/release/libsafe_authenticator.a

package-universal-ios-lib:
ifndef SCL_BUILD_BRANCH
	@echo "A branch or PR reference must be provided."
	@echo "Please set SCL_BUILD_BRANCH to a valid branch or PR reference."
	@exit 1
endif
ifndef SCL_BUILD_NUMBER
	@echo "A valid build number must be supplied for the artifacts to be retrieved."
	@echo "Please set SCL_BUILD_NUMBER to a valid build number."
	@exit 1
endif
	( \
		cd artifacts; \
		tar -C prod/universal -zcvf \
			${SCL_BUILD_BRANCH}-${SCL_BUILD_NUMBER}-scl-prod-apple-ios.tar.gz .; \
	)
	( \
		cd artifacts; \
		tar -C dev/universal -zcvf \
			${SCL_BUILD_BRANCH}-${SCL_BUILD_NUMBER}-scl-dev-apple-ios.tar.gz .; \
	)
	rm -rf artifacts/prod
	rm -rf artifacts/dev

retrieve-all-build-artifacts:
ifndef SCL_BUILD_BRANCH
	@echo "A branch or PR reference must be provided."
	@echo "Please set SCL_BUILD_BRANCH to a valid branch or PR reference."
	@exit 1
endif
ifndef SCL_BUILD_NUMBER
	@echo "A valid build number must be supplied for the artifacts to be retrieved."
	@echo "Please set SCL_BUILD_NUMBER to a valid build number."
	@exit 1
endif
	# This used to include all the target triples, but we're only using
	# this target in Jenkins now and it only builds macOS.
	./scripts/retrieve-build-artifacts \
		"x86_64-apple-darwin" "x86_64-apple-ios" "aarch64-apple-ios" \
		"apple-ios"

retrieve-ios-build-artifacts:
ifndef SCL_BUILD_BRANCH
	@echo "A branch or PR reference must be provided."
	@echo "Please set SCL_BUILD_BRANCH to a valid branch or PR reference."
	@exit 1
endif
ifndef SCL_BUILD_NUMBER
	@echo "A valid build number must be supplied for the artifacts to be retrieved."
	@echo "Please set SCL_BUILD_NUMBER to a valid build number."
	@exit 1
endif
	./scripts/retrieve-build-artifacts "x86_64-apple-ios" "aarch64-apple-ios"

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

deploy-github-release:
ifndef GITHUB_TOKEN
	@echo "Please set GITHUB_TOKEN to the API token for a user who can create releases."
	@exit 1
endif
	github-release release \
		--user ${GITHUB_REPO_OWNER} \
		--repo ${GITHUB_REPO_NAME} \
		--tag ${SAFE_APP_VERSION} \
		--name "safe_client_libs" \
		--description "$$(./scripts/get-release-description ${SAFE_APP_VERSION})"
		--user ${GITHUB_REPO_OWNER} \
		--repo ${GITHUB_REPO_NAME} \
		--tag ${SAFE_APP_VERSION} \
		--name "safe_app-${SAFE_APP_VERSION}-x86_64-apple-darwin.tar.gz" \
		--file deploy/prod/safe_app-${SAFE_APP_VERSION}-x86_64-apple-darwin.tar.gz
	github-release upload \
		--user ${GITHUB_REPO_OWNER} \
		--repo ${GITHUB_REPO_NAME} \
		--tag ${SAFE_APP_VERSION} \
		--name "safe_app-${SAFE_APP_VERSION}-x86_64-pc-windows-gnu.tar.gz" \
		--file deploy/prod/safe_app-${SAFE_APP_VERSION}-x86_64-pc-windows-gnu.tar.gz
	github-release upload \
		--user ${GITHUB_REPO_OWNER} \
		--repo ${GITHUB_REPO_NAME} \
		--tag ${SAFE_APP_VERSION} \
		--name "safe_app-${SAFE_APP_VERSION}-apple-ios.tar.gz" \
		--file deploy/prod/safe_app-${SAFE_APP_VERSION}-apple-ios.tar.gz
	github-release upload \
		--user ${GITHUB_REPO_OWNER} \
		--repo ${GITHUB_REPO_NAME} \
		--tag ${SAFE_APP_VERSION} \
		--name "safe_app-${SAFE_APP_VERSION}-armv7-linux-androideabi.tar.gz" \
		--file deploy/prod/safe_app-${SAFE_APP_VERSION}-armv7-linux-androideabi.tar.gz
	github-release upload \
		--user ${GITHUB_REPO_OWNER} \
		--repo ${GITHUB_REPO_NAME} \
		--tag ${SAFE_APP_VERSION} \
		--name "safe_app-${SAFE_APP_VERSION}-x86_64-linux-android.tar.gz" \
		--file deploy/prod/safe_app-${SAFE_APP_VERSION}-x86_64-linux-android.tar.gz

	github-release upload \
		--user ${GITHUB_REPO_OWNER} \
		--repo ${GITHUB_REPO_NAME} \
		--tag ${SAFE_AUTH_VERSION} \
		--name "safe_authenticator-${SAFE_AUTH_VERSION}-x86_64-unknown-linux-gnu.tar.gz" \
		--file deploy/prod/safe_authenticator-${SAFE_AUTH_VERSION}-x86_64-unknown-linux-gnu.tar.gz
	github-release upload \
		--user ${GITHUB_REPO_OWNER} \
		--repo ${GITHUB_REPO_NAME} \
		--tag ${SAFE_AUTH_VERSION} \
		--name "safe_authenticator-${SAFE_AUTH_VERSION}-x86_64-apple-darwin.tar.gz" \
		--file deploy/prod/safe_authenticator-${SAFE_AUTH_VERSION}-x86_64-apple-darwin.tar.gz
	github-release upload \
		--user ${GITHUB_REPO_OWNER} \
		--repo ${GITHUB_REPO_NAME} \
		--tag ${SAFE_AUTH_VERSION} \
		--name "safe_authenticator-${SAFE_AUTH_VERSION}-x86_64-pc-windows-gnu.tar.gz" \
		--file deploy/prod/safe_authenticator-${SAFE_AUTH_VERSION}-x86_64-pc-windows-gnu.tar.gz
	github-release upload \
		--user ${GITHUB_REPO_OWNER} \
		--repo ${GITHUB_REPO_NAME} \
		--tag ${SAFE_AUTH_VERSION} \
		--name "safe_authenticator-${SAFE_AUTH_VERSION}-apple-ios.tar.gz" \
		--file deploy/prod/safe_authenticator-${SAFE_AUTH_VERSION}-apple-ios.tar.gz
	github-release upload \
		--user ${GITHUB_REPO_OWNER} \
		--repo ${GITHUB_REPO_NAME} \
		--tag ${SAFE_AUTH_VERSION} \
		--name "safe_authenticator-${SAFE_AUTH_VERSION}-armv7-linux-androideabi.tar.gz" \
		--file deploy/prod/safe_authenticator-${SAFE_AUTH_VERSION}-armv7-linux-androideabi.tar.gz
	github-release upload \
		--user ${GITHUB_REPO_OWNER} \
		--repo ${GITHUB_REPO_NAME} \
		--tag ${SAFE_AUTH_VERSION} \
		--name "safe_authenticator-${SAFE_AUTH_VERSION}-x86_64-linux-android.tar.gz" \
		--file deploy/prod/safe_authenticator-${SAFE_AUTH_VERSION}-x86_64-linux-android.tar.gz

publish-safe_core:
	./scripts/publish "safe_core"

publish-safe_authenticator:
	./scripts/publish "safe_authenticator"

publish-safe_app:
	./scripts/publish "safe_app"
