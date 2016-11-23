#!/bin/bash

# Show expanded commands while running
set -x

# Stop the script if any command fails
set -o errtrace
trap 'exit' ERR

cd $TRAVIS_BUILD_DIR

if [[ $TRAVIS_RUST_VERSION = stable ]]; then
  cargo test --release --no-run --verbose
  cargo test --release --features use-mock-routing --verbose
fi

# Hide expanded commands while running
set +x
