# SAFE App

| [![](http://meritbadge.herokuapp.com/safe_app)](https://crates.io/crates/safe_app) | [![Documentation](https://docs.rs/safe_app/badge.svg)](https://docs.rs/safe_app) |
|:----------:|:----------:|

This is the crate for interfacing with application frontends. It contains code for applications to manipulate SAFE data-types on behalf of the owner and code for building the URI for communicating with [safe_authenticator](../safe_authenticator).

## Build Instructions

`safe_app` can interface conditionally against either the routing crate or a mock (routing and vault) used for local testing.

To use it with the Mock:

```
cargo build --features "use-mock-routing"
cargo test --features "use-mock-routing testing"
```

To interface it with actual routing (default):

```
cargo build
cargo test
```

## License

This SAFE Network library is dual-licensed under the Modified BSD ([LICENSE-BSD](LICENSE-BSD) https://opensource.org/licenses/BSD-3-Clause) or the MIT license ([LICENSE-MIT](LICENSE-MIT) http://opensource.org/licenses/MIT) at your option.

## Contribution

Copyrights in the SAFE Network are retained by their contributors. No copyright assignment is required to contribute to this project.
