# SAFE App

**Maintainer:** Spandan Sharma (spandan.sharma@maidsafe.net)

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

Licensed under either of

* the MaidSafe.net Commercial License, version 1.0 or later ([LICENSE](LICENSE))
* the General Public License (GPL), version 3 ([COPYING](COPYING) or http://www.gnu.org/licenses/gpl-3.0.en.html)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the MaidSafe Contributor Agreement ([CONTRIBUTOR](CONTRIBUTOR)), shall be
dual licensed as above, and you agree to be bound by the terms of the MaidSafe Contributor Agreement.
