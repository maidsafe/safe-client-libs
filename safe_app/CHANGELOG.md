# SAFE App

## [0.3.3]
- Update routing to 0.33.2

## [0.3.2]
- Return a null ptr instead of default Rust's (0x01) when vector has had no heap allocations

## [0.3.1]
- Update routing to 0.33.1

## [0.3.0]
- Update routing to 0.33.0
- Fix UB in tests
- Improve access container functions
- Refactor out common types in `safe_core::ffi`
- Make permission handling uniform
- Support sharing of arbitrary MData
- Tests for logging in with low balance

## [0.2.1]
- Update routing to 0.32.2

## [0.2.0]
- Add new FFI function to get the account info from the network (a number of available/used mutations)
- Improve the NFS test coverage
- Update to use Rust Stable 1.19.0 / Nightly 2017-07-20, clippy 0.0.144, and rustfmt 0.9.0
- Update dependencies

## [0.1.0]
- Implement RFC 46 ([New Auth Flow](https://github.com/maidsafe/rfcs/blob/master/text/0046-new-auth-flow/0046-new-auth-flow.md))
- Allow apps to connect to the SAFE Network with read-only access or authorise on behalf of the user
- Provide a Foreign Function Interface to interact with the SAFE Network API from other languages (JavaScript and Node.js, Java, etc.)
