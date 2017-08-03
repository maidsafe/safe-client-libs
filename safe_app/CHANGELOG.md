# SAFE App

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
