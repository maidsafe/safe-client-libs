# SAFE Authenticator - Change Log

## [0.5.0]
- Move `AccessContainerEntry` to safe_core
- Fix revocation bugs
- Do not require the scheme in URIs (e.g. "safe-auth:")
- Replace network event callback with a simpler, disconnect-only callback
- Use a single user data parameter for multiple callbacks
- Fix app re-authorisation using 2 PUTs
- Fix revocation crash with unencrypted entries

## [0.4.0]
- Add more tests for revocation
- Remove of the neccessity to pass `--feature testing` to run tests
- Generate C headers automatically with cheddar
- Improve account creation error reporting

## [0.3.2]
- Update routing to 0.33.2

## [0.3.1]
- Update routing to 0.33.1
- Fix concurrent revocation bugs

## [0.3.0]
- Update routing to 0.33.0
- Sharing of arbitrary MData
- Operation Recovery implementation
- Optimise account packet creation
- Fix builds without feature flags

## [0.2.1]
- Update routing to 0.32.2

## [0.2.0]
- Implement operation recovery for account creation, app authentication, and app revocation
- Change naming to be consistent (several functions prefixed with `authenticator_*` has been renamed to use the `auth_*` prefix instead)
- Add new FFI function to get the account info from the network (a number of available/used mutations)
- Simplify and refactor code (the IPC module has been split into several specialised modules)
- Update to use Rust Stable 1.19.0 / Nightly 2017-07-20, clippy 0.0.144, and rustfmt 0.9.0
- Update dependencies

## [0.1.0]
- Implement RFC 46 ([New Auth Flow](https://github.com/maidsafe/rfcs/blob/master/text/0046-new-auth-flow/0046-new-auth-flow.md))
- Allow users to create accounts and login into the SAFE Network
- Allow applications to be authenticated to use the network on behalf of the user, with an option for users to subsequently revoke the given permissions
- Introduce the concept of an access container, which allows to set fine-grained permissions for apps to access various MutableData instances on the network
- Provide a Foreign Function Interface to use the Authenticator API from other languages (JavaScript and Node.js, Java, etc.)
