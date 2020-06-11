# SAFE Authenticator - Change Log

## [0.16.2]
- Update to latest version of `safe_core`.

## [0.16.1]
- Update safe-nd to 0.9.0
- Refactor to use updated request/response types

## [0.16.0]
- Use Async/await rust.

## [0.15.0]
- Update quic-p2p to 0.5.0
- Move the FFI module into a separate crate
- Attempt to bootstrap multiple times before returning an error

## [0.14.0]
- Do not store `AppPermissions` in the client's config root 
- Refactor unnecessary disconnect during account creation
- Remove unused imports and linting
- Remove macro_use style
- Rename `FfiAppPermissions` to `AppPermissions`
- Make `RegisteredApp` struct include `AppPermissions`
- Add support for GET_NEXT_VERSION in more places
- Fix iOS static libs deployment issue
- Use cargo lipo to generate universal iOS fat libs
- Make returned error codes to be positive numbers
- Remove pedantic warnings
- Fix development build links in release description
- Add missing iOS builds to GHA deploy + fix tagging for releases

## [0.13.0]
- Update to safe-nd 0.7.2
- Remove macro_use and update ffi_utils to 0.15.0
- Make `RegisteredApp` struct include `AppPermissions` in FFI API
- Use GHA for Android libs build
- Define FFI-specific Result types

## [0.12.0]
- Remove Rust Sodium dependency

## [0.11.0]
- Update to quic-p2p 0.3.0
- Add `set_config_dir_path` API to set a custom path for configuration files.
- Deprecate the `maidsafe_utilities` and `config_file_handler` dependencies.
- Migrate to GitHub actions for CI / CD for all platforms except Mac OS builds.
- Fix inconsistency with real vault.

## [0.10.0]
- Use safe_core 0.33.0.
- Use the new network data types internally.
- Refactor the revocation process: we don't do the re-encryption for unpublished MutableData.
- Use the `stable` branch of the Rust compiler and Rust edition 2018.
- Expose all Rust modules and APIs which correspond to the FFI functions.

## [0.9.1]
- Make general documentation fixes and improvements.
- Fix some compiler errors.

## [0.9.0]
- `dir_update_file` and `dir_delete_file` now return the new version of the file entry
- Fix bindgen builds not including the FfiResult struct
- Remove redundant callback parameter documentation for FFI functions
- Fix classes lookup on Android by caching the class loader
- Use a more robust way of obtaining JniEnv references and handle errors gracefully
- Remove `is_mock_build` function, replace with `auth_is_mock` and `app_is_mock`
- Add len parameter to metadata in `auth_decode_ipc_msg`
- Add missing _pictures standard directory

## [0.8.0]
- Implement `AuthClient` with authenticator-specific features, decoupling it from the base `safe_core::Client`

## [0.7.0]
- Use rust 1.26.1 stable / 2018-02-29 nightly
- rustfmt-nightly 0.8.2 and clippy-0.0.206
- Updated license from dual Maidsafe/GPLv3 to GPLv3
- Implement bindings generation
- Add Java/JNI, C, and C# bindings
- Move apps to end of queue on revocation failure

## [0.6.0]
- Use rust 1.22.1 stable / 2018-01-10 nightly
- rustfmt 0.9.0 and clippy-0.0.179
- In `encode_auth_resp` and related functions, if authentication is not granted, return a result of `FFI_RESULT_OK` instead of `ERR_AUTH_DENIED`.

## [0.5.0]
- Move `AccessContainerEntry` to safe_core
- Fix revocation bugs
- Do not require the scheme in URIs (e.g. "safe-auth:")
- Replace network event callback with a simpler, disconnect-only callback
- Use a single user data parameter for multiple callbacks
- Fix app re-authorisation using 2 PUTs
- Fix revocation crash with unencrypted entries
- Add serialisation compatibility tests
- Imporove app revocation tests

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
