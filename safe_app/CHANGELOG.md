# SAFE App

## [0.9.0]
- There's a known bug in this release related to Java/JNI on debug builds. It results in a "no Task is currently running" error message and panic when calling the `file_close` function
- `dir_update_file` and `dir_delete_file` now return the new version of the file entry
- Add a `GET_NEXT_VERSION` constant as an input to `dir_update_file` and `dir_delete_file`
- Fix bindgen builds not including the FfiResult struct
- Remove redundant callback parameter documentation for FFI functions, and make minor documentation fixes
- Fix classes lookup on Android by caching the class loader
- Use a more robust way of obtaining JniEnv references and handle errors gracefully
- Remove `is_mock_build` function, replace with `auth_is_mock` and `app_is_mock`

## [0.8.0]
- Implement `AppClient` with app-specific functions on top of the base abstract `Client`
- Provide SAFE App API to be used as the only required dependency for apps built in Rust
- Refactor examples to use the new API
- Remove unneccessary structures from the API (`MDataAction` was no longer used)

## [0.7.0]
- Use rust 1.26.1 stable / 2018-02-29 nightly
- rustfmt-nightly 0.8.2 and clippy-0.0.206
- Updated license from dual Maidsafe/GPLv3 to dual license (MIT/BSD)
- Implement bindings generation
- Add Java/JNI, C, and C# bindings
- Refactor `mdata_entries_for_each` to `mdata_list_entries`
- Fix a panic in `test_create_app_with_access`
- Add `test_simulate_network_disconnect`

## [0.6.0]
- Use rust 1.22.1 stable / 2018-01-10 nightly
- rustfmt 0.9.0 and clippy-0.0.179
- Improve test app creation APIs
- Move ffi test_utils functions to an ffi module

## [0.5.0]
- Remove `MDataPermissionSetHandle` and related functions
- Fix a bug with object cache handles starting at 0 and conflicting with "special" handles which are defined to be 0
- Rename `mdata_permissions_for_each` to `mdata_list_permission_sets`
- Remove `MDataKeysHandle` and related functions; replaced by `MDataKey` struct in safe_core
- Remove `MDataValuesHandle` and related and functions; replaced by `MDataValue` struct in safe_core
- Add `mdata_get_all_keys` and add `mdata_get_all_values`
- Remove `mdata_info_new_public`
- The object cache capacity limit was removed
- Add `app_reset_object_cache`
- Do not require the scheme in URIs (e.g. "safe-app:")
- Remove `change_mdata_owner`
- Replace network event callback with a simpler, disconnect-only callback
- Use a single user data parameter for multiple callbacks
- Use pointers in FFI in place of value structs
- Add crypto API for secret signing keys and add secret sign key handle
- Add crypto API for signing/verifying
- Add FFI function to get an app's container name

## [0.4.0]
- Improve documentation and fix bugs
- Add more tests for NFS (reading and writing files in chunks)
- Refactor FFI API: rename functions prefixed with `mdata_permissions_set` to `mdata_permission_set`
- Refactor FFI API: change order of callback parameters in some functions (e.g. `mdata_values_for_each`)
- Refactor and reorganise modules structure
- Fix dangling pointer issues in the crypto module
- Improve error descriptions
- Remove of the neccessity to pass `--feature testing` to run tests
- Generate C headers automatically with cheddar
- Increase the object cache capacity to 1000
- Fix compiler errors on rustc-nightly

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
