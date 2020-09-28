# Changelog

## [0.42.1]
- Update ffi-utils to 0.17.0

## [0.42.0]
- Added of SequenceData APIs
- Removed of AppendOnlyData APIs
- Standardize cargo dependency versioning

## [0.41.3]
- Fix CI deploy

## [0.41.2]
- Update the number of responses required to process a request.

## [0.41.1]
- Update quic-p2p to 0.6.2
- Update sn_data_types to 0.9.0
- Refactor to use updated request/response types

## [0.41.0]
- Use Async/await rust.

## [0.40.0]
- Update quic-p2p to 0.5.0
- Attempt to bootstrap multiple times before returning an error

## [0.39.0]
- Add position and index to get_value
- Refactor the connection manager to use new quic-p2p API
- Always use random port instead of default
- Implement multi-vault connection manager
- Implement the new handshake protocol and manage connection state transitions
- Remove unused imports and linting
- Remove macro_use style
- Add support for GET_NEXT_VERSION in more places
- Expose a new `gen_data_map` API which generates a file's data map without putting the chunks on the network
- Make returned error codes to be positive numbers
- Remove pedantic warnings

## [0.38.1]
- Fix broken master workflow

## [0.38.0]
- Update to sn_data_types 0.7.2
- Update to lazy_static 1.4.0
- Update ffi_utils to 0.15.0
- Use GHA for Android libs build
- Expose `gen_data_map` API which generates a file's data map without putting the chunks on the network

## [0.37.3]
- Make another fix to automatic publishing

## [0.37.2]
- Refactor and reenable client mock tests
- Fix automatic publishing

## [0.37.1]
- Fix automatic deploys and releases

## [0.37.0]
- Remove Rust Sodium dependency

## [0.36.0]
- Update to quic-p2p 0.3.0
- Add `set_config_dir_path` API to set a custom path for configuration files.
- Deprecate the `maidsafe_utilities` and `config_file_handler` dependencies.
- Migrate to GitHub actions for CI / CD for all platforms except Mac OS builds.
- Fix inconsistency with real vault.

## [0.35.0]
- Remove unused `routing` module and fix errors
- Rework MDataKey and MDataValue to use FFI conventions
- Make miscellaneous doc fixes
- Clean up FFI documentation

## [0.34.0]
- Technical release to solve some issues in our automated publishing process

## [0.33.0]
- Remove Routing dependency from safe_core.
- Use quic-p2p for communication with Vaults.
- Use new data types from sn_data_types (AppendOnlyData and unpublished ImmutableData).
- Add Safecoin-related tests and features.
- Use the `stable` branch of the Rust compiler and Rust edition 2018.

## [0.32.1]
- Move module-level documentation to wiki, replace with link.
- Make general documentation fixes and improvements.
- Fix some compiler errors.

## [0.32.0]
- Switch to base32 encodings for case-insensitive URIs for IPC
- Send a mock bit with ipc messages so that mock and non-mock components trying to communicate results in an error
- Fix the mock-routing bug which was resulting in corrupted MockVault files
- Remove `is_mock_build` function, replace with `auth_is_mock` and `app_is_mock`

## [0.31.0]
- Refactor `Client` struct to a trait for a better separation of concerns
- Implement `CoreClient` as a bare-bones network client for tests
- Move Authenticator-related `Client` functions to `safe_authenticator`

## [0.30.0]
- Use rust 1.26.1 stable / 2018-02-29 nightly
- rustfmt-nightly 0.8.2 and clippy-0.0.206
- Updated license from dual Maidsafe/GPLv3 to GPLv3
- Add `MDataEntry` struct
- Implement bindings generation

## [0.29.0]
- Use rust 1.22.1 stable / 2018-01-10 nightly
- rustfmt 0.9.0 and clippy-0.0.179
- Fix naming conventions in callback parameters and elsewhere

## [0.28.0]
- Move `AccessContainerEntry` to safe_core
- Add FFI wrapper for `MDataInfo`
- Add access container entry to `AuthGranted`
- Add `MDataKey` and `MDataValue` structs
- Add function for checking mock-routing status of build
- Add config file functionality with options for unlimited mock mutations, in-memory mock storage, and custom mock vault path.
- Add environment variables to override config options for unlimited mock mutations and custom mock vault path.
- Add support for providing arbitrary user data along with `IpcReq::Unregistered` auth request
- Improve documentation for callback parameters
- Improve NFS tests
- Remove unnecessary constants equivalent to environment variables names

## [0.27.0]
- Improve documentation and fix bugs
- Nonce in the MDataInfo struct is no longer optional. This is a breaking external change
- Remove of the neccessity to pass `--feature testing` to run tests
- Replace all secret keys with drop-in equivalents that implement secure cloning. They don't actually clone the underlying data but instead implicitly share it.

## [0.26.2]
- Update routing to 0.33.2

## [0.26.1]
- Update routing to 0.33.1
- Fix mock vault write mode

## [0.26.0]
- Update routing to 0.33.0
- Decryption in MDataInfo tries both the new and old encryption keys before giving up
- Env var to control in-mem or on-disk storage for mock vault
- Change and improve account packet structure
- Fix mock vault deserialisation

## [0.25.1]
- Update routing to 0.32.2

## [0.25.0]
- Add new functions for operations recovery in the `safe_core::recovery` module (e.g. if a `mutate_mdata_entries` operation is failed with the `InvalidSuccessor` error, it will be retried with an increased version)
- Add new testing features to mock-routing (allowing to override certain requests with predefined responses)
- Improve the NFS test coverage
- Update to use Rust Stable 1.19.0 / Nightly 2017-07-20, clippy 0.0.144, and rustfmt 0.9.0
- Update `routing` to 0.32.0 to include more descriptive Map errors
- Update other dependencies

## [0.24.0]
- Use asynchronous I/O and futures for interfacing with Routing
- Deprecate and remove StructuredData and AppendableData types
- Introduce a new data type instead: Map
- Implement URI-based IPC interaction between apps required for supporting mobile devices
- Integrate with routing 0.31.0
- Move all FFI functions to their own separate crates
- Refactor and simplify the NFS module

## [0.23.0]
- Integrate with routing 0.28.5
- Invitation based account creation support in client (API change)
- Invitation-generator and populator example binary
- New error types for ivitation errors
- Serde instead of rustc-serialize in production
- Use chrono instead of time crate (default serde serialisable)
- Fix bugs concerning to unclaimable SD and re-claiming SD via PUT; test cases updated

## [0.22.4]
- Integrate with routing 0.28.4 (0.28.3 is skipped and is yanked from crates).
- Use rust 1.16.0, nightly-2017-03-16 and clippy 0.0.120
- Add a few trace messages for better diagnostics.
- Cleanup README.md

## [0.22.3]
- Integrate with routing 0.28.2

## [0.22.2]
- Integrate with routing 0.28.0

## [0.22.1]
- API to get MAID-Public signing key.

## [0.22.0]
- New error type - MutationError::DataTooLarge.
- New Delete handling and update of code and test cases.
- New APIs - Put to re-claim deleted data (specify version), make data unclaimable.
- Changes and fixes in mock-routing to conform to routing and vaults for error deduction and error types.

## [0.21.2]
- Serialisation and deserialisation for Sign Keys.
- API for getting Filtered keys from AppendableData.
- Fix accidental name mangling of C function.

## [0.21.1]
- Reverting the commit to remove dir-tag from dir-key: commit e829423 reverts commit 4fbc044.
- Trim credentials in examples to not include a `\n`.

## [0.21.0]
- Removal of base64 indirection as we no longer have JSON interface to `safe_core`.
- Many more test cases to thoroughly check low-level-api
- Add new api's wanted by launcher - ownership assertion, version exposure, more serialisations etc.
- Make tag-types for versioned and unversioned StructuredData MaidSafe constants and remove them from `DirectoryKey`.

## [0.20.0]
- API changed from JSON to direct FFI calls for interfacing with other languages.
- Provide low-level-api for finer grained control for manipulation of MaidSafe data types.
- Provide Private & Public Appendable Data operations and manipulations.
- Code APPEND API.
- Update mock-routing to comply with above changes to mimic basic routing and vault functionality for purposes of independent testing.
- Introduce Object Caching - a method in which `safe_core` keeps cache of object in LRU cache and gives only a POD (u64) handle via FFI.
- Increase test cases performace when using mock routing by not writing data to file for test-cases.
- Dependency update - routing updated to 0.26.0.

## [0.19.0]
- Dependency update - routing updated to 0.23.4.
- Log path exposed to FFI so that frontend is intimated where it is expected to create its log files.
- Dependency on rust_sodium instead of sodiumoxide and removal of libsodium instruction from CI builds.

## [0.18.1]
- Dependency update - routing reduced to 0.23.3 and safe_network_common increased to 0.7.0.

## [0.18.0]
- Requests made to safe_core will now timeout after 2 min if there is no response from routing.
- Self_encrypt write used by safe_core via sequential encryptor will now try to put data onto the Network immediately if possible leading to better progress indication across FFI.
- Logging added to safe_core.
- Accessing DNS will not do a bunch of checks which it used to previously because it lead to erroneous corner cases in which one user could not access websites created by other before they created their own DNS first etc.

## [0.17.0]
- Instead of requiring all 3 of PIN, Keyword and Password, have user type only one secure pass-phrase and derive the required credentials internally.

## [0.16.2]
- Expose get-account-info functionality in FFI for launcher to consume.
- Fix sodiumoxide to v0.0.10 as the new released v0.0.12 does not support rustc-serializable types anymore and breaks builds.
- Update dependencies

## [0.16.1]
- Update Routing to 0.23.2
- Add logging to network events.
- Delete existing log file due to issue in v3 of log4rs which instead of truncating/appending overwrites the existing log file garbling it.
- Rustfmt and clippy errors addressed.
- Error recovery test case.
- Extract sub-errors out of Self Encryption errors and convert them to C error codes for FFI.

## [0.16.0]
- Update dependencies
- Refactor FFI as `Box::into_raw()` is stable
- Refactor FFI to deal with pointer to concrete types instead of ptr to void for more type safety
- Fix undefined behaviour in transmute to unrelated type in FFI
- Fix non-termination of background thread which got exposed after fixing the above
- Reorder Imports
- Resolve many Clippy errors
- Expose functionality to collect stats on GETs/PUTs/POSTs/DELETEs
- Error recovery for failure in intermediary steps of a composite operation (like DNS register and delete).

## [0.15.1]
- Upgrade routing to 0.22.0
- Upgrade safe_network_common to 0.3.0

## [0.15.0]
- Upgrade to new routing and self_encryption.

## [0.14.6]
- Merge safe_ffi into safe_core.

## [0.14.5]
- Updating routing to 0.19.1

## [0.14.4]
- Dependency update

## [0.14.3]
- Dependency update

## [0.14.2]
- Pointing and conforming to Routing 0.15.0
- Removal of feature use-mock-crust
- internal code improvement - removing now-a-one-liner function

## [0.14.1]
- Updated dependencies.

## [0.14.0]
- Migrate to Routing 0.13.0.

## [0.13.1]
- Updated dependencies.

## [0.13.0]
- Added minimal support for mock crust.
- Updated dependencies.

## [0.12.1]
- Updated dependencies.

## [0.12.0]
- Integrated with safe_network_common.
- Response handling in case of errors made complete with reason for errors coded in.
- Mock routing updated to give correct reason in cases for errors. All corresponding test cases update to thoroughly test most of scenarios.

## [0.11.0]
- Reintegrated messaging API.
- Fixed a bug in file metadata serialisation which caused the frontend app to crash on Windows.

## [0.10.0]
- Code made more resilient to precision of time resolution on host machines by including dedicated version counter in file metadata. This is also part of public API.
- self_authentication example gives better error message on trying to hijack pre-existing user network name.
- Updated dependencies.

## [0.9.0]
- Updated response handling in line with network behaviour changes.
- Updated dependencies.

## [0.8.0]
- Nfs and Dns modules and examples merged into safe_core.

## [0.7.0]
- Disconnect event detection and translation to ffi compatible value

## [0.6.1]
- self_encryption updated to 0.2.6

## [0.6.0]
- Migrated to Routing 0.7.0
- Switched LOGIN_PACKET_TYPE_TAG to 0

## [0.5.0]
- Refactored to comply with new routing API
- Compiles and passes tests with Mock with stable Rust

## [0.4.0]
- Refactored to comply with new routing API

## [0.3.1]
- Remove wildcard dependencies

## [0.3.0]
- [MAID-1423](https://maidsafe.atlassian.net/browse/MAID-1423) Rename safe_client to safe_core

## [0.2.1]
- Routing crate updated to version 0.4.*

## [0.2.0]
- [MAID-1295](https://maidsafe.atlassian.net/browse/MAID-1295) Remove all unwraps() AND Check for Ok(r#try!( and see if really required (ie., for error conversion etc)
- [MAID-1296](https://maidsafe.atlassian.net/browse/MAID-1296) Remove unwanted errors and Unexpected should take an &str instead of String
- [MAID-1297](https://maidsafe.atlassian.net/browse/MAID-1297) Evaluate test_utils in client
- [MAID-1298](https://maidsafe.atlassian.net/browse/MAID-1298) Put debug statements
- [MAID-1299](https://maidsafe.atlassian.net/browse/MAID-1299) check for all muts (eg., response_getter etc) and validate if really required
- [MAID-1300](https://maidsafe.atlassian.net/browse/MAID-1300) Error conditions in Mock Routing
- [MAID-1301](https://maidsafe.atlassian.net/browse/MAID-1301) Test cases for Error conditions in Mock
- [MAID-1303](https://maidsafe.atlassian.net/browse/MAID-1303) Address the TODO’s and make temporary fixes as permanent (eg., listening to bootstrapped signal)
- [MAID-1304](https://maidsafe.atlassian.net/browse/MAID-1304) Test cases for TODO's and temp fixes as permanent

## [0.1.5]
- Wait for routing to fire a bootstrap completion event
- Added support for environment logger

## [0.1.4]
- [MAID-1219](https://maidsafe.atlassian.net/browse/MAID-1219) Implement Private and Public types
- [MAID-1249](https://maidsafe.atlassian.net/browse/MAID-1249) Implement Unified Structured Datatype
    - [MAID-1252](https://maidsafe.atlassian.net/browse/MAID-1252) Mock Unified StructuredData and ImmutableData
    - [MAID-1253](https://maidsafe.atlassian.net/browse/MAID-1253) Update Mock Routing to support Mock Unified SturcturedData and ImmutableData
    - [MAID-1222](https://maidsafe.atlassian.net/browse/MAID-1222) Compute size of Structured Data
    - [MAID-1223](https://maidsafe.atlassian.net/browse/MAID-1223) Implement a handler for Storing UnVersioned Structured Data
    - [MAID-1224](https://maidsafe.atlassian.net/browse/MAID-1224) Implement a handler for Retrieving Content of UnVersioned Structured Data
    - [MAID-1225](https://maidsafe.atlassian.net/browse/MAID-1225) Write Test Cases for UnVersioned Structured Data handler
    - [MAID-1230](https://maidsafe.atlassian.net/browse/MAID-1230) Implement a handler for Storing Versioned Structured Data
    - [MAID-1231](https://maidsafe.atlassian.net/browse/MAID-1231) Create MaidSafe Specific configuration directory
    - [MAID-1232](https://maidsafe.atlassian.net/browse/MAID-1232) Write Test Cases for Versioned Structured Data handler
    - [MAID-1226](https://maidsafe.atlassian.net/browse/MAID-1226) Implement Session Packet as UnVersioned Structure DataType
    - [MAID-1227](https://maidsafe.atlassian.net/browse/MAID-1227) Update the test cases in Core API
    - [MAID-1228](https://maidsafe.atlassian.net/browse/MAID-1228) Update the test cases in mock routing framework
    - [MAID-1234](https://maidsafe.atlassian.net/browse/MAID-1234) Update Hybrid Encrypt and Decrypt

## [0.1.3]
- [MAID-1283](https://maidsafe.atlassian.net/browse/MAID-1283) Rename repositories from "maidsafe_" to "safe_"

## [0.1.2]
- [MAID-1209](https://maidsafe.atlassian.net/browse/MAID-1209) Remove NFS API

## [0.1.1]
- Updated dependencies' versions
- Fixed lint warnings caused by latest Rust nightly

## [0.1.0] RUST-2 sprint
- Account Creation
    - Register
    - Login
- Implement Storage API
    - Implement types
        - Implement MetaData, File and DirectoryListing types
    - Implement Helpers
        - Directory Helper
            - Save DirectoryListing
            - Get Directory
            - Get Directory Versions
        - File Helper
            - Create File, update file and Metatdata
            - Get Versions
            - Read File
        - Unit test cases for Directory and File Helpers
    - Implement REST DataTypes
        - Container & Blob types
            - Implement Blob and Container types
        - REST API methods in Container
            - Create Container & Get Container
            - List Containers, Update / Get Container Metadata
            - Delete Container
            - Create Blob
            - List Blobs
            - Get Blob
            - Update Blob Content
            - Get Blob Content
            - List Blob Version
            - Delete Blob
            - Copy Blob
            - Update / Get Blob Metadata
        - Unit test cases for API
    - Implement Version Cache (cache key,(blob/container) info to reduce network traffic)
    - Root Directory handling
- Create Example:
    - Self authentication Example
    - Example to demonstrate Storage API
