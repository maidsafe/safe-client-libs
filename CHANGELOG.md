# Safe Core - Change Log

## [0.14.2]
- Remove feature use-mock-crust

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
- [MAID-1295](https://maidsafe.atlassian.net/browse/MAID-1295) Remove all unwraps() AND Check for Ok(try!( and see if really required (ie., for error conversion etc)
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
