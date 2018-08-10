# FFI utils - Change Log

## [0.7.0]
- Add a public helper function `catch_unwind_result` for synchronous APIs (in addition to `catch_unwind_cb` for async)

## [0.6.0]
- Use rust 1.26.1 stable / 2018-02-29 nightly
- rustfmt-nightly 0.8.2 and clippy-0.0.206
- Updated license from dual Maidsafe/GPLv3 to GPLv3
- Add binding generator utilities

## [0.5.0]
- Use rust 1.22.1 stable / 2018-01-10 nightly
- rustfmt 0.9.0 and clippy-0.0.179
- `catch_unwind_error_code` function removed as it was no longer used

## [0.4.0]
- Use pointers to `FfiResult` instead of passing by value
- Change type of `FFI_RESULT_OK` to a static reference
- Don't add padding to URIs
- Update base64 version
- Add support for using a single user data parameter for multiple callbacks
- Add tests for the `catch_unwind` family of functions

## [0.3.0]
- Improve documentation and fix bugs
- Fix compiler errors on rustc-nightly

## [0.2.0]
- Change the log output for FFI errors - remove the decoration and reduce the log level

## [0.1.0]
- Provide FFI utility functions for safe_client_libs
