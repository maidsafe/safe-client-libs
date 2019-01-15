# SAFE Authenticator

| [![](http://meritbadge.herokuapp.com/safe_authenticator)](https://crates.io/crates/safe_authenticator) | [![Documentation](https://docs.rs/safe_authenticator/badge.svg)](https://docs.rs/safe_authenticator) |
|:----------:|:----------:|

This is the crate for interfacing with `Authenticator` frontend. It contains the business logic for the `Authenticator` UI and code for building the URI for communicating with [safe_app](../safe_app).

## Build Instructions

`safe_authenticator` can interface conditionally against either the routing crate or a mock used for local testing.

Please see [the project README](https://github.com/maidsafe/safe_client_libs#building-from-source) for full build instructions.

## License

This SAFE Network library is licensed under the General Public License (GPL), version 3 ([LICENSE](LICENSE) http://www.gnu.org/licenses/gpl-3.0.en.html).

### Linking exception

safe_authenticator is licensed under GPLv3 with linking exception. This means you can link to and use the library from any program, proprietary or open source; paid or gratis. However, if you modify safe_authenticator, you must distribute the source to your modified version under the terms of the GPLv3.

See the LICENSE file for more details.
