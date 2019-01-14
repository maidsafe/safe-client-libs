# SAFE Core

| [![](http://meritbadge.herokuapp.com/safe_core)](https://crates.io/crates/safe_core) | [![Documentation](https://docs.rs/safe_core/badge.svg)](https://docs.rs/safe_core) |
|:----------:|:----------:|

## Build Instructions

`safe_core` can interface conditionally against either the routing crate or a mock used for local testing.

To use it with the Mock:

```
cargo build --features "use-mock-routing"
cargo test --features "use-mock-routing"
```

To interface it with actual routing (default):

```
cargo build
cargo test
```

## License

This SAFE Network library is licensed under the General Public License (GPL), version 3 ([LICENSE](LICENSE) http://www.gnu.org/licenses/gpl-3.0.en.html).

### Linking exception

safe_core is licensed under GPLv3 with linking exception. This means you can link to and use the library from any program, proprietary or open source; paid or gratis. However, if you modify safe_core, you must distribute the source to your modified version under the terms of the GPLv3.

See the LICENSE file for more details.
