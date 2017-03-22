# safe_core

**Maintainer:** Spandan Sharma (spandan.sharma@maidsafe.net)

|Crate|Linux/OS X|Windows|Coverage|Issues|
|:---:|:--------:|:-----:|:------:|:----:|
|[![](http://meritbadge.herokuapp.com/safe_core)](https://crates.io/crates/safe_core)|[![Build Status](https://travis-ci.org/maidsafe/safe_core.svg?branch=master)](https://travis-ci.org/maidsafe/safe_core)|[![Build status](https://ci.appveyor.com/api/projects/status/c61jthx04us5j57j/branch/master?svg=true)](https://ci.appveyor.com/project/MaidSafe-QA/safe-core/branch/master)|[![Coverage Status](https://coveralls.io/repos/maidsafe/safe_core/badge.svg?branch=master)](https://coveralls.io/r/maidsafe/safe_core?branch=master)|[![Stories in Ready](https://badge.waffle.io/maidsafe/safe_core.png?label=ready&title=Ready)](https://waffle.io/maidsafe/safe_core)|

| [API Docs - master branch](http://docs.maidsafe.net/safe_client_libs/master/safe_core/index.html) | [MaidSafe website](https://maidsafe.net) | [SAFE Dev Forum](https://forum.safedev.org) | [SAFE Network Forum](https://safenetforum.org) |
|:------:|:-------:|:-------:|:-------:|

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

Licensed under either of

* the MaidSafe.net Commercial License, version 1.0 or later ([LICENSE](LICENSE))
* the General Public License (GPL), version 3 ([COPYING](COPYING) or http://www.gnu.org/licenses/gpl-3.0.en.html)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the MaidSafe Contributor Agreement, version 1.1 ([CONTRIBUTOR]
(CONTRIBUTOR)), shall be dual licensed as above, and you agree to be bound by the terms of the
MaidSafe Contributor Agreement, version 1.1.
