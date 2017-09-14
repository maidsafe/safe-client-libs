// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

//! Secret encryption and signing keys with more secure cloning semantics. These
//! keys implement implicit sharing of the underlying sensitive data to avoid
//! multiple copies of it stored in the memory, preventing certain class of attacks.

/// Symmetric encryption utilities.
pub mod shared_secretbox {
    use rust_sodium::crypto::secretbox;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::fmt::{self, Debug};
    use std::ops::Deref;
    use std::sync::Arc;

    /// Shared symmetric encryption key.
    #[derive(Clone, Eq, PartialEq)]
    pub struct Key(Arc<secretbox::Key>);

    impl Key {
        /// Create new safe-to-share key from the given regular key.
        pub fn new(inner: secretbox::Key) -> Self {
            // NOTE: make sure we move the inner array, not the whole key, because
            // moving the key would leave the `inner` variable in the "moved-from"
            // state which means it's destructor wouldn't be called and the old
            // memory location wouldn't be zeroed - leaving the sensitive data
            // dangling in the memory.
            Key(Arc::new(secretbox::Key(inner.0)))
        }

        /// Create new key from the given raw key data.
        pub fn from_raw(data: &[u8; secretbox::KEYBYTES]) -> Self {
            // FIXME: this function subverts the purpose of this module - it
            // copies the sensitive data. Possible fix might be to take the input by
            // mutable reference and zero it afterwards.
            Key(Arc::new(secretbox::Key(*data)))
        }

        /// Create new key from the data in the given slice.
        pub fn from_slice(data: &[u8]) -> Option<Self> {
            secretbox::Key::from_slice(data).map(Self::new)
        }
    }

    /// Generate new random shared symmetric encryption key.
    pub fn gen_key() -> Key {
        Key::new(secretbox::gen_key())
    }

    impl Deref for Key {
        type Target = secretbox::Key;

        fn deref(&self) -> &Self::Target {
            &*self.0
        }
    }

    impl<'de> Deserialize<'de> for Key {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let inner = secretbox::Key::deserialize(deserializer)?;
            Ok(Key::new(inner))
        }
    }

    impl Serialize for Key {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.0.serialize(serializer)
        }
    }

    impl Debug for Key {
        fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
            self.0.fmt(f)
        }
    }
}

/// Asymmetric encryption utilities.
pub mod shared_box {
    use rust_sodium::crypto::box_;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::fmt::{self, Debug};
    use std::ops::Deref;
    use std::sync::Arc;

    /// Shared secret encryption key.
    #[derive(Clone, Eq, PartialEq)]
    pub struct SecretKey(Arc<box_::SecretKey>);

    impl SecretKey {
        /// Create new safe-to-share key from the given regular key.
        pub fn new(inner: box_::SecretKey) -> Self {
            SecretKey(Arc::new(box_::SecretKey(inner.0)))
        }

        /// Create new key from the given raw key data.
        pub fn from_raw(data: &[u8; box_::SECRETKEYBYTES]) -> Self {
            // FIXME: this function subverts the purpose of this module - it
            // copies the sensitive data. Possible fix might be to take the input by
            // mutable reference and zero it afterwards.
            SecretKey(Arc::new(box_::SecretKey(*data)))
        }
    }

    /// Generate new random public/secret keypair.
    pub fn gen_keypair() -> (box_::PublicKey, SecretKey) {
        let (pk, sk) = box_::gen_keypair();
        (pk, SecretKey::new(sk))
    }

    impl Deref for SecretKey {
        type Target = box_::SecretKey;

        fn deref(&self) -> &Self::Target {
            &*self.0
        }
    }

    impl<'de> Deserialize<'de> for SecretKey {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let inner = box_::SecretKey::deserialize(deserializer)?;
            Ok(SecretKey::new(inner))
        }
    }

    impl Serialize for SecretKey {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.0.serialize(serializer)
        }
    }

    impl Debug for SecretKey {
        fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
            self.0.fmt(f)
        }
    }
}

/// Signing utilities.
pub mod shared_sign {
    use rust_sodium::crypto::sign;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::fmt::{self, Debug};
    use std::ops::Deref;
    use std::sync::Arc;

    /// Shared secret signing key.
    #[derive(Clone, Eq, PartialEq)]
    pub struct SecretKey(Arc<sign::SecretKey>);

    impl SecretKey {
        /// Create new safe-to-share key from the given regular key.
        pub fn new(inner: sign::SecretKey) -> Self {
            SecretKey(Arc::new(sign::SecretKey(inner.0)))
        }

        /// Create new key from the given raw key data.
        pub fn from_raw(data: &[u8; sign::SECRETKEYBYTES]) -> Self {
            // FIXME: this function subverts the purpose of this module - it
            // copies the sensitive data. Possible fix might be to take the input by
            // mutable reference and zero it afterwards.
            SecretKey(Arc::new(sign::SecretKey(*data)))
        }
    }

    /// Generate new random public/secret keypair.
    pub fn gen_keypair() -> (sign::PublicKey, SecretKey) {
        let (pk, sk) = sign::gen_keypair();
        (pk, SecretKey::new(sk))
    }

    /// Generate new random public/secret keypair using the given seed.
    pub fn keypair_from_seed(seed: &sign::Seed) -> (sign::PublicKey, SecretKey) {
        let (pk, sk) = sign::keypair_from_seed(seed);
        (pk, SecretKey::new(sk))
    }

    impl Deref for SecretKey {
        type Target = sign::SecretKey;

        fn deref(&self) -> &Self::Target {
            &*self.0
        }
    }

    impl<'de> Deserialize<'de> for SecretKey {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let inner = sign::SecretKey::deserialize(deserializer)?;
            Ok(SecretKey::new(inner))
        }
    }

    impl Serialize for SecretKey {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.0.serialize(serializer)
        }
    }

    impl Debug for SecretKey {
        fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
            self.0.fmt(f)
        }
    }
}
