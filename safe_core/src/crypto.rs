// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Secret encryption and signing keys with more secure cloning semantics. These
//! keys implement implicit sharing of the underlying sensitive data to avoid
//! multiple copies of it stored in the memory, preventing certain class of attacks.

/// Symmetric encryption utilities.
pub mod shared_secretbox {
    use crate::utils::{self, SymEncKey};
    use serde::{Deserialize, Serialize};
    use std::convert::TryInto;
    use std::fmt::{self, Debug};
    use std::ops::Deref;
    use std::sync::Arc;

    /// Shared symmetric encryption key.
    #[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
    pub struct Key(Arc<SymEncKey>);

    impl Key {
        /// Create new safe-to-share key from the given regular key.
        pub fn new(inner: &SymEncKey) -> Self {
            // NOTE: make sure we move the inner array, not the whole key, because
            // moving the key would leave the `inner` variable in the "moved-from"
            // state which means it's destructor wouldn't be called and the old
            // memory location wouldn't be zeroed - leaving the sensitive data
            // dangling in the memory.
            Key(Arc::new(*inner))
        }

        /// Create new key from the given raw key data.
        pub fn from_raw(data: &SymEncKey) -> Self {
            // FIXME: this function subverts the purpose of this module - it
            // copies the sensitive data. Possible fix might be to take the input by
            // mutable reference and zero it afterwards.
            Key(Arc::new(*data))
        }

        /// Create new key from the data in the given slice.
        pub fn from_slice(data: &[u8]) -> Option<Self> {
            let key: SymEncKey = unwrap!(data.try_into());
            Some(Self(Arc::new(key)))
        }
    }

    /// Generate new random shared symmetric encryption key.
    pub fn gen_key() -> Key {
        Key::new(&utils::generate_sym_enc_key())
    }

    impl Deref for Key {
        type Target = SymEncKey;

        fn deref(&self) -> &Self::Target {
            &*self.0
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
    use bincode::deserialize;
    use serde::{Deserialize, Serialize};
    use std::fmt::{self, Debug};
    use std::ops::Deref;
    use threshold_crypto::{serde_impl::SerdeSecret, SecretKey as BlsSecretKey};

    /// Shared secret encryption key.
    #[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
    pub struct SecretKey(SerdeSecret<BlsSecretKey>);

    impl SecretKey {
        /// Create new safe-to-share key from the given regular key.
        pub fn new(inner: BlsSecretKey) -> Self {
            SecretKey(SerdeSecret(inner))
        }

        /// Create new key from the given raw key data.
        pub fn from_raw(data: &[u8]) -> Result<Self, crate::CoreError> {
            // FIXME: this function subverts the purpose of this module - it
            // copies the sensitive data. Possible fix might be to take the input by
            // mutable reference and zero it afterwards.
            let sk = deserialize(data)?;
            Ok(SecretKey(sk))
        }
    }

    /// Generate new random public/secret keypair.
    pub fn gen_keypair() -> (threshold_crypto::PublicKey, SecretKey) {
        let sk = threshold_crypto::SecretKey::random();
        let pk = sk.public_key();
        (pk, SecretKey::new(sk))
    }

    impl Deref for SecretKey {
        type Target = threshold_crypto::SecretKey;

        fn deref(&self) -> &Self::Target {
            &(*self.0)
        }
    }

    impl Debug for SecretKey {
        fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
            self.0.fmt(f)
        }
    }
}
