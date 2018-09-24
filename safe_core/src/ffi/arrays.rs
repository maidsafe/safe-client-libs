// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use routing::XOR_NAME_LEN;
use safe_crypto::{
    NONCE_BYTES, PUBLIC_ENCRYPT_KEY_BYTES, PUBLIC_SIGN_KEY_BYTES, SECRET_ENCRYPT_KEY_BYTES,
    SECRET_SIGN_KEY_BYTES, SYMMETRIC_KEY_BYTES,
};

/// Array containing public key bytes.
pub type PublicEncryptKeyArray = [u8; PUBLIC_ENCRYPT_KEY_BYTES];
/// Array containing secret key bytes.
pub type SecretEncryptKeyArray = [u8; SECRET_ENCRYPT_KEY_BYTES];

/// Array containing symmetric secret key bytes.
pub type SymmetricKeyArray = [u8; SYMMETRIC_KEY_BYTES];

/// Array containing nonce bytes.
pub type NonceArray = [u8; NONCE_BYTES];

/// Array containing sign public key bytes.
pub type PublicSignKeyArray = [u8; PUBLIC_SIGN_KEY_BYTES];
/// Array containing sign secret key bytes.
pub type SecretSignKeyArray = [u8; SECRET_SIGN_KEY_BYTES];

/// Array containing `XorName` bytes.
pub type XorNameArray = [u8; XOR_NAME_LEN];
