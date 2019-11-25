// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use rust_sodium::crypto::box_::{
    NONCEBYTES as ASYM_NONCE_LEN, PUBLICKEYBYTES as ASYM_PUBLIC_KEY_LEN,
    SECRETKEYBYTES as ASYM_SECRET_KEY_LEN,
};
use rust_sodium::crypto::secretbox::{KEYBYTES as SYM_KEY_LEN, NONCEBYTES as SYM_NONCE_LEN};
use safe_nd::XOR_NAME_LEN;
use threshold_crypto::{PK_SIZE as BLS_PUBLIC_KEY_LEN, SIG_SIZE};

/// Array containing public key bytes.
pub type AsymPublicKey = [u8; ASYM_PUBLIC_KEY_LEN];
/// Array containing private key bytes.
pub type AsymSecretKey = [u8; ASYM_SECRET_KEY_LEN];
/// Array containing nonce bytes.
pub type AsymNonce = [u8; ASYM_NONCE_LEN];

/// Array containing private key bytes.
pub type SymSecretKey = [u8; SYM_KEY_LEN];
/// Array containing nonce bytes.
pub type SymNonce = [u8; SYM_NONCE_LEN];

/// Array containing BLS public key.
pub type BlsPublicKey = [u8; BLS_PUBLIC_KEY_LEN];
/// Array containing a BLS Signature.
pub type Signature = [u8; SIG_SIZE];

/// Array containing `XorName` bytes.
pub type XorNameArray = [u8; XOR_NAME_LEN];
