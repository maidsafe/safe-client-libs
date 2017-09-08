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

use routing::XOR_NAME_LEN;
use rust_sodium::crypto::{box_, secretbox, sign};

/// Array containing public key bytes.
pub type AsymPublicKey = [u8; box_::PUBLICKEYBYTES];
/// Array containing private key bytes.
pub type AsymSecretKey = [u8; box_::SECRETKEYBYTES];
/// Array containing nonce bytes.
pub type AsymNonce = [u8; box_::NONCEBYTES];

/// Array containing private key bytes.
pub type SymSecretKey = [u8; secretbox::KEYBYTES];
/// Array containing nonce bytes.
pub type SymNonce = [u8; secretbox::NONCEBYTES];

/// Array containing sign public key bytes.
pub type SignPublicKey = [u8; sign::PUBLICKEYBYTES];
/// Array containing sign private key bytes.
pub type SignSecretKey = [u8; sign::SECRETKEYBYTES];

/// Array containing `XorName` bytes.
pub type XorNameArray = [u8; XOR_NAME_LEN];
