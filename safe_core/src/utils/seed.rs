// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use client::ClientKeys;
use errors::CoreError;
use safe_crypto::{self, PublicSignKey, Seed, SEED_BYTES};

/// Amount of seed subparts used when calculating values from a seed.
pub const SEED_SUBPARTS: usize = 4;

/// Calculate sign key from seed.
pub fn sign_pk_from_seed(seed: &str) -> Result<PublicSignKey, CoreError> {
    let arr = divide_seed(seed)?;
    let mut seed_bytes: [u8; SEED_BYTES] = Default::default();
    seed_bytes.copy_from_slice(&safe_crypto::hash(arr[SEED_SUBPARTS - 2]));

    let id_seed = Seed::from_bytes(seed_bytes);
    let maid_keys = ClientKeys::new(Some(&id_seed));

    Ok(maid_keys.sign_pk)
}

/// Divide `seed` into the number of subparts given by `SEED_SUBPARTS`.
pub fn divide_seed(seed: &str) -> Result<[&[u8]; SEED_SUBPARTS], CoreError> {
    let seed = seed.as_bytes();
    if seed.len() < SEED_SUBPARTS {
        let e = format!(
            "Improper Seed length of {}. Please supply bigger Seed.",
            seed.len()
        );
        return Err(CoreError::Unexpected(e));
    }

    let interval = seed.len() / SEED_SUBPARTS;

    let mut arr: [&[u8]; SEED_SUBPARTS] = Default::default();
    for (i, val) in arr.iter_mut().enumerate() {
        *val = &seed[interval * i..interval * (i + 1)];
    }

    Ok(arr)
}
