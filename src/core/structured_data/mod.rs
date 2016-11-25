// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net
// Commercial License, version 1.0 or later, or (2) The General Public License
// (GPL), version 3, depending on which licence you accepted on initial access
// to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project
// generally, you agree to be bound by the terms of the MaidSafe Contributor
// Agreement, version 1.0.
// This, along with the Licenses can be found in the root directory of this
// project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network
// Software distributed under the GPL Licence is distributed on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
//
// Please review the Licences for the specific language governing permissions
// and limitations relating to use of the SAFE Network Software.

use core::{Client, CoreError, CoreFuture};
use core::futures::FutureExt;
use futures::Future;
use maidsafe_utilities::serialisation::serialise;
use routing::{Data, DataIdentifier, MAX_STRUCTURED_DATA_SIZE_IN_BYTES, StructuredData,
              XOR_NAME_LEN, XorName};
use rust_sodium::crypto::sign;
use std::{u64, u8};

/// Unversioned-Structured Data
pub mod unversioned;
/// Versioned-Structured Data
pub mod versioned;

const PADDING_SIZE_IN_BYTES: usize = 1024;
const MIN_RESIDUAL_SPACE_FOR_VALID_STRUCTURED_DATA_IN_BYTES: usize = 70;

/// Inform about data fitting or not into given StructuredData
#[derive(Eq, PartialEq, Ord, PartialOrd, Debug)]
pub enum DataFitResult {
    /// Invalid StrucuturedData.
    NoDataCanFit,
    /// Given data is too large to fit into the given StructuredData
    DataDoesNotFit,
    /// Given data fits into the given StructuredData
    DataFits,
}

/// Check if it is possible to fit the given data into the given StructuredData
pub fn can_data_fit(data: &[u8],
                    curr_owner_keys: Vec<sign::PublicKey>,
                    prev_owner_keys: Vec<sign::PublicKey>)
                    -> Result<DataFitResult, CoreError> {
    if data.len() > MAX_STRUCTURED_DATA_SIZE_IN_BYTES - PADDING_SIZE_IN_BYTES {
        Ok(DataFitResult::DataDoesNotFit)
    } else {
        let available_size = approximate_space_for_data(curr_owner_keys, prev_owner_keys)?;
        if available_size <= MIN_RESIDUAL_SPACE_FOR_VALID_STRUCTURED_DATA_IN_BYTES {
            Ok(DataFitResult::NoDataCanFit)
        } else if available_size < data.len() {
            Ok(DataFitResult::DataDoesNotFit)
        } else {
            Ok(DataFitResult::DataFits)
        }
    }
}

/// Calculates approximate space available for data. Calculates the worst case
/// scenario in which all owners must sign this StructuredData.
pub fn approximate_space_for_data(curr_owner_keys: Vec<sign::PublicKey>,
                                  prev_owner_keys: Vec<sign::PublicKey>)
                                  -> Result<usize, CoreError> {
    let max_signatures_possible = if prev_owner_keys.is_empty() {
        curr_owner_keys.len()
    } else {
        prev_owner_keys.len()
    };

    let mut data = StructuredData::new(u64::MAX,
                                       XorName([u8::MAX; XOR_NAME_LEN]),
                                       u64::MAX,
                                       Vec::new(),
                                       curr_owner_keys,
                                       prev_owner_keys,
                                       None)?;

    // Fill it with rest of signatures
    let signatures =
        vec![sign::Signature([u8::MAX; sign::SIGNATUREBYTES]); max_signatures_possible];
    data.replace_signatures(signatures);

    let data_len = serialise(&data)?.len() + PADDING_SIZE_IN_BYTES;
    if MAX_STRUCTURED_DATA_SIZE_IN_BYTES <= data_len {
        Ok(0)
    } else {
        Ok(MAX_STRUCTURED_DATA_SIZE_IN_BYTES - data_len)
    }
}

/// GET structured data from the network.
pub fn get(client: &Client, type_tag: u64, id: &XorName) -> Box<CoreFuture<StructuredData>> {
    let data_id = DataIdentifier::Structured(*id, type_tag);
    client.get(data_id, None)
        .and_then(|data| match data {
            Data::Structured(data) => Ok(data),
            _ => Err(CoreError::ReceivedUnexpectedData),
        })
        .into_box()
}

/// Delete structured data from the network.
pub fn delete(client: &Client,
              data: StructuredData,
              signing_key: &sign::SecretKey)
              -> Box<CoreFuture<()>> {
    let data = fry!(create_for_deletion(data, signing_key));
    client.delete(Data::Structured(data), None)
}

/// Delete structured data from the network, with recovery
pub fn delete_recover(client: &Client,
                      data: StructuredData,
                      signing_key: &sign::SecretKey)
                      -> Box<CoreFuture<()>> {
    let data = fry!(create_for_deletion(data, signing_key));
    client.delete_recover(Data::Structured(data), None)
}

fn create_for_deletion(data: StructuredData,
                       signing_key: &sign::SecretKey)
                       -> Result<StructuredData, CoreError> {
    Ok(StructuredData::new(data.get_type_tag(),
                           *data.name(),
                           data.get_version() + 1,
                           vec![],
                           vec![],
                           data.get_owner_keys().clone(),
                           Some(signing_key))?)
}

#[cfg(test)]
mod tests {
    use core::utility::test_utils;
    use routing::MAX_STRUCTURED_DATA_SIZE_IN_BYTES;
    use super::*;

    // Refers the fixed size of the get_approximate_space_for_data fn without
    // signatures
    const DEFAULT_FIXED_SIZE: usize = MAX_STRUCTURED_DATA_SIZE_IN_BYTES - 1112;
    // 112 is the size of a signature after serialisation.
    const FIXED_SIZE_OF_SIGNATURE: usize = 112;

    #[test]
    fn test_approximate_space_for_data() {
        // Assertion based on Fixed Key sizes
        {
            let mut keys = test_utils::get_max_sized_public_keys(1);
            assert_eq!(unwrap!(approximate_space_for_data(keys.clone(), Vec::new())),
                       DEFAULT_FIXED_SIZE - FIXED_SIZE_OF_SIGNATURE);
            keys.extend(test_utils::get_max_sized_public_keys(1));
            assert_eq!(unwrap!(approximate_space_for_data(keys.clone(), Vec::new())),
                       DEFAULT_FIXED_SIZE - (FIXED_SIZE_OF_SIGNATURE * keys.len()));
            keys.extend(test_utils::get_max_sized_public_keys(902)); // 904 keys Max
            let max_used_space = unwrap!(approximate_space_for_data(keys.clone(), Vec::new()));
            assert!((max_used_space < FIXED_SIZE_OF_SIGNATURE) && (max_used_space > 0));
            keys.extend(test_utils::get_max_sized_public_keys(1));
            let space = unwrap!(approximate_space_for_data(keys.clone(), Vec::new()));
            assert_eq!(space, 0);
        }
        // Random key assertions
        {
            let mut keys = test_utils::generate_public_keys(10);
            let space = unwrap!(approximate_space_for_data(keys.clone(), Vec::new()));
            assert!(space > 5000);

            let space = unwrap!(approximate_space_for_data(test_utils::generate_public_keys(1),
                                                           keys.clone()));
            assert!(space > 5000);

            keys.extend(test_utils::generate_public_keys(40)); // 50 keys
            let space = unwrap!(approximate_space_for_data(keys.clone(), Vec::new()));
            assert!(space > 5000);

            let space = unwrap!(approximate_space_for_data(test_utils::generate_public_keys(1),
                                                           keys.clone()));
            assert!(space > 5000);

            keys.extend(test_utils::generate_public_keys(850)); // 900 keys
            let space = unwrap!(approximate_space_for_data(keys.clone(), Vec::new()));
            assert!(space > 100);

            let space = unwrap!(approximate_space_for_data(test_utils::generate_public_keys(1),
                                                           keys.clone()));
            assert!(space > 100);
        }
    }

    #[test]
    fn test_can_data_fit() {
        // Assertion based on Fixed Key sizes Maximum of 904 keys can be accommodated
        // after serialisation. Thus the fixed key tests work on that calculation
        {
            let mut keys = test_utils::get_max_sized_public_keys(1);
            assert_eq!(DataFitResult::DataFits,
                       unwrap!(can_data_fit(&[], keys.clone(), Vec::new())));
            assert_eq!(DataFitResult::DataDoesNotFit,
                       unwrap!(can_data_fit(&[1u8; 102400], keys.clone(), Vec::new())));
            assert_eq!(DataFitResult::DataDoesNotFit,
                       unwrap!(can_data_fit(&[1u8; 103424], keys.clone(), Vec::new())));
            keys.extend(test_utils::get_max_sized_public_keys(902));
            assert_eq!(DataFitResult::DataFits,
                       unwrap!(can_data_fit(&[], keys.clone(), Vec::new())));
            assert_eq!(DataFitResult::DataDoesNotFit,
                       unwrap!(can_data_fit(&[0u8; 102400], keys.clone(), Vec::new())));
            keys.extend(test_utils::get_max_sized_public_keys(1));
            assert_eq!(DataFitResult::NoDataCanFit,
                       unwrap!(can_data_fit(&[], keys.clone(), Vec::new())));
        }
        // Empty data
        {
            let mut keys = test_utils::generate_public_keys(250);
            assert_eq!(DataFitResult::DataFits,
                       unwrap!(can_data_fit(&[], keys.clone(), Vec::new())));
            assert_eq!(DataFitResult::DataFits,
                       unwrap!(can_data_fit(&[],
                                            test_utils::generate_public_keys(1),
                                            keys.clone())));
            keys.extend(test_utils::generate_public_keys(750));
            assert_eq!(DataFitResult::NoDataCanFit,
                       unwrap!(can_data_fit(&[], keys, Vec::new())));
        }
        // Data of size 80kb
        {
            let data = vec![99u8; 1024 * 80];
            let mut keys = test_utils::generate_public_keys(1);
            assert_eq!(DataFitResult::DataFits,
                       unwrap!(can_data_fit(&data, keys.clone(), Vec::new())));
            keys.extend(test_utils::generate_public_keys(98));
            assert_eq!(DataFitResult::DataFits,
                       unwrap!(can_data_fit(&data, keys.clone(), Vec::new())));
            keys.extend(test_utils::generate_public_keys(190));
            assert_eq!(DataFitResult::DataDoesNotFit,
                       unwrap!(can_data_fit(&data, keys.clone(), Vec::new())));
            keys.extend(test_utils::generate_public_keys(610));
            assert_eq!(DataFitResult::DataDoesNotFit,
                       unwrap!(can_data_fit(&data, keys.clone(), Vec::new())));
            keys.extend(test_utils::generate_public_keys(15));
            assert_eq!(DataFitResult::NoDataCanFit,
                       unwrap!(can_data_fit(&data, keys, Vec::new())));
        }
        // Data size of 100 kb
        {
            let data = vec![1u8; 102400];
            assert_eq!(DataFitResult::DataDoesNotFit,
                       unwrap!(can_data_fit(&data,
                                            test_utils::generate_public_keys(1),
                                            Vec::new())));
        }
        // Data size of 101 kb
        {
            let data = vec![1u8; 103424];
            assert_eq!(DataFitResult::DataDoesNotFit,
                       unwrap!(can_data_fit(&data,
                                            test_utils::generate_public_keys(1),
                                            Vec::new())));
        }
    }
}
