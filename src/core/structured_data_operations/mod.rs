// Copyright 2015 MaidSafe.net limited.
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

// TODO Remove type_tag parameter from api's of unversioned and versioned SD's as they are now
// consolidated to 500 and 501

/// Unversioned-Structured Data
pub mod unversioned;
/// Versioned-Structured Data
pub mod versioned;

use core::errors::CoreError;
use maidsafe_utilities::serialisation::serialise;
use routing::{StructuredData, XOR_NAME_LEN, XorName};
use rust_sodium::crypto::sign;
use std::{u64, u8};
use std::collections::{BTreeMap, BTreeSet};

const PADDING_SIZE_IN_BYTES: u64 = 1024;
const MIN_RESIDUAL_SPACE_FOR_VALID_STRUCTURED_DATA_IN_BYTES: u64 = 70;

/// Inform about data fitting or not into given `StructuredData`
#[derive(Eq, PartialEq, Ord, PartialOrd, Debug)]
pub enum DataFitResult {
    /// Invalid StrucuturedData.
    NoDataCanFit,
    /// Given data is too large to fit into the given StructuredData
    DataDoesNotFit,
    /// Given data fits into the given StructuredData
    DataFits,
}

/// Calculates approximate space available for data. Calculates the worst case scenario in which
/// all owners must sign this `StructuredData`.
pub fn get_approximate_space_for_data(owners: BTreeSet<sign::PublicKey>) -> Result<u64, CoreError> {
    let mut structured_data = StructuredData::new(u64::MAX,
                                                  XorName([u8::MAX; XOR_NAME_LEN]),
                                                  u64::MAX,
                                                  Vec::new(),
                                                  owners.clone())?;

    // Fill it with rest of signatures
    let max_signatures = owners
        .iter()
        .cloned()
        .fold(BTreeMap::new(), |mut signatures, owner| {
            let _ = signatures.insert(owner, sign::Signature([u8::MAX; sign::SIGNATUREBYTES]));
            signatures
        });
    structured_data.replace_signatures(max_signatures);

    let serialised_structured_data_len = serialise(&structured_data)?.len() as u64 +
                                         PADDING_SIZE_IN_BYTES;
    if ::routing::MAX_STRUCTURED_DATA_SIZE_IN_BYTES <= serialised_structured_data_len {
        Ok(0)
    } else {
        Ok(::routing::MAX_STRUCTURED_DATA_SIZE_IN_BYTES - serialised_structured_data_len)
    }
}

/// Check if it is possible to fit the given data into the given `StructuredData`
pub fn check_if_data_can_fit_in_structured_data(data: &[u8],
                                                owner_keys: BTreeSet<sign::PublicKey>)
                                                -> Result<DataFitResult, CoreError> {
    if data.len() as u64 > ::routing::MAX_STRUCTURED_DATA_SIZE_IN_BYTES - PADDING_SIZE_IN_BYTES {
        Ok(DataFitResult::DataDoesNotFit)
    } else {
        let available_size = get_approximate_space_for_data(owner_keys)?;
        if available_size <= MIN_RESIDUAL_SPACE_FOR_VALID_STRUCTURED_DATA_IN_BYTES {
            Ok(DataFitResult::NoDataCanFit)
        } else if available_size < data.len() as u64 {
            Ok(DataFitResult::DataDoesNotFit)
        } else {
            Ok(DataFitResult::DataFits)
        }
    }
}

#[cfg(test)]
mod test {
    // use core::utility::test_utils;
    // use super::*;

    // // Refers the fixed size of the get_approximate_space_for_data fn without signatures
    // const DEFAULT_FIXED_SIZE: u64 = ::routing::MAX_STRUCTURED_DATA_SIZE_IN_BYTES - 1144; // 1112;
    // // 112 is the size of a signature after serialisation.
    // const FIXED_SIZE_OF_SIGNATURE: u64 = 112;

    // #[test]
    // fn approximate_space_for_data() {
    //     // Assertion based on Fixed Key sizes
    //     {
    //         let mut keys = test_utils::get_max_sized_public_keys(1);
    //         assert_eq!(unwrap!(get_approximate_space_for_data(keys.clone())),
    //                    DEFAULT_FIXED_SIZE - FIXED_SIZE_OF_SIGNATURE);
    //         keys.extend(test_utils::get_max_sized_public_keys(1));
    //         assert_eq!(unwrap!(get_approximate_space_for_data(keys.clone())),
    //                    DEFAULT_FIXED_SIZE - (FIXED_SIZE_OF_SIGNATURE * keys.len() as u64));
    //         keys.extend(test_utils::get_max_sized_public_keys(902)); // 904 keys Max
    //         let max_used_space = unwrap!(get_approximate_space_for_data(keys.clone()));
    //         assert!((max_used_space < FIXED_SIZE_OF_SIGNATURE) && (max_used_space > 0),
    //                 "{} < {} && {} > 0",
    //                 max_used_space,
    //                 FIXED_SIZE_OF_SIGNATURE,
    //                 max_used_space);
    //         keys.extend(test_utils::get_max_sized_public_keys(1));
    //         let space = unwrap!(get_approximate_space_for_data(keys.clone()));
    //         assert_eq!(space, 0);
    //     }
    //     // Random key assertions
    //     {
    //         let mut keys = test_utils::generate_public_keys(10);
    //         let space = unwrap!(get_approximate_space_for_data(keys.clone()));
    //         assert!(space > 5000);

    //         let space = unwrap!(get_approximate_space_for_data(
    //             test_utils::generate_public_keys(1)));
    //         assert!(space > 5000);

    //         keys.extend(test_utils::generate_public_keys(40)); // 50 keys
    //         let space = unwrap!(get_approximate_space_for_data(keys.clone()));
    //         assert!(space > 5000);

    //         let space = unwrap!(get_approximate_space_for_data(
    //             test_utils::generate_public_keys(1)));
    //         assert!(space > 5000);

    //         keys.extend(test_utils::generate_public_keys(850)); // 900 keys
    //         let space = unwrap!(get_approximate_space_for_data(keys.clone()));
    //         assert!(space > 100);

    //         let space = unwrap!(get_approximate_space_for_data(
    //             test_utils::generate_public_keys(1)));
    //         assert!(space > 100);
    //     }
    // }

    // #[test]
    // fn data_can_fit_in_structured_data() {
    // // Assertion based on Fixed Key sizes
    // // Maximum of 904 keys can be accommodated after serialisation. Thus the fixed key tests
    // // work on that calculation
    // {
    //     let mut keys = test_utils::get_max_sized_public_keys(1);
    //     assert_eq!(DataFitResult::DataFits,
    //                unwrap!(check_if_data_can_fit_in_structured_data(&[], keys.clone())));
    //     assert_eq!(DataFitResult::DataDoesNotFit,
    //                unwrap!(check_if_data_can_fit_in_structured_data(&[1u8; 102400],
    //                                                                 keys.clone())));
    //     assert_eq!(DataFitResult::DataDoesNotFit,
    //                unwrap!(check_if_data_can_fit_in_structured_data(&[1u8; 103424],
    //                                                                 keys.clone())));
    //     keys.extend(test_utils::get_max_sized_public_keys(902));
    //     assert_eq!(DataFitResult::DataFits,
    //                unwrap!(check_if_data_can_fit_in_structured_data(&[], keys.clone())));
    //     assert_eq!(DataFitResult::DataDoesNotFit,
    //                unwrap!(check_if_data_can_fit_in_structured_data(&[0u8; 102400],
    //                                                                 keys.clone())));
    //     keys.extend(test_utils::get_max_sized_public_keys(1));
    //     assert_eq!(DataFitResult::NoDataCanFit,
    //                unwrap!(check_if_data_can_fit_in_structured_data(&[], keys.clone())));
    // }
    // // Empty data
    // {
    //     let mut keys = test_utils::generate_public_keys(250);
    //     assert_eq!(DataFitResult::DataFits,
    //                unwrap!(check_if_data_can_fit_in_structured_data(&[], keys.clone())));
    //     assert_eq!(DataFitResult::DataFits,
    //                unwrap!(check_if_data_can_fit_in_structured_data(
    //                    &[],
    //                    test_utils::generate_public_keys(1))));
    //     keys.extend(test_utils::generate_public_keys(750));
    //     assert_eq!(DataFitResult::NoDataCanFit,
    //                unwrap!(check_if_data_can_fit_in_structured_data(&[], keys)));
    // }
    // // Data of size 80kb
    // {
    //     let data = vec![99u8; 1024 * 80];
    //     let mut keys = test_utils::generate_public_keys(1);
    //     assert_eq!(DataFitResult::DataFits,
    //                unwrap!(check_if_data_can_fit_in_structured_data(&data, keys.clone())));
    //     keys.extend(test_utils::generate_public_keys(98));
    //     assert_eq!(DataFitResult::DataFits,
    //                unwrap!(check_if_data_can_fit_in_structured_data(&data, keys.clone())));
    //     keys.extend(test_utils::generate_public_keys(190));
    //     assert_eq!(DataFitResult::DataDoesNotFit,
    //                unwrap!(check_if_data_can_fit_in_structured_data(&data, keys.clone())));
    //     keys.extend(test_utils::generate_public_keys(610));
    //     assert_eq!(DataFitResult::DataDoesNotFit,
    //                unwrap!(check_if_data_can_fit_in_structured_data(&data, keys.clone())));
    //     keys.extend(test_utils::generate_public_keys(15));
    //     assert_eq!(DataFitResult::NoDataCanFit,
    //                unwrap!(check_if_data_can_fit_in_structured_data(&data, keys)));
    // }
    // // Data size of 100 kb
    // {
    //     let data = vec![1u8; 102400];
    //     assert_eq!(DataFitResult::DataDoesNotFit,
    //                unwrap!(check_if_data_can_fit_in_structured_data(
    //                    &data,
    //                    test_utils::generate_public_keys(1))));
    // }
    // // Data size of 101 kb
    // {
    //     let data = vec![1u8; 103424];
    //     assert_eq!(DataFitResult::DataDoesNotFit,
    //                unwrap!(check_if_data_can_fit_in_structured_data(
    //                    &data,
    //                    test_utils::generate_public_keys(1))));
    // }
    // }
}
