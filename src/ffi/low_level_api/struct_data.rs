// Copyright 2016 MaidSafe.net limited.
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

use core::{CLIENT_STRUCTURED_DATA_TAG, immut_data_operations};
use core::client::Client;
use core::errors::CoreError;
use core::structured_data_operations::{unversioned, versioned};
use ffi::app::App;
use ffi::errors::FfiError;
use ffi::helper;
use ffi::low_level_api::{CipherOptHandle, DataIdHandle, StructDataHandle};
use ffi::low_level_api::cipher_opt::CipherOpt;
use ffi::low_level_api::object_cache::object_cache;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{Data, DataIdentifier, ImmutableData, NO_OWNER_PUB_KEY, StructuredData, XOR_NAME_LEN,
              XorName};
use std::{mem, ptr, slice};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

/// Create new `StructuredData`
#[no_mangle]
pub unsafe extern "C" fn struct_data_new(app: *const App,
                                         type_tag: u64,
                                         id: *const [u8; XOR_NAME_LEN],
                                         version: u64,
                                         cipher_opt_h: CipherOptHandle,
                                         data: *const u8,
                                         size: usize,
                                         o_handle: *mut StructDataHandle)
                                         -> i32 {
    helper::catch_unwind_i32(|| {
        let app = &*app;
        let client = app.get_client();
        let xor_id = XorName(*id);
        let plain_text = slice::from_raw_parts(data, size).to_owned();

        let (owner_key, private_signing_key) = {
            let client_guard = unwrap!(client.lock());
            let owner_key = *ffi_try!(client_guard.get_public_signing_key());
            let private_signing_key = ffi_try!(client_guard.get_secret_signing_key()).clone();
            (owner_key, private_signing_key)
        };

        let mut owners = BTreeSet::new();
        owners.insert(owner_key);

        let mut sd = match type_tag {
            ::UNVERSIONED_STRUCT_DATA_TYPE_TAG => {
                let raw_data = ffi_try!(ffi_try!(unwrap!(object_cache())
                                                     .get_cipher_opt(cipher_opt_h))
                                                .encrypt(app, &plain_text));

                ffi_try!(unversioned::create(client,
                                             type_tag,
                                             xor_id,
                                             version,
                                             raw_data,
                                             owners,
                                             None))
            }
            ::VERSIONED_STRUCT_DATA_TYPE_TAG => {
                let immut_data =
                    ffi_try!(immut_data_operations::create(client.clone(), plain_text, None));
                // TODO The above data could be exactly 1 MiB and ideally should not be touched any
                // more. For this however we will require CipherOpt to be in core module. Until
                // that we need to live with this.
                let ser_immut_data = ffi_try!(serialise(&immut_data).map_err(FfiError::from));
                let raw_data = ffi_try!(ffi_try!(unwrap!(object_cache())
                                                     .get_cipher_opt(cipher_opt_h))
                                                .encrypt(app, &ser_immut_data));

                let immut_data_final = Data::Immutable(ImmutableData::new(raw_data));
                let immut_data_final_name = *immut_data_final.name();

                let resp_getter = ffi_try!(unwrap!(client.lock()).put(immut_data_final, None));
                ffi_try!(resp_getter.get());

                ffi_try!(versioned::create(client,
                                           immut_data_final_name,
                                           type_tag,
                                           xor_id,
                                           version,
                                           owners))
            }
            x if x >= CLIENT_STRUCTURED_DATA_TAG => {
                let raw_data = ffi_try!(ffi_try!(unwrap!(object_cache())
                                                     .get_cipher_opt(cipher_opt_h))
                                                .encrypt(app, &plain_text));

                ffi_try!(StructuredData::new(type_tag, xor_id, version, raw_data, owners)
                             .map_err(CoreError::from))
            }
            _ => ffi_try!(Err(FfiError::InvalidStructuredDataTypeTag)),
        };

        let _ = ffi_try!(sd.add_signature(&(owner_key, private_signing_key))
                             .map_err(CoreError::from));

        let handle = unwrap!(object_cache()).insert_sd(sd);
        ptr::write(o_handle, handle);

        0
    })
}

/// Fetch an existing `StructuredData` from Network.
#[no_mangle]
pub unsafe extern "C" fn struct_data_fetch(app: *const App,
                                           data_id_h: DataIdHandle,
                                           o_handle: *mut StructDataHandle)
                                           -> i32 {
    helper::catch_unwind_i32(|| {
        let client = (*app).get_client();
        let data_id = *ffi_try!(unwrap!(object_cache()).get_data_id(data_id_h));
        let resp_getter = ffi_try!(unwrap!(client.lock()).get(data_id, None));
        let sd = match ffi_try!(resp_getter.get()) {
            Data::Structured(sd) => sd,
            _ => ffi_try!(Err(CoreError::ReceivedUnexpectedData)),
        };

        let handle = unwrap!(object_cache()).insert_sd(sd);
        ptr::write(o_handle, handle);

        0
    })
}

// TODO possibly move this to data_id module
/// Extract `DataIdentifier` from `StructuredData`.
#[no_mangle]
pub unsafe extern "C" fn struct_data_extract_data_id(sd_h: StructDataHandle,
                                                     o_handle: *mut DataIdHandle)
                                                     -> i32 {
    helper::catch_unwind_i32(|| {
                                 let mut obj_cache = unwrap!(object_cache());
                                 let data_id = ffi_try!(obj_cache.get_sd(sd_h)).identifier();
                                 let handle = obj_cache.insert_data_id(data_id);
                                 ptr::write(o_handle, handle);

                                 0
                             })
}

// TODO See if we can extract common functionality and merge with new() above
/// Put new data into `StructuredData`. Version is not updated. It will be updated on POST.
#[no_mangle]
pub unsafe extern "C" fn struct_data_new_data(app: *const App,
                                              sd_h: StructDataHandle,
                                              cipher_opt_h: CipherOptHandle,
                                              data: *const u8,
                                              size: usize)
                                              -> i32 {
    helper::catch_unwind_i32(|| {
        let mut object_cache = unwrap!(object_cache());

        let app = &*app;
        let client = app.get_client();
        let plain_text = slice::from_raw_parts(data, size).to_owned();

        let owner_key = *ffi_try!(unwrap!(client.lock()).get_public_signing_key());
        let sign_key = ffi_try!(unwrap!(client.lock()).get_secret_signing_key()).clone();

        let mut new_sd = match ffi_try!(object_cache.get_sd(sd_h)).get_type_tag() {
            ::UNVERSIONED_STRUCT_DATA_TYPE_TAG => {
                let raw_data = ffi_try!(ffi_try!(object_cache.get_cipher_opt(cipher_opt_h))
                                            .encrypt(app, &plain_text));

                let sd = ffi_try!(object_cache.get_sd(sd_h));
                ffi_try!(unversioned::create(client,
                                             sd.get_type_tag(),
                                             *sd.name(),
                                             sd.get_version(),
                                             raw_data,
                                             sd.get_owners().clone(),
                                             // TODO avoid cloning this above
                                             None))
            }
            ::VERSIONED_STRUCT_DATA_TYPE_TAG => {
                let immut_data =
                    ffi_try!(immut_data_operations::create(client.clone(), plain_text, None));
                let ser_immut_data = ffi_try!(serialise(&immut_data).map_err(FfiError::from));
                let raw_data = ffi_try!(ffi_try!(object_cache.get_cipher_opt(cipher_opt_h))
                                            .encrypt(app, &ser_immut_data));

                let immut_data_final = Data::Immutable(ImmutableData::new(raw_data));
                let immut_data_final_name = *immut_data_final.name();

                let resp_getter = ffi_try!(unwrap!(client.lock()).put(immut_data_final, None));
                ffi_try!(resp_getter.get());

                ffi_try!(versioned::append_version(client,
                                                   ffi_try!(object_cache.get_sd(sd_h)).clone(),
                                                   immut_data_final_name,
                                                   &sign_key,
                                                   false))
            }
            x if x >= CLIENT_STRUCTURED_DATA_TAG => {
                let raw_data = ffi_try!(ffi_try!(object_cache.get_cipher_opt(cipher_opt_h))
                                            .encrypt(app, &plain_text));

                let sd = ffi_try!(object_cache.get_sd(sd_h));
                ffi_try!(StructuredData::new(sd.get_type_tag(),
                                             *sd.name(),
                                             sd.get_version(),
                                             raw_data,
                                             sd.get_owners().clone())
                                 .map_err(CoreError::from))
            }
            _ => ffi_try!(Err(FfiError::InvalidStructuredDataTypeTag)),
        };

        let _ = ffi_try!(new_sd
                             .add_signature(&(owner_key, sign_key))
                             .map_err(CoreError::from));

        *ffi_try!(object_cache.get_sd(sd_h)) = new_sd;
        0
    })
}

/// Extract data from `StructuredData`
#[no_mangle]
pub unsafe extern "C" fn struct_data_extract_data(app: *const App,
                                                  sd_h: StructDataHandle,
                                                  o_data: *mut *mut u8,
                                                  o_size: *mut usize,
                                                  o_capacity: *mut usize)
                                                  -> i32 {
    helper::catch_unwind_i32(|| {
        let app = &*app;
        let client = app.get_client();

        // Note: Order of locking is object_cache followed by client - ensure this order
        // everywhere.
        let mut obj_cache = unwrap!(object_cache());

        let mut plain_text = match ffi_try!(obj_cache.get_sd(sd_h)).get_type_tag() {
            ::UNVERSIONED_STRUCT_DATA_TYPE_TAG => {
                let raw_data =
                    ffi_try!(unversioned::get_data(client, ffi_try!(obj_cache.get_sd(sd_h)), None));
                ffi_try!(CipherOpt::decrypt(&app, &raw_data))
            }
            ::VERSIONED_STRUCT_DATA_TYPE_TAG => {
                let immut_data_final_name =
                    ffi_try!(versioned::current_version(ffi_try!(obj_cache.get_sd(sd_h))));

                let resp_getter = ffi_try!(unwrap!(client.lock())
                    .get(DataIdentifier::Immutable(immut_data_final_name), None));
                let immut_data_final = match ffi_try!(resp_getter.get()) {
                    Data::Immutable(immut_data) => immut_data,
                    _ => ffi_try!(Err(CoreError::ReceivedUnexpectedData)),
                };

                let ser_immut_data = ffi_try!(CipherOpt::decrypt(&app, immut_data_final.value()));
                let immut_data = ffi_try!(deserialise::<ImmutableData>(&ser_immut_data)
                                              .map_err(FfiError::from));
                ffi_try!(immut_data_operations::get_data_from_immut_data(client, immut_data, None))
            }
            x if x >= CLIENT_STRUCTURED_DATA_TAG => {
                ffi_try!(CipherOpt::decrypt(&app, ffi_try!(obj_cache.get_sd(sd_h)).get_data()))
            }
            _ => ffi_try!(Err(FfiError::InvalidStructuredDataTypeTag)),
        };

        *o_data = plain_text.as_mut_ptr();
        ptr::write(o_size, plain_text.len());
        ptr::write(o_capacity, plain_text.capacity());
        mem::forget(plain_text);

        0
    })
}

/// Get number of versions from a versioned `StructuredData`
#[no_mangle]
pub unsafe extern "C" fn struct_data_num_of_versions(sd_h: StructDataHandle,
                                                     o_num: *mut usize)
                                                     -> i32 {
    helper::catch_unwind_i32(|| {
                                 let mut obj_cache = unwrap!(object_cache());
                                 let sd = ffi_try!(obj_cache.get_sd(sd_h));
                                 let num = ffi_try!(versioned::version_count(&sd)
                                                        .map_err(FfiError::from));
                                 ptr::write(o_num, num as usize);
                                 0
                             })
}

/// Get nth (starts from 0) version from a versioned `StructuredData`
#[no_mangle]
pub unsafe extern "C" fn struct_data_nth_version(app: *const App,
                                                 sd_h: StructDataHandle,
                                                 n: usize,
                                                 o_data: *mut *mut u8,
                                                 o_size: *mut usize,
                                                 o_capacity: *mut usize)
                                                 -> i32 {
    helper::catch_unwind_i32(|| {
        let app = &*app;
        let client = app.get_client();

        let mut versions = {
            let mut obj_cache = unwrap!(object_cache());
            let sd = ffi_try!(obj_cache.get_sd(sd_h));

            if sd.get_type_tag() != ::VERSIONED_STRUCT_DATA_TYPE_TAG {
                ffi_try!(Err(FfiError::InvalidStructuredDataTypeTag));
            }

            ffi_try!(versioned::get_all_versions(client.clone(), sd))
        };

        if n >= versions.len() {
            ffi_try!(Err(FfiError::InvalidVersionNumber));
        }

        // TODO Try to combine this code with above (extract_data) if it makes it smaller
        let immut_data_final_name = versions.remove(n);
        let resp_getter = ffi_try!(unwrap!(client.lock())
                                       .get(DataIdentifier::Immutable(immut_data_final_name),
                                            None));
        let immut_data_final = match ffi_try!(resp_getter.get()) {
            Data::Immutable(immut_data) => immut_data,
            _ => ffi_try!(Err(CoreError::ReceivedUnexpectedData)),
        };

        let ser_immut_data = ffi_try!(CipherOpt::decrypt(&app, immut_data_final.value()));
        let immut_data = ffi_try!(deserialise::<ImmutableData>(&ser_immut_data)
                                      .map_err(FfiError::from));
        let mut plain_text =
            ffi_try!(immut_data_operations::get_data_from_immut_data(client, immut_data, None));

        *o_data = plain_text.as_mut_ptr();
        ptr::write(o_size, plain_text.len());
        ptr::write(o_capacity, plain_text.capacity());
        mem::forget(plain_text);

        0
    })
}

/// PUT `StructuredData`
#[no_mangle]
pub unsafe extern "C" fn struct_data_put(app: *const App, sd_h: StructDataHandle) -> i32 {
    helper::catch_unwind_i32(|| {
        let sd = ffi_try!(unwrap!(object_cache()).get_sd(sd_h)).clone();
        let data = Data::Structured(sd);
        let client = (*app).get_client();
        let resp_getter = ffi_try!(unwrap!(client.lock()).put(data, None));
        ffi_try!(resp_getter.get());

        0
    })
}

/// Make `StructuredData` unclaimable - after this operation, the `StructuredData` will remain in
/// the network with no data but will not be claimable by anyone any more including the original
/// owner.
#[no_mangle]
pub unsafe extern "C" fn struct_data_make_unclaimable(app: *const App,
                                                      sd_h: StructDataHandle)
                                                      -> i32 {
    helper::catch_unwind_i32(|| {
        let mut object_cache = unwrap!(object_cache());
        let sd = ffi_try!(object_cache.get_sd(sd_h));
        match struct_data_post_impl((*app).get_client(), sd, true) {
            Ok(new_sd) => {
                *sd = new_sd;
                0
            }
            Err(e) => ffi_try!(Err(e)),
        }
    })
}

/// POST `StructuredData`. This will bump version.
#[no_mangle]
pub unsafe extern "C" fn struct_data_post(app: *const App, sd_h: StructDataHandle) -> i32 {
    helper::catch_unwind_i32(|| {
        let mut object_cache = unwrap!(object_cache());
        let sd = ffi_try!(object_cache.get_sd(sd_h));
        match struct_data_post_impl((*app).get_client(), sd, false) {
            Ok(new_sd) => {
                *sd = new_sd;
                0
            }
            Err(e) => ffi_try!(Err(e)),
        }
    })
}

fn struct_data_post_impl(client: Arc<Mutex<Client>>,
                         sd: &StructuredData,
                         make_unclaimable: bool)
                         -> Result<StructuredData, FfiError> {
    let mut new_sd = {
        if make_unclaimable {
            let mut owners = BTreeSet::new();
            owners.insert(NO_OWNER_PUB_KEY);

            StructuredData::new(sd.get_type_tag(),
                                *sd.name(),
                                sd.get_version() + 1,
                                vec![],
                                owners)
                    .map_err(CoreError::from)?
        } else {
            // TODO Ask routing to remove this inefficiency of requiring to clone data and all
            StructuredData::new(sd.get_type_tag(),
                                *sd.name(),
                                sd.get_version() + 1,
                                sd.get_data().clone(),
                                sd.get_owners().clone())
                    .map_err(CoreError::from)?
        }
    };

    let owner_key = *unwrap!(client.lock()).get_public_signing_key()?;
    let private_signing_key = unwrap!(client.lock()).get_secret_signing_key()?.clone();
    let _ = new_sd
        .add_signature(&(owner_key, private_signing_key))
        .map_err(CoreError::from)?;

    let data = Data::Structured(new_sd.clone());
    let resp_getter = unwrap!(client.lock()).post(data, None)?;
    resp_getter.get()?;

    Ok(new_sd)
}

/// DELETE `StructuredData`. Version will be bumped.
#[no_mangle]
pub unsafe extern "C" fn struct_data_delete(app: *const App, sd_h: StructDataHandle) -> i32 {
    helper::catch_unwind_i32(|| {
        let mut object_cache = unwrap!(object_cache());
        let sd = ffi_try!(object_cache.get_sd(sd_h));
        match struct_data_delete_impl((*app).get_client(), sd) {
            Ok(new_sd) => {
                *sd = new_sd;
                0
            }
            Err(e) => ffi_try!(Err(e)),
        }
    })
}

fn struct_data_delete_impl(client: Arc<Mutex<Client>>,
                           sd: &StructuredData)
                           -> Result<StructuredData, FfiError> {
    // TODO Ask routing to remove this inefficiency of requiring to clone data and all
    let mut new_sd = StructuredData::new(sd.get_type_tag(),
                                         *sd.name(),
                                         sd.get_version() + 1,
                                         vec![],
                                         sd.get_owners().clone())
            .map_err(CoreError::from)?;

    let owner_key = *unwrap!(client.lock()).get_public_signing_key()?;
    let private_signing_key = unwrap!(client.lock()).get_secret_signing_key()?.clone();
    let _ = new_sd
        .add_signature(&(owner_key, private_signing_key))
        .map_err(CoreError::from)?;

    let data = Data::Structured(new_sd.clone());
    let resp_getter = unwrap!(client.lock()).delete(data, None)?;
    resp_getter.get()?;

    Ok(new_sd)
}

/// See if `StructuredData` size is valid.
#[no_mangle]
pub unsafe extern "C" fn struct_data_validate_size(handle: StructDataHandle,
                                                   o_valid: *mut bool)
                                                   -> i32 {
    helper::catch_unwind_i32(|| {
                                 *o_valid = ffi_try!(unwrap!(object_cache()).get_sd(handle))
                                     .validate_size();
                                 0
                             })
}

/// Get the current version of `StructuredData` by its handle
#[no_mangle]
pub unsafe extern "C" fn struct_data_version(handle: StructDataHandle, o_version: *mut u64) -> i32 {
    helper::catch_unwind_i32(|| {
                                 *o_version = ffi_try!(unwrap!(object_cache()).get_sd(handle))
                                     .get_version();
                                 0
                             })
}

/// Returns true if the app is one of the owners of the provided `StructuredData`.
#[no_mangle]
pub unsafe extern "C" fn struct_data_is_owned(app: *const App,
                                              handle: StructDataHandle,
                                              o_is_owned: *mut bool)
                                              -> i32 {
    helper::catch_unwind_i32(|| {
        let client = (*app).get_client();
        let my_key = *ffi_try!(unwrap!(client.lock()).get_public_signing_key());

        *o_is_owned = ffi_try!(unwrap!(object_cache()).get_sd(handle))
            .get_owners()
            .contains(&my_key);

        0
    })
}

/// Free `StructuredData` handle
#[no_mangle]
pub extern "C" fn struct_data_free(handle: StructDataHandle) -> i32 {
    helper::catch_unwind_i32(|| {
                                 let _ = ffi_try!(unwrap!(object_cache()).remove_sd(handle));
                                 0
                             })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::{CLIENT_STRUCTURED_DATA_TAG, utility};
    use ffi::app::App;
    use ffi::errors::FfiError;
    use ffi::low_level_api::{CipherOptHandle, DataIdHandle, StructDataHandle};
    use ffi::low_level_api::cipher_opt::*;
    use ffi::low_level_api::object_cache::object_cache;
    use ffi::test_utils;
    use rand;
    use std::ptr;

    #[test]
    fn make_unclaimable() {
        let app = test_utils::create_app(false);

        let mut cipher_opt_h: CipherOptHandle = 0;
        let mut sd_h: StructDataHandle = 0;
        let mut data_id_h: DataIdHandle = 0;

        let id = rand::random();
        let plain_text = unwrap!(utility::generate_random_vector::<u8>(10));

        unsafe {
            assert_eq!(cipher_opt_new_symmetric(&mut cipher_opt_h), 0);

            // Create
            assert_eq!(struct_data_new(&app,
                                       ::UNVERSIONED_STRUCT_DATA_TYPE_TAG,
                                       &id,
                                       0,
                                       cipher_opt_h,
                                       plain_text.as_ptr(),
                                       plain_text.len(),
                                       &mut sd_h),
                       0);
            assert_eq!(struct_data_extract_data_id(sd_h, &mut data_id_h), 0);
            assert_eq!(struct_data_put(&app, sd_h), 0);

            // Make unclaimable
            assert_eq!(struct_data_make_unclaimable(&app, sd_h), 0);

            // Try to read data - it should return an error
            assert_eq!(struct_data_fetch(&app, data_id_h, &mut sd_h), 0);
            let _ = unwrap!(object_cache()).get_sd(sd_h);

            let mut data_ptr = ptr::null_mut();
            let mut data_size = 0usize;
            let mut data_cap = 0usize;

            assert_ne!(struct_data_extract_data(&app,
                                                sd_h,
                                                &mut data_ptr,
                                                &mut data_size,
                                                &mut data_cap),
                       0);

            // Check that SD is not owned anymore and the only owner key is NO_OWNER_PUBKEY.
            let mut is_owned = false;
            assert_eq!(struct_data_is_owned(&app, sd_h, &mut is_owned), 0);
            assert_eq!(is_owned, false);
            assert!(unwrap!(unwrap!(object_cache()).get_sd(sd_h))
                        .get_owners()
                        .contains(&NO_OWNER_PUB_KEY));

            // Try to do POST and DELETE - they should fail
            // -25 is CoreError::InvalidSuccessor { reason: MutationError::InvalidOwners }
            let new_plain_text = unwrap!(utility::generate_random_vector::<u8>(10));
            assert_eq!(struct_data_new_data(&app,
                                            sd_h,
                                            cipher_opt_h,
                                            new_plain_text.as_ptr(),
                                            new_plain_text.len()),
                       0);

            assert_eq!(struct_data_post(&app, sd_h), -25);
            assert_eq!(struct_data_delete(&app, sd_h), -25);
        }
    }

    #[test]
    fn unversioned_struct_data_crud() {
        let app = test_utils::create_app(false);

        let mut cipher_opt_h: CipherOptHandle = 0;
        let mut sd_h: StructDataHandle = 0;
        let mut data_id_h: DataIdHandle = 0;
        let id = rand::random();
        let mut plain_text = unwrap!(utility::generate_random_vector::<u8>(10));
        unsafe {
            assert_eq!(cipher_opt_new_symmetric(&mut cipher_opt_h), 0);

            // Create
            assert_eq!(struct_data_new(&app,
                                       ::UNVERSIONED_STRUCT_DATA_TYPE_TAG,
                                       &id,
                                       0,
                                       cipher_opt_h,
                                       plain_text.as_ptr(),
                                       plain_text.len(),
                                       &mut sd_h),
                       0);
            assert_eq!(struct_data_extract_data_id(sd_h, &mut data_id_h), 0);

            // Put
            assert_eq!(struct_data_put(&app, sd_h), 0);
            let _ = unwrap!(object_cache()).get_sd(sd_h);
            assert_eq!(struct_data_free(sd_h), 0);
            assert!(unwrap!(object_cache()).get_sd(sd_h).is_err());

            // Fetch
            assert_eq!(struct_data_fetch(&app, data_id_h, &mut sd_h), 0);
            let _ = unwrap!(object_cache()).get_sd(sd_h);

            // Extract Data
            let rx_plain_text_0 = extract_data(&app, sd_h);
            assert_eq!(rx_plain_text_0, plain_text);

            // New Data
            plain_text = unwrap!(utility::generate_random_vector::<u8>(10));
            assert_eq!(struct_data_new_data(&app,
                                            sd_h,
                                            cipher_opt_h,
                                            plain_text.as_ptr(),
                                            plain_text.len()),
                       0);

            // Post
            assert_eq!(struct_data_post(&app, sd_h), 0);
            let _ = unwrap!(object_cache()).get_sd(sd_h);
            assert_eq!(struct_data_free(sd_h), 0);
            assert!(unwrap!(object_cache()).get_sd(sd_h).is_err());

            // Fetch
            assert_eq!(struct_data_fetch(&app, data_id_h, &mut sd_h), 0);
            let _ = unwrap!(object_cache()).get_sd(sd_h);

            // Extract Data
            let rx_plain_text_1 = extract_data(&app, sd_h);
            assert_eq!(rx_plain_text_1, plain_text);
            assert!(rx_plain_text_1 != rx_plain_text_0);


            // Perform Invalid Operations - should error out
            let err_code: i32 = FfiError::InvalidStructuredDataTypeTag.into();
            let mut versions = 0;
            assert_eq!(struct_data_num_of_versions(sd_h, &mut versions), err_code);
            {
                let mut data_ptr: *mut u8 = ptr::null_mut();
                let mut data_size = 0;
                let mut capacity = 0;
                assert_eq!(struct_data_nth_version(&app,
                                                   sd_h,
                                                   0,
                                                   &mut data_ptr,
                                                   &mut data_size,
                                                   &mut capacity),
                           err_code);
            }

            // Check StructData owners
            let mut is_owned = false;
            assert_eq!(struct_data_is_owned(&app, sd_h, &mut is_owned), 0);
            assert_eq!(is_owned, true);

            let app_fake = test_utils::create_app(false);
            assert_eq!(struct_data_is_owned(&app_fake, sd_h, &mut is_owned), 0);
            assert_eq!(is_owned, false);

            // Delete
            assert_eq!(struct_data_delete(&app, sd_h), 0);
            let _ = unwrap!(object_cache()).get_sd(sd_h);

            // Re-delete should fail - MutationError::InvalidOperation; Fetch should be successful
            assert_eq!(struct_data_delete(&app, sd_h), -26);
            assert_eq!(struct_data_free(sd_h), 0);
            let err_code: i32 = FfiError::InvalidStructDataHandle.into();
            assert_eq!(struct_data_free(sd_h), err_code);
            assert!(unwrap!(object_cache()).get_sd(sd_h).is_err());

            assert_eq!(struct_data_fetch(&app, data_id_h, &mut sd_h), 0);
            assert_eq!(struct_data_free(sd_h), 0);
            assert_eq!(struct_data_free(sd_h), err_code);

            // Re-claim via PUT
            assert_eq!(struct_data_fetch(&app, data_id_h, &mut sd_h), 0);
            let mut version = 0;
            assert_eq!(struct_data_version(sd_h, &mut version), 0);
            assert_eq!(struct_data_free(sd_h), 0);
            // Create
            assert_eq!(struct_data_new(&app,
                                       ::UNVERSIONED_STRUCT_DATA_TYPE_TAG,
                                       &id,
                                       version + 1,
                                       cipher_opt_h,
                                       plain_text.as_ptr(),
                                       plain_text.len(),
                                       &mut sd_h),
                       0);

            // FIXME: after SD delete we have an empty set of owners
            // that means that we don't need to provide signatures in the SD created above
            // There should be a way to skip adding signatures or there should be a separate
            // API to sign SD.

            // Put - Reclaim
            assert_eq!(struct_data_put(&app, sd_h), 0);
        }
    }

    #[test]
    fn versioned_struct_data_crud() {
        let app = test_utils::create_app(false);

        let mut cipher_opt_h: CipherOptHandle = 0;
        let mut sd_h: StructDataHandle = 0;
        let mut data_id_h: DataIdHandle = 0;

        let name = rand::random();
        let data0 = unwrap!(utility::generate_random_vector(10));
        let data1 = unwrap!(utility::generate_random_vector(10));

        unsafe {
            assert_eq!(cipher_opt_new_symmetric(&mut cipher_opt_h), 0);

            // Create
            assert_eq!(struct_data_new(&app,
                                       ::VERSIONED_STRUCT_DATA_TYPE_TAG,
                                       &name,
                                       0,
                                       cipher_opt_h,
                                       data0.as_ptr(),
                                       data0.len(),
                                       &mut sd_h),
                       0);
            assert_eq!(struct_data_extract_data_id(sd_h, &mut data_id_h), 0);

            // Put and re-fetch
            assert_eq!(struct_data_put(&app, sd_h), 0);
            assert_eq!(struct_data_free(sd_h), 0);
            assert_eq!(struct_data_fetch(&app, data_id_h, &mut sd_h), 0);

            // Check content
            let mut num_versions = 0usize;
            assert_eq!(struct_data_num_of_versions(sd_h, &mut num_versions), 0);
            assert_eq!(num_versions, 1);
            assert_eq!(nth_version(&app, sd_h, 0), data0);

            let mut version = 0;
            assert_eq!(struct_data_version(sd_h, &mut version), 0);
            assert_eq!(version, 0);

            assert_eq!(extract_data(&app, sd_h), data0);

            // Update the content
            assert_eq!(struct_data_new_data(&app, sd_h, cipher_opt_h, data1.as_ptr(), data1.len()),
                       0);

            // Post and re-fetch
            assert_eq!(struct_data_post(&app, sd_h), 0);
            assert_eq!(struct_data_free(sd_h), 0);
            assert_eq!(struct_data_fetch(&app, data_id_h, &mut sd_h), 0);

            // Check content
            assert_eq!(struct_data_num_of_versions(sd_h, &mut num_versions), 0);
            assert_eq!(num_versions, 2);
            assert_eq!(nth_version(&app, sd_h, 0), data0);
            assert_eq!(nth_version(&app, sd_h, 1), data1);

            assert_eq!(extract_data(&app, sd_h), data1);

            let mut version = 0;
            assert_eq!(struct_data_version(sd_h, &mut version), 0);
            assert_eq!(version, 1);

            // Delete
            assert_eq!(struct_data_delete(&app, sd_h), 0);
            // -26 is CoreError::MutationFailure { reason: MutationError::InvalidOperation }
            assert_eq!(struct_data_delete(&app, sd_h), -26);
            assert_eq!(struct_data_fetch(&app, data_id_h, &mut sd_h), 0);
        }
    }

    #[test]
    fn client_struct_data_crud() {
        let app = test_utils::create_app(false);

        let mut cipher_opt_h: CipherOptHandle = 0;
        let mut sd_h: StructDataHandle = 0;
        let mut data_id_h: DataIdHandle = 0;

        let name = rand::random();
        let data0 = unwrap!(utility::generate_random_vector(10));
        let data1 = unwrap!(utility::generate_random_vector(10));

        unsafe {
            assert_eq!(cipher_opt_new_symmetric(&mut cipher_opt_h), 0);

            // Invalid client tag
            let err_code: i32 = FfiError::InvalidStructuredDataTypeTag.into();
            assert_eq!(struct_data_new(&app,
                                       CLIENT_STRUCTURED_DATA_TAG - 1,
                                       &name,
                                       0,
                                       cipher_opt_h,
                                       data0.as_ptr(),
                                       data0.len(),
                                       &mut sd_h),
                       err_code);

            // Create
            assert_eq!(struct_data_new(&app,
                                       CLIENT_STRUCTURED_DATA_TAG + 1,
                                       &name,
                                       0,
                                       cipher_opt_h,
                                       data0.as_ptr(),
                                       data0.len(),
                                       &mut sd_h),
                       0);
            assert_eq!(struct_data_extract_data_id(sd_h, &mut data_id_h), 0);

            // Put and re-fetch
            assert_eq!(struct_data_put(&app, sd_h), 0);
            assert_eq!(struct_data_free(sd_h), 0);
            assert_eq!(struct_data_fetch(&app, data_id_h, &mut sd_h), 0);

            // Check content
            assert_eq!(extract_data(&app, sd_h), data0);

            // Update the content
            assert_eq!(struct_data_new_data(&app, sd_h, cipher_opt_h, data1.as_ptr(), data1.len()),
                       0);

            // Post and re-fetch
            assert_eq!(struct_data_post(&app, sd_h), 0);
            assert_eq!(struct_data_free(sd_h), 0);
            assert_eq!(struct_data_fetch(&app, data_id_h, &mut sd_h), 0);

            // Check content
            assert_eq!(extract_data(&app, sd_h), data1);

            // Invalid operations
            let mut num_versions = 0;
            assert_eq!(struct_data_num_of_versions(sd_h, &mut num_versions),
                       err_code);

            // Delete
            assert_eq!(struct_data_delete(&app, sd_h), 0);
            // -26 is CoreError::MutationFailure { reason: MutationError::InvalidOperation }
            assert_eq!(struct_data_delete(&app, sd_h), -26);
            assert_eq!(struct_data_fetch(&app, data_id_h, &mut sd_h), 0);
        }
    }

    // Helper function to fetch the current data from the structured data using FFI.
    fn extract_data(app: &App, sd_h: StructDataHandle) -> Vec<u8> {
        let mut data_ptr = ptr::null_mut();
        let mut data_size = 0usize;
        let mut data_cap = 0usize;

        unsafe {
            assert_eq!(struct_data_extract_data(app,
                                                sd_h,
                                                &mut data_ptr,
                                                &mut data_size,
                                                &mut data_cap),
                       0);

            Vec::from_raw_parts(data_ptr, data_size, data_cap)
        }
    }

    // Helper function to fetch the nth version from the structured data using FFI.
    fn nth_version(app: &App, sd_h: StructDataHandle, n: usize) -> Vec<u8> {
        let mut data_ptr = ptr::null_mut();
        let mut data_size = 0usize;
        let mut data_cap = 0usize;

        unsafe {
            assert_eq!(struct_data_nth_version(app,
                                               sd_h,
                                               n,
                                               &mut data_ptr,
                                               &mut data_size,
                                               &mut data_cap),
                       0);

            Vec::from_raw_parts(data_ptr, data_size, data_cap)
        }
    }
}
