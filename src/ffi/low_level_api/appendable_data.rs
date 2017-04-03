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

use core::errors::CoreError;
use ffi::app::App;
use ffi::errors::FfiError;
use ffi::helper;
use ffi::low_level_api::{AppendableDataHandle, DataIdHandle, EncryptKeyHandle, SignKeyHandle};
use ffi::low_level_api::object_cache::object_cache;
use routing::{AppendWrapper, AppendedData, Data, Filter, PrivAppendableData, PrivAppendedData,
              PubAppendableData, XOR_NAME_LEN, XorName};
use std::{mem, ptr};
use std::collections::BTreeSet;
use std::iter;

/// Wrapper for `PrivAppendableData` and `PubAppendableData`.
#[derive(Clone, Debug, Hash)]
pub enum AppendableData {
    /// Public appendable data.
    Pub(PubAppendableData),
    /// Private appendable data.
    Priv(PrivAppendableData),
}

impl AppendableData {
    fn filter_mut(&mut self) -> &mut Filter {
        match *self {
            AppendableData::Pub(ref mut data) => &mut data.filter,
            AppendableData::Priv(ref mut data) => &mut data.filter,
        }
    }
}

impl Into<Data> for AppendableData {
    fn into(self) -> Data {
        match self {
            AppendableData::Pub(data) => Data::PubAppendable(data),
            AppendableData::Priv(data) => Data::PrivAppendable(data),
        }
    }
}

/// Filter Type
#[repr(C)]
#[derive(Debug, PartialEq)]
pub enum FilterType {
    /// BlackList
    BlackList,
    /// WhiteList
    WhiteList,
}

/// Create new `PubAppendableData`
#[no_mangle]
pub unsafe extern "C" fn appendable_data_new_pub(app: *const App,
                                                 name: *const [u8; XOR_NAME_LEN],
                                                 o_handle: *mut AppendableDataHandle)
                                                 -> i32 {
    helper::catch_unwind_i32(|| {
        let client = (*app).get_client();
        let name = XorName(*name);

        let (owner_key, private_signing_key) = {
            let client = unwrap!(client.lock());
            let owner_key = *ffi_try!(client.get_public_signing_key());
            let private_signing_key = ffi_try!(client.get_secret_signing_key()).clone();
            (owner_key, private_signing_key)
        };

        let mut owners = BTreeSet::new();
        owners.insert(owner_key);

        let mut data = ffi_try!(PubAppendableData::new(name,
                                                       0,
                                                       owners,
                                                       Default::default(),
                                                       Filter::black_list(iter::empty()))
                                        .map_err(CoreError::from));
        let _ = ffi_try!(data.add_signature(&(owner_key, private_signing_key))
                             .map_err(CoreError::from));

        let handle = unwrap!(object_cache()).insert_ad(AppendableData::Pub(data));

        ptr::write(o_handle, handle);
        0
    })
}

/// Create new `PrivAppendableData`
#[no_mangle]
pub unsafe extern "C" fn appendable_data_new_priv(app: *const App,
                                                  name: *const [u8; XOR_NAME_LEN],
                                                  o_handle: *mut AppendableDataHandle)
                                                  -> i32 {
    helper::catch_unwind_i32(|| {
        let app = &*app;
        let client = app.get_client();
        let name = XorName(*name);

        let (owner_key, private_signing_key) = {
            let client = unwrap!(client.lock());
            let owner_key = *ffi_try!(client.get_public_signing_key());
            let private_signing_key = ffi_try!(client.get_secret_signing_key()).clone();
            (owner_key, private_signing_key)
        };

        let mut owners = BTreeSet::new();
        owners.insert(owner_key);

        let mut data = ffi_try!(PrivAppendableData::new(name,
                                                        0,
                                                        owners,
                                                        Default::default(),
                                                        Filter::black_list(iter::empty()),
                                                        ffi_try!(app.asym_keys()).0)
                                        .map_err(CoreError::from));
        let _ = ffi_try!(data.add_signature(&(owner_key, private_signing_key))
                             .map_err(CoreError::from));

        let handle = unwrap!(object_cache()).insert_ad(AppendableData::Priv(data));

        ptr::write(o_handle, handle);
        0
    })
}

/// Get existing appendable data from Network.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_get(app: *const App,
                                             data_id_h: DataIdHandle,
                                             o_handle: *mut AppendableDataHandle)
                                             -> i32 {
    helper::catch_unwind_i32(|| {
        let data_id = *ffi_try!(unwrap!(object_cache()).get_data_id(data_id_h));

        let client = (*app).get_client();
        let resp_getter = ffi_try!(unwrap!(client.lock()).get(data_id, None));
        let data = match ffi_try!(resp_getter.get()) {
            Data::PubAppendable(data) => AppendableData::Pub(data),
            Data::PrivAppendable(data) => AppendableData::Priv(data),
            _ => ffi_try!(Err(CoreError::ReceivedUnexpectedData)),
        };

        let handle = unwrap!(object_cache()).insert_ad(data);

        ptr::write(o_handle, handle);
        0
    })
}

/// Extract `DataIdentifier` from `AppendableData`.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_extract_data_id(ad_h: AppendableDataHandle,
                                                         o_handle: *mut DataIdHandle)
                                                         -> i32 {
    helper::catch_unwind_i32(|| {
        let mut object_cache = unwrap!(object_cache());
        let data_id = match *ffi_try!(object_cache.get_ad(ad_h)) {
            AppendableData::Pub(ref elt) => elt.identifier(),
            AppendableData::Priv(ref elt) => elt.identifier(),
        };
        let handle = object_cache.insert_data_id(data_id);

        ptr::write(o_handle, handle);
        0
    })
}

/// PUT appendable data.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_put(app: *const App, ad_h: AppendableDataHandle) -> i32 {
    helper::catch_unwind_i32(|| {
        let data = ffi_try!(unwrap!(object_cache()).get_ad(ad_h)).clone();

        let client = (*app).get_client();
        let resp_getter = ffi_try!(unwrap!(client.lock()).put(data.into(), None));
        ffi_try!(resp_getter.get());

        0
    })
}

/// POST appendable data (bumps the version).
#[no_mangle]
pub unsafe extern "C" fn appendable_data_post(app: *const App,
                                              ad_h: AppendableDataHandle,
                                              include_data: bool)
                                              -> i32 {
    helper::catch_unwind_i32(|| {
        let client = (*app).get_client();

        let new_ad = {
            let mut object_cache = unwrap!(object_cache());
            let ad = ffi_try!(object_cache.get_ad(ad_h));

            match *ad {
                AppendableData::Pub(ref old_data) => {
                    let mut new_data =
                        ffi_try!(PubAppendableData::new(old_data.name,
                                                        old_data.version + 1,
                                                        old_data.owners.clone(),
                                                        old_data.deleted_data.clone(),
                                                        old_data.filter.clone())
                                         .map_err(CoreError::from));
                    if include_data {
                        new_data.data = old_data.data.clone();
                    }
                    let owner_key = *ffi_try!(unwrap!(client.lock()).get_public_signing_key());
                    let private_signing_key =
                        ffi_try!(unwrap!(client.lock()).get_secret_signing_key()).clone();
                    let _ = ffi_try!(new_data
                                         .add_signature(&(owner_key, private_signing_key))
                                         .map_err(CoreError::from));
                    AppendableData::Pub(new_data)
                }
                AppendableData::Priv(ref old_data) => {
                    let mut new_data =
                        ffi_try!(PrivAppendableData::new(old_data.name,
                                                         old_data.version + 1,
                                                         old_data.owners.clone(),
                                                         old_data.deleted_data.clone(),
                                                         old_data.filter.clone(),
                                                         old_data.encrypt_key.clone())
                                         .map_err(CoreError::from));
                    if include_data {
                        new_data.data = old_data.data.clone();
                    }
                    let owner_key = *ffi_try!(unwrap!(client.lock()).get_public_signing_key());
                    let private_signing_key =
                        ffi_try!(unwrap!(client.lock()).get_secret_signing_key()).clone();
                    let _ = ffi_try!(new_data
                                         .add_signature(&(owner_key, private_signing_key))
                                         .map_err(CoreError::from));
                    AppendableData::Priv(new_data)
                }
            }
        };
        let resp_getter = ffi_try!(unwrap!(client.lock()).post(new_ad.clone().into(), None));
        ffi_try!(resp_getter.get());
        *ffi_try!(unwrap!(object_cache()).get_ad(ad_h)) = new_ad;

        0
    })
}

// TODO: DELETE (disabled for now)

/// Get the filter type
#[no_mangle]
pub unsafe extern "C" fn appendable_data_filter_type(ad_h: AppendableDataHandle,
                                                     o_type: *mut FilterType)
                                                     -> i32 {
    helper::catch_unwind_i32(|| {
        let mut object_cache = unwrap!(object_cache());
        let ad = ffi_try!(object_cache.get_ad(ad_h));
        let filter = ad.filter_mut();
        let filter_type = match *filter {
            Filter::BlackList(_) => FilterType::BlackList,
            Filter::WhiteList(_) => FilterType::WhiteList,
        };

        ptr::write(o_type, filter_type);
        0
    })
}

/// Switch the filter of the appendable data.
#[no_mangle]
pub extern "C" fn appendable_data_toggle_filter(ad_h: AppendableDataHandle) -> i32 {
    helper::catch_unwind_i32(|| {
        let mut object_cache = unwrap!(object_cache());
        let ad = ffi_try!(object_cache.get_ad(ad_h));

        let filter = ad.filter_mut();
        match *filter {
            Filter::BlackList(_) => *filter = Filter::white_list(iter::empty()),
            Filter::WhiteList(_) => *filter = Filter::black_list(iter::empty()),
        }

        0
    })
}

/// Insert a new entry to the (whitelist or blacklist) filter. If the key was
/// already present in the filter, this is a no-op.
#[no_mangle]
pub extern "C" fn appendable_data_insert_to_filter(ad_h: AppendableDataHandle,
                                                   sign_key_h: SignKeyHandle)
                                                   -> i32 {
    helper::catch_unwind_i32(|| {
        let mut object_cache = unwrap!(object_cache());
        let sign_key = *ffi_try!(object_cache.get_sign_key(sign_key_h));
        let ad = ffi_try!(object_cache.get_ad(ad_h));

        let _ = match *ad.filter_mut() {
            Filter::WhiteList(ref mut list) |
            Filter::BlackList(ref mut list) => list.insert(sign_key),
        };

        0
    })
}

/// Remove the given key from the (whitelist or blacklist) filter. If the key
/// isn't present in the filter, this is a no-op.
#[no_mangle]
pub extern "C" fn appendable_data_remove_from_filter(ad_h: AppendableDataHandle,
                                                     sign_key_h: SignKeyHandle)
                                                     -> i32 {
    helper::catch_unwind_i32(|| {
        let mut object_cache = unwrap!(object_cache());
        let sign_key = *ffi_try!(object_cache.get_sign_key(sign_key_h));
        let ad = ffi_try!(object_cache.get_ad(ad_h));

        let _ = match *ad.filter_mut() {
            Filter::WhiteList(ref mut list) |
            Filter::BlackList(ref mut list) => list.remove(&sign_key),
        };

        0
    })
}

/// Get the number of filtered keys.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_num_of_filter_keys(ad_h: AppendableDataHandle,
                                                            o_num: *mut usize)
                                                            -> i32 {
    helper::catch_unwind_i32(|| {
        let mut object_cache = unwrap!(object_cache());
        let ad = ffi_try!(object_cache.get_ad(ad_h));

        let num = match *ad.filter_mut() {
            Filter::WhiteList(ref mut list) |
            Filter::BlackList(ref mut list) => list.len(),
        };

        *o_num = num;
        0
    })
}

/// Get the nth filter key.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_nth_filter_key(ad_h: AppendableDataHandle,
                                                        n: usize,
                                                        o_handle: *mut SignKeyHandle)
                                                        -> i32 {
    helper::catch_unwind_i32(|| {
        let filter_key = {
            let mut object_cache = unwrap!(object_cache());
            let ad = ffi_try!(object_cache.get_ad(ad_h));

            match *ad.filter_mut() {
                Filter::WhiteList(ref mut list) |
                Filter::BlackList(ref mut list) => *ffi_try!(nth(list, n)),
            }
        };

        *o_handle = unwrap!(object_cache()).insert_sign_key(filter_key);
        0
    })
}

/// Get the owner's encrypt key
#[no_mangle]
pub unsafe extern "C" fn appendable_data_encrypt_key(ad_h: AppendableDataHandle,
                                                     o_handle: *mut EncryptKeyHandle)
                                                     -> i32 {
    helper::catch_unwind_i32(|| {
        let mut object_cache = unwrap!(object_cache());
        let pk = match *ffi_try!(object_cache.get_ad(ad_h)) {
            AppendableData::Priv(ref elt) => elt.encrypt_key,
            _ => ffi_try!(Err(FfiError::UnsupportedOperation)),
        };
        let handle = object_cache.insert_encrypt_key(pk);
        ptr::write(o_handle, handle);
        0
    })
}

/// Get number of appended data items.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_num_of_data(ad_h: AppendableDataHandle,
                                                     o_num: *mut usize)
                                                     -> i32 {
    helper::catch_unwind_i32(|| {
                                 ffi_try!(appendable_data_num_of_data_impl(ad_h, false, o_num));
                                 0
                             })
}

/// Get number of appended deleted data items.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_num_of_deleted_data(ad_h: AppendableDataHandle,
                                                             o_num: *mut usize)
                                                             -> i32 {
    helper::catch_unwind_i32(|| {
                                 ffi_try!(appendable_data_num_of_data_impl(ad_h, true, o_num));
                                 0
                             })
}

unsafe fn appendable_data_num_of_data_impl(ad_h: AppendableDataHandle,
                                           is_deleted_data: bool,
                                           o_num: *mut usize)
                                           -> Result<(), FfiError> {
    let mut object_cache = unwrap!(object_cache());
    let ad = object_cache.get_ad(ad_h)?;
    let num = match *ad {
        AppendableData::Pub(ref elt) => {
            if is_deleted_data {
                elt.deleted_data.len()
            } else {
                elt.data.len()
            }
        }
        AppendableData::Priv(ref elt) => {
            if is_deleted_data {
                elt.deleted_data.len()
            } else {
                elt.data.len()
            }
        }
    };

    ptr::write(o_num, num);
    Ok(())
}

/// Get nth appended `DataIdentifier` from data.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_nth_data_id(app: *const App,
                                                     ad_h: AppendableDataHandle,
                                                     n: usize,
                                                     o_handle: *mut DataIdHandle)
                                                     -> i32 {
    helper::catch_unwind_i32(|| {
                                 ffi_try!(appendable_data_nth_data_id_impl(app,
                                                                           ad_h,
                                                                           n,
                                                                           false,
                                                                           o_handle));
                                 0
                             })
}

/// Get nth appended `DataIdentifier` from deleted data.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_nth_deleted_data_id(app: *const App,
                                                             ad_h: AppendableDataHandle,
                                                             n: usize,
                                                             o_handle: *mut DataIdHandle)
                                                             -> i32 {
    helper::catch_unwind_i32(|| {
                                 ffi_try!(appendable_data_nth_data_id_impl(app,
                                                                           ad_h,
                                                                           n,
                                                                           true,
                                                                           o_handle));
                                 0
                             })
}

unsafe fn appendable_data_nth_data_id_impl(app: *const App,
                                           ad_h: AppendableDataHandle,
                                           n: usize,
                                           is_deleted_data: bool,
                                           o_handle: *mut DataIdHandle)
                                           -> Result<(), FfiError> {
    let app = &*app;

    let mut object_cache = unwrap!(object_cache());

    let data_id = match *object_cache.get_ad(ad_h)? {
        AppendableData::Priv(ref elt) => {
            let priv_data = if is_deleted_data {
                nth(&elt.deleted_data, n)?
            } else {
                nth(&elt.data, n)?
            };
            let &(ref pk, ref sk) = app.asym_keys()?;
            priv_data
                .open(pk, sk)
                .map_err(CoreError::from)?
                .pointer

        }
        AppendableData::Pub(ref elt) => {
            if is_deleted_data {
                nth(&elt.deleted_data, n)?.pointer
            } else {
                nth(&elt.data, n)?.pointer
            }
        }
    };

    let handle = object_cache.insert_data_id(data_id);

    ptr::write(o_handle, handle);
    Ok(())
}

/// Get nth sign key from data
#[no_mangle]
pub unsafe extern "C" fn appendable_data_nth_data_sign_key(app: *const App,
                                                           ad_h: AppendableDataHandle,
                                                           n: usize,
                                                           o_handle: *mut SignKeyHandle)
                                                           -> i32 {
    helper::catch_unwind_i32(|| {
                                 ffi_try!(appendable_data_nth_sign_key_impl(app,
                                                                            ad_h,
                                                                            n,
                                                                            false,
                                                                            o_handle));
                                 0
                             })
}

/// Get nth sign key from deleted data
#[no_mangle]
pub unsafe extern "C" fn appendable_data_nth_deleted_data_sign_key(app: *const App,
                                                                   ad_h: AppendableDataHandle,
                                                                   n: usize,
                                                                   o_handle: *mut SignKeyHandle)
                                                                   -> i32 {
    helper::catch_unwind_i32(|| {
                                 ffi_try!(appendable_data_nth_sign_key_impl(app,
                                                                            ad_h,
                                                                            n,
                                                                            true,
                                                                            o_handle));
                                 0
                             })
}

unsafe fn appendable_data_nth_sign_key_impl(app: *const App,
                                            ad_h: AppendableDataHandle,
                                            n: usize,
                                            is_deleted_data: bool,
                                            o_handle: *mut SignKeyHandle)
                                            -> Result<(), FfiError> {
    let app = &*app;

    let mut object_cache = unwrap!(object_cache());

    let sign_key = match *object_cache.get_ad(ad_h)? {
        AppendableData::Priv(ref elt) => {
            let priv_data = if is_deleted_data {
                nth(&elt.deleted_data, n)?
            } else {
                nth(&elt.data, n)?
            };
            let &(ref pk, ref sk) = app.asym_keys()?;
            priv_data
                .open(pk, sk)
                .map_err(CoreError::from)?
                .sign_key

        }
        AppendableData::Pub(ref elt) => {
            if is_deleted_data {
                nth(&elt.deleted_data, n)?.sign_key
            } else {
                nth(&elt.data, n)?.sign_key
            }
        }
    };

    let handle = object_cache.insert_sign_key(sign_key);

    ptr::write(o_handle, handle);
    Ok(())
}

/// Remove the n-th data item from the appendable data. The data has to be POST'd afterwards for the
/// change to be registered by the network. The data is moved to deleted data.
#[no_mangle]
pub extern "C" fn appendable_data_remove_nth_data(ad_h: AppendableDataHandle, n: usize) -> i32 {
    helper::catch_unwind_i32(|| {
        let mut object_cache = unwrap!(object_cache());
        match *ffi_try!(object_cache.get_ad(ad_h)) {
            AppendableData::Pub(ref mut elt) => {
                // TODO Isn't there Entry::Occupied::remove() like HashMap etc to prevent clone ?
                //      If there is refactor in other places too here.
                let item = ffi_try!(nth(&elt.data, n)).clone();
                if elt.data.remove(&item) {
                    let _ = elt.deleted_data.insert(item);
                }
            }
            AppendableData::Priv(ref mut elt) => {
                let item = ffi_try!(nth(&elt.data, n)).clone();
                if elt.data.remove(&item) {
                    let _ = elt.deleted_data.insert(item);
                }
            }
        }

        0
    })
}

/// Restore the n-th delete data item to data field back. The data has to be POST'd afterwards for
/// the change to be registered by the network.
#[no_mangle]
pub extern "C" fn appendable_data_restore_nth_deleted_data(ad_h: AppendableDataHandle,
                                                           n: usize)
                                                           -> i32 {
    helper::catch_unwind_i32(|| {
        let mut object_cache = unwrap!(object_cache());
        match *ffi_try!(object_cache.get_ad(ad_h)) {
            AppendableData::Pub(ref mut elt) => {
                // TODO Isn't there Entry::Occupied::remove() like HashMap etc to prevent clone ?
                //      If there is refactor in other places too here.
                let item = ffi_try!(nth(&elt.deleted_data, n)).clone();
                if elt.deleted_data.remove(&item) {
                    let _ = elt.data.insert(item);
                }
            }
            AppendableData::Priv(ref mut elt) => {
                let item = ffi_try!(nth(&elt.deleted_data, n)).clone();
                if elt.deleted_data.remove(&item) {
                    let _ = elt.data.insert(item);
                }
            }
        }

        0
    })
}

/// Clear all data - moves it to deleted data.
#[no_mangle]
pub extern "C" fn appendable_data_clear_data(ad_h: AppendableDataHandle) -> i32 {
    helper::catch_unwind_i32(|| {
        let mut object_cache = unwrap!(object_cache());
        match *ffi_try!(object_cache.get_ad(ad_h)) {
            AppendableData::Pub(ref mut elt) => {
                let tmp = mem::replace(&mut elt.data, Default::default());
                elt.deleted_data.extend(tmp);
            }
            AppendableData::Priv(ref mut elt) => {
                let tmp = mem::replace(&mut elt.data, Default::default());
                elt.deleted_data.extend(tmp);
            }
        };

        0
    })
}

/// Remove the n-th data item from the deleted data. The data has to be POST'd afterwards for the
/// change to be registered by the network. The data is removed permanently.
#[no_mangle]
pub extern "C" fn appendable_data_remove_nth_deleted_data(ad_h: AppendableDataHandle,
                                                          n: usize)
                                                          -> i32 {
    helper::catch_unwind_i32(|| {
        let mut object_cache = unwrap!(object_cache());
        match *ffi_try!(object_cache.get_ad(ad_h)) {
            AppendableData::Pub(ref mut elt) => {
                let item = ffi_try!(nth(&elt.deleted_data, n)).clone();
                let _ = elt.deleted_data.remove(&item);
            }
            AppendableData::Priv(ref mut elt) => {
                let item = ffi_try!(nth(&elt.deleted_data, n)).clone();
                let _ = elt.deleted_data.remove(&item);
            }
        }

        0
    })
}

/// Clear all deleted data - data will be actually be removed.
#[no_mangle]
pub extern "C" fn appendable_data_clear_deleted_data(ad_h: AppendableDataHandle) -> i32 {
    helper::catch_unwind_i32(|| {
        let mut object_cache = unwrap!(object_cache());
        match *ffi_try!(object_cache.get_ad(ad_h)) {
            AppendableData::Pub(ref mut elt) => elt.deleted_data.clear(),
            AppendableData::Priv(ref mut elt) => elt.deleted_data.clear(),
        };

        0
    })
}

/// Append data.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_append(app: *const App,
                                                ad_h: AppendableDataHandle,
                                                data_id_h: DataIdHandle)
                                                -> i32 {
    helper::catch_unwind_i32(|| {
        let client = (*app).get_client();

        let append_wrapper = {
            let mut object_cache = unwrap!(object_cache());
            let data_id = *ffi_try!(object_cache.get_data_id(data_id_h));

            let client = unwrap!(client.lock());
            let sign_pk = ffi_try!(client.get_public_signing_key());
            let sign_sk = ffi_try!(client.get_secret_signing_key());

            let appended_data = ffi_try!(AppendedData::new(data_id, *sign_pk, sign_sk)
                                             .map_err(CoreError::from));

            match *ffi_try!(object_cache.get_ad(ad_h)) {
                AppendableData::Priv(ref elt) => {
                    let priv_appended_data = ffi_try!(PrivAppendedData::new(&appended_data,
                                                                            &elt.encrypt_key)
                                                              .map_err(CoreError::from));
                    ffi_try!(AppendWrapper::new_priv(elt.name,
                                                     priv_appended_data,
                                                     (sign_pk, sign_sk),
                                                     elt.version)
                                     .map_err(CoreError::from))
                }
                AppendableData::Pub(ref elt) => {
                    AppendWrapper::new_pub(elt.name, appended_data, elt.version)
                }
            }
        };

        let resp_getter = ffi_try!(unwrap!(client.lock()).append(append_wrapper, None));
        ffi_try!(resp_getter.get());

        0
    })
}

/// Get the current version of `AppendableData` by its handle
#[no_mangle]
pub unsafe extern "C" fn appendable_data_version(handle: AppendableDataHandle,
                                                 o_version: *mut u64)
                                                 -> i32 {
    helper::catch_unwind_i32(|| {
        *o_version = match *ffi_try!(unwrap!(object_cache()).get_ad(handle)) {
            AppendableData::Pub(ref mut elt) => elt.get_version(),
            AppendableData::Priv(ref mut elt) => elt.get_version(),
        };

        0
    })
}

/// See if `AppendableData` size is valid.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_validate_size(handle: AppendableDataHandle,
                                                       o_valid: *mut bool)
                                                       -> i32 {
    helper::catch_unwind_i32(|| {
        *o_valid = match *ffi_try!(unwrap!(object_cache()).get_ad(handle)) {
            AppendableData::Pub(ref elt) => elt.validate_size(),
            AppendableData::Priv(ref elt) => elt.validate_size(),
        };

        0
    })
}

/// Returns true if the app is one of the owners of the provided `AppendableData`.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_is_owned(app: *const App,
                                                  handle: AppendableDataHandle,
                                                  o_is_owned: *mut bool)
                                                  -> i32 {
    helper::catch_unwind_i32(|| {
        let client = (*app).get_client();
        let my_key = *ffi_try!(unwrap!(client.lock()).get_public_signing_key());

        *o_is_owned = match *ffi_try!(unwrap!(object_cache()).get_ad(handle)) {
            AppendableData::Pub(ref mut elt) => elt.get_owners().contains(&my_key),
            AppendableData::Priv(ref mut elt) => elt.get_owners().contains(&my_key),
        };

        0
    })
}

/// Free `AppendableData` handle
#[no_mangle]
pub extern "C" fn appendable_data_free(handle: AppendableDataHandle) -> i32 {
    helper::catch_unwind_i32(|| {
                                 let _ = ffi_try!(unwrap!(object_cache()).remove_ad(handle));
                                 0
                             })
}

// Convenience function to access n-th item from the given set, returning FfiError::InvalidIndex
// if not found.
fn nth<T>(items: &BTreeSet<T>, n: usize) -> Result<&T, FfiError> {
    items.iter().nth(n).ok_or(FfiError::InvalidIndex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffi::app::App;
    use ffi::errors::FfiError;
    use ffi::low_level_api::{AppendableDataHandle, DataIdHandle};
    use ffi::low_level_api::misc::*;
    use ffi::low_level_api::object_cache::object_cache;
    use ffi::test_utils;
    use rand;
    use routing::DataIdentifier;
    use rust_sodium::crypto::sign;
    use std::collections::HashSet;

    macro_rules! assert_num_of_data {
        ($ad_h:ident, $expected:expr) => {
            let mut num: usize = 0;
            assert_eq!(appendable_data_num_of_data($ad_h, &mut num), 0);
            assert_eq!(num, $expected);
        }
    }

    macro_rules! assert_num_of_deleted_data {
        ($ad_h:ident, $expected:expr) => {
            let mut num: usize = 0;
            assert_eq!(appendable_data_num_of_deleted_data($ad_h, &mut num), 0);
            assert_eq!(num, $expected);
        }
    }

    #[test]
    fn put_append_and_get() {
        let app = test_utils::create_app(false);

        let ad_name = rand::random();
        let mut ad_h: AppendableDataHandle = 0;
        let mut ad_id_h: DataIdHandle = 0;

        // Data to append
        let (_, immut_id_0_h) = generate_random_immutable_data_id();
        let (_, immut_id_1_h) = generate_random_immutable_data_id();

        let mut got_immut_id_0_h: DataIdHandle = 0;
        let mut got_immut_id_1_h: DataIdHandle = 0;

        unsafe {
            // Create
            assert_eq!(appendable_data_new_pub(&app, &ad_name, &mut ad_h), 0);

            assert_eq!(appendable_data_extract_data_id(ad_h, &mut ad_id_h), 0);

            // PUT to the network
            assert_eq!(appendable_data_put(&app, ad_h), 0);

            // APPEND
            assert_eq!(appendable_data_append(&app, ad_h, immut_id_0_h), 0);
            assert_eq!(appendable_data_append(&app, ad_h, immut_id_1_h), 0);

            // GET back
            reload_ad(&app, ad_id_h, &mut ad_h);
            assert_num_of_data!(ad_h, 2);

            assert_eq!(appendable_data_nth_data_id(&app, ad_h, 0, &mut got_immut_id_0_h),
                       0);
            assert_eq!(appendable_data_nth_data_id(&app, ad_h, 1, &mut got_immut_id_1_h),
                       0);

            let mut is_owner = false;

            // Check owners
            assert_eq!(appendable_data_is_owned(&app, ad_h, &mut is_owner), 0);
            assert_eq!(is_owner, true);

            let app_fake = test_utils::create_app(false);
            assert_eq!(appendable_data_is_owned(&app_fake, ad_h, &mut is_owner), 0);
            assert_eq!(is_owner, false);

            assert_eq!(appendable_data_free(ad_h), 0);
        }

        // Verify the data items we got back are the same we put in.
        {
            let mut object_cache = unwrap!(object_cache());

            let mut orig = HashSet::with_capacity(2);
            let _ = orig.insert(*unwrap!(object_cache.get_data_id(immut_id_0_h)));
            let _ = orig.insert(*unwrap!(object_cache.get_data_id(immut_id_1_h)));

            let mut got = HashSet::with_capacity(2);
            let _ = got.insert(*unwrap!(object_cache.get_data_id(got_immut_id_0_h)));
            let _ = got.insert(*unwrap!(object_cache.get_data_id(got_immut_id_1_h)));

            assert_eq!(orig, got);
        }
    }

    #[test]
    fn filter() {
        let app0 = test_utils::create_app(false);
        let app1 = test_utils::create_app(false);
        let app2 = test_utils::create_app(false);

        let (sign_key1_h, _sign_key2_h) = {
            let mut object_cache = unwrap!(object_cache());
            (object_cache.insert_sign_key(get_sign_pk(&app1)),
             object_cache.insert_sign_key(get_sign_pk(&app2)))
        };

        let ad_name = rand::random();
        let mut ad_h: AppendableDataHandle = 0;
        let mut ad_id_h: DataIdHandle = 0;
        let mut filter_type = FilterType::BlackList;

        let (_, immut_id_1_h) = generate_random_immutable_data_id();
        let (_, immut_id_2_h) = generate_random_immutable_data_id();

        unsafe {
            assert_eq!(appendable_data_new_pub(&app0, &ad_name, &mut ad_h), 0);
            assert_eq!(appendable_data_extract_data_id(ad_h, &mut ad_id_h), 0);
            assert_eq!(appendable_data_put(&app0, ad_h), 0);

            // Anyone can append by default
            assert_eq!(appendable_data_append(&app1, ad_h, immut_id_1_h), 0);
            assert_eq!(appendable_data_append(&app2, ad_h, immut_id_2_h), 0);
        }

        // Set blacklist
        let (_, immut_id_1_h) = generate_random_immutable_data_id();
        let (_, immut_id_2_h) = generate_random_immutable_data_id();


        unsafe {
            assert_eq!(appendable_data_filter_type(ad_h, &mut filter_type), 0);
            assert_eq!(filter_type, FilterType::BlackList);

            assert_eq!(appendable_data_insert_to_filter(ad_h, sign_key1_h), 0);
            assert_eq!(appendable_data_post(&app0, ad_h, false), 0);

            assert!(appendable_data_append(&app1, ad_h, immut_id_1_h) != 0);
            assert_eq!(appendable_data_append(&app2, ad_h, immut_id_2_h), 0);

            assert_eq!(appendable_data_remove_from_filter(ad_h, sign_key1_h), 0);
            assert_eq!(appendable_data_post(&app0, ad_h, false), 0);
            assert_eq!(appendable_data_append(&app1, ad_h, immut_id_1_h), 0);
        }

        // Set whitelist
        let (_, immut_id_1_h) = generate_random_immutable_data_id();
        let (_, immut_id_2_h) = generate_random_immutable_data_id();

        unsafe {
            assert_eq!(appendable_data_toggle_filter(ad_h), 0);
            assert_eq!(appendable_data_filter_type(ad_h, &mut filter_type), 0);

            assert_eq!(filter_type, FilterType::WhiteList);
            assert_eq!(appendable_data_insert_to_filter(ad_h, sign_key1_h), 0);
            assert_eq!(appendable_data_post(&app0, ad_h, false), 0);

            assert_eq!(appendable_data_append(&app1, ad_h, immut_id_1_h), 0);
            assert!(appendable_data_append(&app2, ad_h, immut_id_2_h) != 0);

            assert_eq!(appendable_data_remove_from_filter(ad_h, sign_key1_h), 0);
            assert_eq!(appendable_data_post(&app0, ad_h, false), 0);
            assert!(appendable_data_append(&app1, ad_h, immut_id_1_h) != 0);

            // Toggle filter and ensure it's blacklist again
            assert_eq!(appendable_data_toggle_filter(ad_h), 0);
            assert_eq!(appendable_data_filter_type(ad_h, &mut filter_type), 0);
            assert_eq!(filter_type, FilterType::BlackList);
        }
    }

    #[test]
    fn priv_appendable_data() {
        let app0 = test_utils::create_app(false);
        let app1 = test_utils::create_app(false);
        let app2 = test_utils::create_app(false);

        let ad_name = rand::random();
        let mut ad_priv_h: AppendableDataHandle = 0;
        let mut ad_id_h: DataIdHandle = 0;

        // Data to append
        let (_, immut_id_0_h) = generate_random_immutable_data_id();
        let (_, immut_id_1_h) = generate_random_immutable_data_id();

        // Generate keys for extra test apps
        let (sign_key1_h, sign_key2_h) = {
            let mut object_cache = unwrap!(object_cache());
            (object_cache.insert_sign_key(get_sign_pk(&app1)),
             object_cache.insert_sign_key(get_sign_pk(&app2)))
        };

        let mut got_immut_id_0_h: DataIdHandle = 0;
        let mut got_immut_id_1_h: DataIdHandle = 0;

        unsafe {
            // Create
            assert_eq!(appendable_data_new_priv(&app0, &ad_name, &mut ad_priv_h), 0);
            assert_eq!(appendable_data_extract_data_id(ad_priv_h, &mut ad_id_h), 0);

            // Test PUT requests for private data
            assert_eq!(appendable_data_put(&app0, ad_priv_h), 0);
            assert_eq!(appendable_data_append(&app0, ad_priv_h, immut_id_0_h), 0);
            assert_eq!(appendable_data_append(&app0, ad_priv_h, immut_id_1_h), 0);

            reload_ad(&app0, ad_id_h, &mut ad_priv_h);
            assert_num_of_data!(ad_priv_h, 2);

            assert_eq!(appendable_data_nth_data_id(&app0, ad_priv_h, 0, &mut got_immut_id_0_h),
                       0);
            assert_eq!(appendable_data_nth_data_id(&app0, ad_priv_h, 1, &mut got_immut_id_1_h),
                       0);

            // Check owners of appendable data
            let mut is_owner = false;

            assert_eq!(appendable_data_is_owned(&app0, ad_priv_h, &mut is_owner), 0);
            assert_eq!(is_owner, true);

            assert_eq!(appendable_data_is_owned(&app1, ad_priv_h, &mut is_owner), 0);
            assert_eq!(is_owner, false);

            // Delete and restore private appendable data
            assert_eq!(appendable_data_remove_nth_data(ad_priv_h, 0), 0);
            assert_eq!(appendable_data_post(&app0, ad_priv_h, true), 0);

            reload_ad(&app0, ad_id_h, &mut ad_priv_h);
            assert_num_of_data!(ad_priv_h, 1);
            assert_num_of_deleted_data!(ad_priv_h, 1);

            let mut deleted_data_h = 0;
            assert_eq!(appendable_data_nth_deleted_data_id(&app0,
                                                           ad_priv_h,
                                                           0,
                                                           &mut deleted_data_h),
                       0);

            assert_eq!(appendable_data_restore_nth_deleted_data(ad_priv_h, 0), 0);
            assert_eq!(appendable_data_post(&app0, ad_priv_h, true), 0);

            reload_ad(&app0, ad_id_h, &mut ad_priv_h);
            assert_num_of_data!(ad_priv_h, 2);
            assert_num_of_deleted_data!(ad_priv_h, 0);

            // Other apps can append new data
            assert_eq!(appendable_data_append(&app1, ad_priv_h, immut_id_0_h), 0);
            assert_eq!(appendable_data_append(&app2, ad_priv_h, immut_id_1_h), 0);

            // Check blacklist filter for private appendable data
            let mut filter_type = FilterType::BlackList;

            assert_eq!(appendable_data_filter_type(ad_priv_h, &mut filter_type), 0);
            assert_eq!(filter_type, FilterType::BlackList);

            assert_eq!(appendable_data_insert_to_filter(ad_priv_h, sign_key1_h), 0);
            assert_eq!(appendable_data_insert_to_filter(ad_priv_h, sign_key2_h), 0);
            assert_eq!(appendable_data_post(&app0, ad_priv_h, false), 0);

            assert!(appendable_data_append(&app1, ad_priv_h, immut_id_0_h) != 0);
            assert!(appendable_data_append(&app2, ad_priv_h, immut_id_1_h) != 0);

            // Check whitelist filter for private data
            assert_eq!(appendable_data_toggle_filter(ad_priv_h), 0);
            assert_eq!(appendable_data_filter_type(ad_priv_h, &mut filter_type), 0);

            assert_eq!(filter_type, FilterType::WhiteList);
            assert_eq!(appendable_data_insert_to_filter(ad_priv_h, sign_key2_h), 0);
            assert_eq!(appendable_data_post(&app0, ad_priv_h, false), 0);

            assert_eq!(appendable_data_append(&app2, ad_priv_h, immut_id_1_h), 0);
            assert!(appendable_data_append(&app1, ad_priv_h, immut_id_0_h) != 0);

            assert_eq!(appendable_data_free(ad_priv_h), 0);
        }

        // Verify the data items we got back are the same we put in.
        {
            let mut object_cache = unwrap!(object_cache());

            let mut orig = HashSet::with_capacity(2);
            let _ = orig.insert(*unwrap!(object_cache.get_data_id(immut_id_0_h)));
            let _ = orig.insert(*unwrap!(object_cache.get_data_id(immut_id_1_h)));

            let mut got = HashSet::with_capacity(2);
            let _ = got.insert(*unwrap!(object_cache.get_data_id(got_immut_id_0_h)));
            let _ = got.insert(*unwrap!(object_cache.get_data_id(got_immut_id_1_h)));

            assert_eq!(orig, got);
        }

        assert_eq!(misc_sign_key_free(sign_key1_h), 0);
        assert_eq!(misc_sign_key_free(sign_key2_h), 0);
    }

    #[test]
    fn delete_data() {
        let app = test_utils::create_app(false);

        let ad_name = rand::random();
        let mut ad_h: AppendableDataHandle = 0;
        let mut ad_id_h: DataIdHandle = 0;

        let (_, immut_id_0_h) = generate_random_immutable_data_id();
        let (_, immut_id_1_h) = generate_random_immutable_data_id();

        unsafe {
            // Create AD and PUT it to the network.
            assert_eq!(appendable_data_new_pub(&app, &ad_name, &mut ad_h), 0);
            assert_eq!(appendable_data_extract_data_id(ad_h, &mut ad_id_h), 0);
            assert_eq!(appendable_data_put(&app, ad_h), 0);

            // Append stuff to it.
            assert_eq!(appendable_data_append(&app, ad_h, immut_id_0_h), 0);
            assert_eq!(appendable_data_append(&app, ad_h, immut_id_1_h), 0);

            // GET it back.
            reload_ad(&app, ad_id_h, &mut ad_h);
            assert_num_of_data!(ad_h, 2);

            // Try to remove one of available versions first
            assert_eq!(appendable_data_remove_nth_data(ad_h, 0), 0);
            assert_eq!(appendable_data_post(&app, ad_h, true), 0);

            reload_ad(&app, ad_id_h, &mut ad_h);
            assert_num_of_data!(ad_h, 1);
            assert_num_of_deleted_data!(ad_h, 1);

            // Try restoring deleted data
            assert_eq!(appendable_data_restore_nth_deleted_data(ad_h, 0), 0);
            assert_eq!(appendable_data_post(&app, ad_h, true), 0);

            reload_ad(&app, ad_id_h, &mut ad_h);
            assert_num_of_data!(ad_h, 2);

            // Permanently delete data
            assert_eq!(appendable_data_remove_nth_data(ad_h, 0), 0);
            assert_eq!(appendable_data_remove_nth_deleted_data(ad_h, 0), 0);
            assert_eq!(appendable_data_post(&app, ad_h, true), 0);

            reload_ad(&app, ad_id_h, &mut ad_h);
            assert_num_of_deleted_data!(ad_h, 0);

            // clear the data and POST it.
            assert_eq!(appendable_data_clear_data(ad_h), 0);
            assert_eq!(appendable_data_post(&app, ad_h, false), 0);

            // GET it back.
            reload_ad(&app, ad_id_h, &mut ad_h);
            assert_num_of_data!(ad_h, 0);
            assert_num_of_deleted_data!(ad_h, 2);

            // Permanently clear deleted data
            assert_eq!(appendable_data_clear_deleted_data(ad_h), 0);
            assert_eq!(appendable_data_post(&app, ad_h, false), 0);

            reload_ad(&app, ad_id_h, &mut ad_h);
            assert_num_of_deleted_data!(ad_h, 0);

            assert_eq!(appendable_data_free(ad_h), 0);
        }
    }

    #[test]
    fn data_encrypt_key() {
        let app = test_utils::create_app(false);

        let mut encrypt_key_h = 0;

        unsafe {
            // Initialise public appendable data
            let mut ad_h = 0;
            assert_eq!(appendable_data_new_pub(&app, &rand::random(), &mut ad_h), 0);

            // Public appendable data doens't have a private owner key
            assert_eq!(appendable_data_encrypt_key(ad_h, &mut encrypt_key_h),
                       FfiError::UnsupportedOperation.into());

            assert_eq!(appendable_data_free(ad_h), 0);

            // Initialise private appendable data
            let mut ad_h = 0;
            assert_eq!(appendable_data_new_priv(&app, &rand::random(), &mut ad_h),
                       0);

            assert_eq!(appendable_data_encrypt_key(ad_h, &mut encrypt_key_h), 0);

            assert_eq!(misc_encrypt_key_free(encrypt_key_h), 0);
        }
    }

    #[test]
    fn data_sign_key() {
        let app0 = test_utils::create_app(false);
        let app1 = test_utils::create_app(false);

        let sign_key1 = get_sign_pk(&app1);
        let sign_key1_h = unwrap!(object_cache()).insert_sign_key(sign_key1);

        let mut ad_h = 0;
        let mut ad_id_h: DataIdHandle = 0;

        // Data to append
        let (_, immut_id_0_h) = generate_random_immutable_data_id();
        let (_, immut_id_1_h) = generate_random_immutable_data_id();

        unsafe {
            // Create test data
            assert_eq!(appendable_data_new_pub(&app0, &rand::random(), &mut ad_h),
                       0);
            assert_eq!(appendable_data_extract_data_id(ad_h, &mut ad_id_h), 0);

            assert_eq!(appendable_data_put(&app0, ad_h), 0);
            assert_eq!(appendable_data_append(&app1, ad_h, immut_id_0_h), 0);

            reload_ad(&app0, ad_id_h, &mut ad_h);

            // Get a data key of app1
            let mut sign_key_h = 0;
            assert_eq!(appendable_data_nth_data_sign_key(&app0, ad_h, 0, &mut sign_key_h),
                       0);
            assert_eq!(*unwrap!(unwrap!(object_cache()).get_sign_key(sign_key_h)),
                       sign_key1);

            // Now try to get a data key from deleted data
            assert_eq!(appendable_data_remove_nth_data(ad_h, 0), 0);
            assert_eq!(appendable_data_post(&app0, ad_h, true), 0);
            reload_ad(&app0, ad_id_h, &mut ad_h);

            let mut deleted_sk_h = 0;
            assert_eq!(appendable_data_nth_deleted_data_sign_key(&app0,
                                                                 ad_h,
                                                                 0,
                                                                 &mut deleted_sk_h),
                       0);
            assert_eq!(*unwrap!(unwrap!(object_cache()).get_sign_key(deleted_sk_h)),
                       sign_key1);

            // Filter out the key that we've got for an app1
            assert_eq!(appendable_data_insert_to_filter(ad_h, deleted_sk_h), 0);
            assert_eq!(appendable_data_post(&app0, ad_h, false), 0);

            assert!(appendable_data_append(&app1, ad_h, immut_id_1_h) != 0);

            assert_eq!(appendable_data_free(ad_h), 0);
        }

        assert_eq!(misc_sign_key_free(sign_key1_h), 0);
    }

    fn generate_random_immutable_data_id() -> (DataIdentifier, DataIdHandle) {
        let name = rand::random();
        let id = DataIdentifier::Immutable(name);

        let mut obj_cache = unwrap!(object_cache());
        let id_h = obj_cache.insert_data_id(id);

        (id, id_h)
    }

    fn get_sign_pk(app: &App) -> sign::PublicKey {
        let client = app.get_client();
        let client = unwrap!(client.lock());
        *unwrap!(client.get_public_signing_key())
    }

    fn reload_ad(app: &App, ad_id_h: DataIdHandle, ad_h: &mut AppendableDataHandle) {
        assert_eq!(appendable_data_free(*ad_h), 0);
        unsafe {
            assert_eq!(appendable_data_get(app, ad_id_h, ad_h), 0);
        }
    }
}
