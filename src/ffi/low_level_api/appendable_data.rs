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

use core::{Client, CoreError, FutureExt};
use ffi::{AppHandle, AppendableDataHandle, DataIdHandle, EncryptKeyHandle, SignKeyHandle};
use ffi::{FfiError, FfiResult, OpaqueCtx, Session};
use ffi::callback::CallbackArgs;
use ffi::helper::catch_unwind_cb;
use ffi::object_cache::ObjectCache;
use futures::{self, Future};
use routing::{AppendWrapper, AppendedData, Data, Filter, PrivAppendableData, PrivAppendedData,
              PubAppendableData, XOR_NAME_LEN, XorName};
use std::collections::BTreeSet;
use std::iter;
use std::mem;
use std::os::raw::c_void;

type ADHandle = AppendableDataHandle;

/// Wrapper for PrivAppendableData and PubAppendableData.
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

impl CallbackArgs for FilterType {
    fn default() -> Self {
        FilterType::BlackList
    }
}

/// Create new PubAppendableData
#[no_mangle]
pub unsafe extern "C" fn appendable_data_new_pub(session: *const Session,
                                                 name: *const [u8; XOR_NAME_LEN],
                                                 user_data: *mut c_void,
                                                 o_cb: unsafe extern "C" fn(*mut c_void,
                                                                            i32,
                                                                            ADHandle)) {
    catch_unwind_cb(user_data, o_cb, || {
        let name = XorName(*name);
        let user_data = OpaqueCtx(user_data);

        (*session).send(move |client, object_cache| {
            match appendable_data_new_pub_impl(client, object_cache, name) {
                Ok(handle) => o_cb(user_data.0, 0, handle),
                Err(e) => o_cb(user_data.0, ffi_error_code!(e), 0),
            }
            None
        })
    });
}

fn appendable_data_new_pub_impl(client: &Client,
                                obj_cache: &ObjectCache,
                                name: XorName)
                                -> FfiResult<ADHandle> {
    let owner_key = client.public_signing_key()?;
    let sign_key = client.secret_signing_key()?.clone();

    let data = PubAppendableData::new(name,
                                      0,
                                      vec![owner_key],
                                      Default::default(),
                                      Default::default(),
                                      Filter::black_list(iter::empty()),
                                      Some(&sign_key));
    let data = AppendableData::Pub(data.map_err(CoreError::from)?);
    Ok(obj_cache.insert_ad(data))
}

/// Create new PrivAppendableData
#[no_mangle]
pub unsafe extern "C" fn appendable_data_new_priv(session: *const Session,
                                                  app: AppHandle,
                                                  name: *const [u8; XOR_NAME_LEN],
                                                  user_data: *mut c_void,
                                                  o_cb: unsafe extern "C" fn(*mut c_void,
                                                                             i32,
                                                                             ADHandle)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        let name = XorName(*name);

        (*session).send(move |client, obj_cache| {
            match appendable_data_new_priv_impl(client, obj_cache, name, app) {
                Ok(handle) => o_cb(user_data.0, 0, handle),
                Err(e) => o_cb(user_data.0, ffi_error_code!(e), 0),
            }
            None
        })
    });
}

fn appendable_data_new_priv_impl(client: &Client,
                                 obj_cache: &ObjectCache,
                                 name: XorName,
                                 app_handle: AppHandle)
                                 -> FfiResult<ADHandle> {
    let owner_key = client.public_signing_key()?;
    let sign_key = client.secret_signing_key()?;

    let data = {
        let app = obj_cache.get_app(app_handle)?;
        PrivAppendableData::new(name,
                                0,
                                vec![owner_key],
                                Default::default(),
                                Default::default(),
                                Filter::black_list(iter::empty()),
                                app.asym_enc_keys()?.0,
                                Some(&sign_key))
    };
    let data = AppendableData::Priv(data.map_err(CoreError::from)?);

    Ok(obj_cache.insert_ad(data))
}

/// Get existing appendable data from Network.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_get(session: *const Session,
                                             data_id_h: DataIdHandle,
                                             user_data: *mut c_void,
                                             o_cb: unsafe extern "C" fn(*mut c_void,
                                                                        i32,
                                                                        ADHandle)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |client, obj_cache| {
            let c2 = client.clone();
            let obj_cache = obj_cache.clone();

            let data_id = obj_cache.get_data_id(data_id_h).map(|id| id.clone());

            let fut = futures::done(data_id)
                .map_err(FfiError::from)
                .and_then(move |data_id| c2.get(data_id, None).map_err(FfiError::from))
                .and_then(move |response| {
                    let data = match response {
                        Data::PubAppendable(data) => AppendableData::Pub(data),
                        Data::PrivAppendable(data) => AppendableData::Priv(data),
                        _ => {
                            return Err(FfiError::from(CoreError::ReceivedUnexpectedData));
                        }
                    };
                    Ok(obj_cache.insert_ad(data))
                })
                .map(move |handle| o_cb(user_data.0, 0, handle))
                .map_err(move |e| o_cb(user_data.0, ffi_error_code!(e), 0))
                .into_box();

            Some(fut)
        })
    });
}

/// Extract DataIdentifier from AppendableData.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_extract_data_id(session: *const Session,
                                                         ad_h: ADHandle,
                                                         user_data: *mut c_void,
                                                         o_cb: unsafe extern "C" fn(*mut c_void,
                                                                                    i32,
                                                                                    DataIdHandle)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            match appendable_data_extract_data_id_impl(obj_cache, ad_h) {
                Ok(handle) => o_cb(user_data.0, 0, handle),
                Err(e) => o_cb(user_data.0, ffi_error_code!(e), 0),
            }
            None
        })
    });
}

fn appendable_data_extract_data_id_impl(object_cache: &ObjectCache,
                                        ad_h: ADHandle)
                                        -> FfiResult<DataIdHandle> {
    let data_id = match *object_cache.get_ad(ad_h)? {
        AppendableData::Pub(ref elt) => elt.identifier(),
        AppendableData::Priv(ref elt) => elt.identifier(),
    };
    Ok(object_cache.insert_data_id(data_id))
}

/// PUT appendable data.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_put(session: *const Session,
                                             ad_h: ADHandle,
                                             user_data: *mut c_void,
                                             o_cb: unsafe extern "C" fn(*mut c_void, i32)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |client, obj_cache| {
            let data_res = obj_cache.get_ad(ad_h).map(|v| v.clone());
            let c2 = client.clone();

            let fut = futures::done(data_res)
                .and_then(move |data| c2.put(data.into(), None).map_err(FfiError::from))
                .then(move |res| {
                    o_cb(user_data.0, ffi_result_code!(res));
                    Ok(())
                })
                .into_box();

            Some(fut)
        })
    });
}

/// POST appendable data (bumps the version).
#[no_mangle]
pub unsafe extern "C" fn appendable_data_post(session: *const Session,
                                              ad_h: ADHandle,
                                              include_data: bool,
                                              user_data: *mut c_void,
                                              o_cb: unsafe extern "C" fn(*mut c_void, i32)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |client, obj_cache| {
            let c2 = client.clone();
            let new_ad = appendable_data_post_impl(client, obj_cache, ad_h, include_data);

            let fut = futures::done(new_ad)
                .and_then(move |new_ad| {
                    c2.post(new_ad.clone().into(), None).map_err(FfiError::from)
                })
                .then(move |res| {
                    o_cb(user_data.0, ffi_result_code!(res));
                    Ok(())
                })
                .into_box();

            Some(fut)
        })
    });
}

fn appendable_data_post_impl(client: &Client,
                             obj_cache: &ObjectCache,
                             ad_h: ADHandle,
                             include_data: bool)
                             -> FfiResult<AppendableData> {
    match *obj_cache.get_ad(ad_h)? {
        AppendableData::Pub(ref old) => {
            let sk = client.secret_signing_key()?;
            let new_data = PubAppendableData::new(old.name,
                                                  old.version + 1,
                                                  old.current_owner_keys
                                                      .clone(),
                                                  old.previous_owner_keys
                                                      .clone(),
                                                  old.deleted_data.clone(),
                                                  old.filter.clone(),
                                                  Some(&sk))
                .map_err(CoreError::from);
            let mut new_data = new_data?;
            if include_data {
                new_data.data = old.data.clone();
            }
            Ok(AppendableData::Pub(new_data))
        }
        AppendableData::Priv(ref old_data) => {
            let new_data = PrivAppendableData::new(old_data.name,
                                                   old_data.version + 1,
                                                   old_data.current_owner_keys.clone(),
                                                   old_data.previous_owner_keys.clone(),
                                                   old_data.deleted_data.clone(),
                                                   old_data.filter.clone(),
                                                   old_data.encrypt_key.clone(),
                                                   Some(&client.secret_signing_key()?))
                .map_err(CoreError::from);
            let mut new_data = new_data?;

            if include_data {
                new_data.data = old_data.data.clone();
            }
            Ok(AppendableData::Priv(new_data))
        }
    }
}

// TODO: DELETE (disabled for now)

/// Get the filter type
#[no_mangle]
pub unsafe extern "C" fn appendable_data_filter_type(session: *const Session,
                                                     ad_h: ADHandle,
                                                     user_data: *mut c_void,
                                                     o_cb: unsafe extern "C" fn(*mut c_void,
                                                                                i32,
                                                                                FilterType)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            match obj_cache.get_ad(ad_h) {
                Ok(mut ad) => {
                    let filter = ad.filter_mut();
                    let filter_type = match *filter {
                        Filter::BlackList(_) => FilterType::BlackList,
                        Filter::WhiteList(_) => FilterType::WhiteList,
                    };
                    o_cb(user_data.0, 0, filter_type);
                }
                Err(e) => o_cb(user_data.0, ffi_error_code!(e), FilterType::BlackList),
            }
            None
        })
    })
}

/// Switch the filter of the appendable data.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_toggle_filter(session: *const Session,
                                                       ad_h: ADHandle,
                                                       user_data: *mut c_void,
                                                       o_cb: unsafe extern "C" fn(*mut c_void,
                                                                                  i32)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            match obj_cache.get_ad(ad_h) {
                Ok(mut ad) => {
                    let filter = ad.filter_mut();
                    match *filter {
                        Filter::BlackList(_) => *filter = Filter::white_list(iter::empty()),
                        Filter::WhiteList(_) => *filter = Filter::black_list(iter::empty()),
                    }
                    o_cb(user_data.0, 0);
                }
                Err(e) => o_cb(user_data.0, ffi_error_code!(e)),
            }
            None
        })
    })
}

/// Insert a new entry to the (whitelist or blacklist) filter. If the key was
/// already present in the filter, this is a no-op.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_insert_to_filter(session: *const Session,
                                                          ad_h: ADHandle,
                                                          sign_key_h: SignKeyHandle,
                                                          user_data: *mut c_void,
                                                          o_cb: unsafe extern "C" fn(*mut c_void,
                                                                                     i32)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            let res = appendable_data_insert_to_filter_impl(obj_cache, ad_h, sign_key_h);
            o_cb(user_data.0, ffi_result_code!(res));
            None
        })
    });
}

fn appendable_data_insert_to_filter_impl(obj_cache: &ObjectCache,
                                         ad_h: ADHandle,
                                         sign_key_h: SignKeyHandle)
                                         -> FfiResult<()> {
    let sign_key = *obj_cache.get_sign_key(sign_key_h)?;
    let mut ad = obj_cache.get_ad(ad_h)?;
    let _ = match *ad.filter_mut() {
        Filter::WhiteList(ref mut list) |
        Filter::BlackList(ref mut list) => list.insert(sign_key),
    };
    Ok(())
}

/// Remove the given key from the (whitelist or blacklist) filter. If the key
/// isn't present in the filter, this is a no-op.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_remove_from_filter(session: *const Session,
                                                            ad_h: ADHandle,
                                                            sign_key_h: SignKeyHandle,
                                                            user_data: *mut c_void,
                                                            o_cb: unsafe extern "C"
                                                            fn(*mut c_void,
                                                               i32)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            let res = appendable_data_remove_from_filter_impl(obj_cache, ad_h, sign_key_h);
            o_cb(user_data.0, ffi_result_code!(res));
            None
        })
    });
}

fn appendable_data_remove_from_filter_impl(obj_cache: &ObjectCache,
                                           ad_h: ADHandle,
                                           sign_key_h: SignKeyHandle)
                                           -> FfiResult<()> {
    let sign_key = *obj_cache.get_sign_key(sign_key_h)?;
    let mut ad = obj_cache.get_ad(ad_h)?;
    let _ = match *ad.filter_mut() {
        Filter::WhiteList(ref mut list) |
        Filter::BlackList(ref mut list) => list.remove(&sign_key),
    };
    Ok(())
}

/// Get the owner's encrypt key
#[no_mangle]
pub unsafe extern "C" fn appendable_data_encrypt_key(session: *const Session,
                                                     ad_h: ADHandle,
                                                     user_data: *mut c_void,
                                                     o_cb: unsafe extern "C" fn(*mut c_void,
                                                                                i32,
                                                                                EncryptKeyHandle)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            match appendable_data_encrypt_key_impl(obj_cache, ad_h) {
                Ok(handle) => o_cb(user_data.0, 0, handle),
                Err(e) => o_cb(user_data.0, ffi_error_code!(e), 0),
            }
            None
        })
    });
}

fn appendable_data_encrypt_key_impl(object_cache: &ObjectCache,
                                    ad_h: AppendableDataHandle)
                                    -> FfiResult<EncryptKeyHandle> {
    let pk = match *object_cache.get_ad(ad_h)? {
        AppendableData::Priv(ref elt) => elt.encrypt_key.clone(),
        _ => Err(FfiError::UnsupportedOperation)?,
    };
    Ok(object_cache.insert_encrypt_key(pk))
}

/// Get number of appended data items.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_num_of_data(session: *const Session,
                                                     ad_h: ADHandle,
                                                     user_data: *mut c_void,
                                                     o_cb: unsafe extern "C" fn(*mut c_void,
                                                                                i32,
                                                                                usize)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            match appendable_data_num_of_data_impl(obj_cache, ad_h, false) {
                Ok(num_of_data) => o_cb(user_data.0, 0, num_of_data),
                Err(e) => o_cb(user_data.0, ffi_error_code!(e), 0),
            }
            None
        })
    });
}

/// Get number of appended deleted data items.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_num_of_deleted_data(session: *const Session,
                                                             ad_h: ADHandle,
                                                             user_data: *mut c_void,
                                                             o_cb: unsafe extern "C" fn(*mut c_void,
                                                                                        i32,
                                                                                        usize)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            match appendable_data_num_of_data_impl(obj_cache, ad_h, true) {
                Ok(num) => o_cb(user_data.0, 0, num),
                Err(e) => o_cb(user_data.0, ffi_error_code!(e), 0),
            }
            None
        })
    });
}

fn appendable_data_num_of_data_impl(obj_cache: &ObjectCache,
                                    ad_h: ADHandle,
                                    is_deleted_data: bool)
                                    -> FfiResult<usize> {
    let num = match *obj_cache.get_ad(ad_h)? {
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
    Ok(num)
}

/// Get nth appended DataIdentifier from data.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_nth_data_id(session: *const Session,
                                                     app: AppHandle,
                                                     ad_h: ADHandle,
                                                     n: usize,
                                                     user_data: *mut c_void,
                                                     o_cb: unsafe extern "C" fn(*mut c_void,
                                                                                i32,
                                                                                DataIdHandle)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            match appendable_data_nth_data_id_impl(obj_cache, app, ad_h, n, false) {
                Ok(handle) => o_cb(user_data.0, 0, handle),
                Err(e) => o_cb(user_data.0, ffi_error_code!(e), 0),
            }
            None
        })
    });
}

/// Get nth appended DataIdentifier from deleted data.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_nth_deleted_data_id(session: *const Session,
                                                             app: AppHandle,
                                                             ad_h: ADHandle,
                                                             n: usize,
                                                             user_data: *mut c_void,
                                                             o_cb: unsafe extern "C"
                                                             fn(*mut c_void,
                                                                i32,
                                                                DataIdHandle)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            match appendable_data_nth_data_id_impl(obj_cache, app, ad_h, n, true) {
                Ok(handle) => {
                    o_cb(user_data.0, 0, handle);
                }
                Err(e) => {
                    o_cb(user_data.0, ffi_error_code!(e), 0);
                }
            }
            None
        })
    });
}

fn appendable_data_nth_data_id_impl(obj_cache: &ObjectCache,
                                    app: AppHandle,
                                    ad_h: ADHandle,
                                    n: usize,
                                    is_deleted_data: bool)
                                    -> Result<DataIdHandle, FfiError> {
    let app_keys = obj_cache.get_app(app)?.asym_enc_keys();
    let data_id = match *obj_cache.get_ad(ad_h)? {
        AppendableData::Priv(ref elt) => {
            let priv_data = if is_deleted_data {
                nth(&elt.deleted_data, n)?
            } else {
                nth(&elt.data, n)?
            };
            let (ref pk, ref sk) = app_keys?;
            priv_data.open(pk, sk).map_err(CoreError::from)?.pointer

        }
        AppendableData::Pub(ref elt) => {
            if is_deleted_data {
                nth(&elt.deleted_data, n)?.pointer
            } else {
                nth(&elt.data, n)?.pointer
            }
        }
    };
    let handle = obj_cache.insert_data_id(data_id);
    Ok(handle)
}

/// Get nth sign key from data
#[no_mangle]
pub unsafe extern "C" fn appendable_data_nth_data_sign_key(session: *const Session,
                                                           app: AppHandle,
                                                           ad_h: ADHandle,
                                                           n: usize,
                                                           user_data: *mut c_void,
                                                           o_cb: unsafe extern "C"
                                                           fn(*mut c_void,
                                                              i32,
                                                              SignKeyHandle)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            match appendable_data_nth_sign_key_impl(obj_cache, app, ad_h, n, false) {
                Ok(handle) => o_cb(user_data.0, 0, handle),
                Err(e) => o_cb(user_data.0, ffi_error_code!(e), 0),
            }
            None
        })
    })
}

/// Get nth sign key from deleted data
#[no_mangle]
pub unsafe extern "C" fn appendable_data_nth_deleted_data_sign_key(session: *const Session,
                                                                   app: AppHandle,
                                                                   ad_h: ADHandle,
                                                                   n: usize,
                                                                   user_data: *mut c_void,
                                                                   o_cb: unsafe extern "C"
                                                                   fn(*mut c_void,
                                                                      i32,
                                                                      SignKeyHandle)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            match appendable_data_nth_sign_key_impl(obj_cache, app, ad_h, n, true) {
                Ok(handle) => o_cb(user_data.0, 0, handle),
                Err(e) => o_cb(user_data.0, ffi_error_code!(e), 0),
            }
            None
        })
    });
}

unsafe fn appendable_data_nth_sign_key_impl(obj_cache: &ObjectCache,
                                            app: AppHandle,
                                            ad_h: ADHandle,
                                            n: usize,
                                            is_deleted_data: bool)
                                            -> Result<SignKeyHandle, FfiError> {
    let app_enc_keys = obj_cache.get_app(app)?.asym_enc_keys()?;
    let sign_key = match *obj_cache.get_ad(ad_h)? {
        AppendableData::Priv(ref elt) => {
            let priv_data = if is_deleted_data {
                nth(&elt.deleted_data, n)?
            } else {
                nth(&elt.data, n)?
            };
            let (ref pk, ref sk) = app_enc_keys;
            priv_data.open(pk, sk).map_err(CoreError::from)?.sign_key
        }
        AppendableData::Pub(ref elt) => {
            if is_deleted_data {
                nth(&elt.deleted_data, n)?.sign_key
            } else {
                nth(&elt.data, n)?.sign_key
            }
        }
    };

    let handle = obj_cache.insert_sign_key(sign_key);
    Ok(handle)
}

/// Remove the n-th data item from the appendable data. The data has to be
/// POST'd afterwards for the
/// change to be registered by the network. The data is moved to deleted data.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_remove_nth_data(session: *const Session,
                                                         ad_h: ADHandle,
                                                         n: usize,
                                                         user_data: *mut c_void,
                                                         o_cb: unsafe extern "C" fn(*mut c_void,
                                                                                    i32)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            let res = appendable_data_remove_nth_data_impl(obj_cache, ad_h, n);
            o_cb(user_data.0, ffi_result_code!(res));
            None
        })
    })
}

fn appendable_data_remove_nth_data_impl(obj_cache: &ObjectCache,
                                        ad_h: ADHandle,
                                        n: usize)
                                        -> FfiResult<()> {
    match *obj_cache.get_ad(ad_h)? {
        AppendableData::Pub(ref mut elt) => {
            // TODO Isn't there Entry::Occupied::remove() like HashMap etc to prevent
            // clone? If there is refactor in other places too here.
            let item = nth(&elt.data, n)?.clone();
            if elt.data.remove(&item) {
                let _ = elt.deleted_data.insert(item);
            }
        }
        AppendableData::Priv(ref mut elt) => {
            let item = nth(&elt.data, n)?.clone();
            if elt.data.remove(&item) {
                let _ = elt.deleted_data.insert(item);
            }
        }
    }
    Ok(())
}

/// Restore the n-th delete data item to data field back. The data has to be
/// POST'd afterwards for the change to be registered by the network.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_restore_nth_deleted_data(session: *const Session,
                                                                  ad_h: ADHandle,
                                                                  n: usize,
                                                                  user_data: *mut c_void,
                                                                  o_cb: unsafe extern "C"
                                                                  fn(*mut c_void,
                                                                     i32)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            let res = appendable_data_restore_nth_deleted_data_impl(obj_cache, ad_h, n);
            o_cb(user_data.0, ffi_result_code!(res));
            None
        })
    });
}

fn appendable_data_restore_nth_deleted_data_impl(obj_cache: &ObjectCache,
                                                 ad_h: ADHandle,
                                                 n: usize)
                                                 -> FfiResult<()> {
    match *obj_cache.get_ad(ad_h)? {
        AppendableData::Pub(ref mut elt) => {
            // TODO Isn't there Entry::Occupied::remove() like HashMap etc to prevent
            // clone? If there is refactor in other places too here.
            let item = nth(&elt.deleted_data, n)?.clone();
            if elt.deleted_data.remove(&item) {
                let _ = elt.data.insert(item);
            }
        }
        AppendableData::Priv(ref mut elt) => {
            let item = nth(&elt.deleted_data, n)?.clone();
            if elt.deleted_data.remove(&item) {
                let _ = elt.data.insert(item);
            }
        }
    }
    Ok(())
}

/// Clear all data - moves it to deleted data.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_clear_data(session: *const Session,
                                                    ad_h: ADHandle,
                                                    user_data: *mut c_void,
                                                    o_cb: unsafe extern "C" fn(*mut c_void, i32)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            let res = appendable_data_clear_data_impl(obj_cache, ad_h);
            o_cb(user_data.0, ffi_result_code!(res));
            None
        })
    });
}

fn appendable_data_clear_data_impl(obj_cache: &ObjectCache, ad_h: ADHandle) -> FfiResult<()> {
    match *obj_cache.get_ad(ad_h)? {
        AppendableData::Pub(ref mut elt) => {
            let tmp = mem::replace(&mut elt.data, Default::default());
            elt.deleted_data.extend(tmp);
        }
        AppendableData::Priv(ref mut elt) => {
            let tmp = mem::replace(&mut elt.data, Default::default());
            elt.deleted_data.extend(tmp);
        }
    };
    Ok(())
}

/// Remove the n-th data item from the deleted data. The data has to be POST'd
/// afterwards for the
/// change to be registered by the network. The data is removed permanently.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_remove_nth_deleted_data(session: *const Session,
                                                                 ad_h: ADHandle,
                                                                 n: usize,
                                                                 user_data: *mut c_void,
                                                                 o_cb: unsafe extern "C"
                                                                 fn(*mut c_void,
                                                                    i32)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            let res = appendable_data_remove_nth_deleted_data_impl(obj_cache, ad_h, n);
            o_cb(user_data.0, ffi_result_code!(res));
            None
        })
    });
}

fn appendable_data_remove_nth_deleted_data_impl(obj_cache: &ObjectCache,
                                                ad_h: ADHandle,
                                                n: usize)
                                                -> FfiResult<()> {
    match *obj_cache.get_ad(ad_h)? {
        AppendableData::Pub(ref mut elt) => {
            let item = nth(&elt.deleted_data, n)?.clone();
            let _ = elt.deleted_data.remove(&item);
        }
        AppendableData::Priv(ref mut elt) => {
            let item = nth(&elt.deleted_data, n)?.clone();
            let _ = elt.deleted_data.remove(&item);
        }
    }
    Ok(())
}

/// Clear all deleted data - data will be actually be removed.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_clear_deleted_data(session: *const Session,
                                                            ad_h: ADHandle,
                                                            user_data: *mut c_void,
                                                            o_cb: unsafe extern "C"
                                                            fn(*mut c_void,
                                                               i32)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            let res = appendable_data_clear_deleted_data_impl(obj_cache, ad_h);
            o_cb(user_data.0, ffi_result_code!(res));
            None
        })
    });
}

fn appendable_data_clear_deleted_data_impl(obj_cache: &ObjectCache,
                                           ad_h: ADHandle)
                                           -> FfiResult<()> {
    match *obj_cache.get_ad(ad_h)? {
        AppendableData::Pub(ref mut elt) => elt.deleted_data.clear(),
        AppendableData::Priv(ref mut elt) => elt.deleted_data.clear(),
    }
    Ok(())
}

/// Append data.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_append(session: *const Session,
                                                ad_h: ADHandle,
                                                data_id_h: DataIdHandle,
                                                user_data: *mut c_void,
                                                o_cb: unsafe extern "C" fn(*mut c_void, i32)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |client, obj_cache| {
            let c2 = client.clone();

            let fut =
                futures::done(appendable_data_append_impl(client, obj_cache, ad_h, data_id_h))
                    .and_then(move |append_wrapper| {
                        c2.append(append_wrapper, None).map_err(FfiError::from)
                    })
                    .map(move |_| o_cb(user_data.0, 0))
                    .map_err(move |e| o_cb(user_data.0, ffi_error_code!(e)))
                    .into_box();

            Some(fut)
        })
    });
}

fn appendable_data_append_impl(client: &Client,
                               obj_cache: &ObjectCache,
                               ad_h: ADHandle,
                               data_id_h: DataIdHandle)
                               -> FfiResult<AppendWrapper> {
    let data_id = *obj_cache.get_data_id(data_id_h)?;

    let sign_pk = client.public_signing_key()?;
    let sign_sk = client.secret_signing_key()?;

    let appended_data = AppendedData::new(data_id, sign_pk, &sign_sk).map_err(CoreError::from)?;

    match *obj_cache.get_ad(ad_h)? {
        AppendableData::Priv(ref elt) => {
            let priv_appended_data = try!(PrivAppendedData::new(&appended_data, &elt.encrypt_key)
                .map_err(FfiError::from));
            AppendWrapper::new_priv(elt.name,
                                    priv_appended_data,
                                    (&sign_pk, &sign_sk),
                                    elt.version)
                .map_err(FfiError::from)
        }
        AppendableData::Pub(ref elt) => {
            Ok(AppendWrapper::new_pub(elt.name, appended_data, elt.version))
        }
    }
}

/// Get the current version of AppendableData by its handle
#[no_mangle]
pub unsafe extern "C" fn appendable_data_version(session: *const Session,
                                                 handle: ADHandle,
                                                 user_data: *mut c_void,
                                                 o_cb: unsafe extern "C" fn(*mut c_void,
                                                                            i32,
                                                                            u64)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            match appendable_data_version_impl(obj_cache, handle) {
                Ok(ver) => o_cb(user_data.0, 0, ver),
                Err(e) => o_cb(user_data.0, ffi_error_code!(e), 0),
            }
            None
        })
    });
}

fn appendable_data_version_impl(obj_cache: &ObjectCache, handle: ADHandle) -> FfiResult<u64> {
    Ok(match *obj_cache.get_ad(handle)? {
        AppendableData::Pub(ref mut elt) => elt.get_version(),
        AppendableData::Priv(ref mut elt) => elt.get_version(),
    })
}

/// Returns true if the app is one of the owners of the provided AppendableData.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_is_owned(session: *const Session,
                                                  handle: ADHandle,
                                                  user_data: *mut c_void,
                                                  o_cb: unsafe extern "C" fn(*mut c_void,
                                                                             i32,
                                                                             bool)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |client, obj_cache| {
            match appendable_data_is_owned_impl(client, obj_cache, handle) {
                Ok(is_owned) => o_cb(user_data.0, 0, is_owned),
                Err(e) => o_cb(user_data.0, ffi_error_code!(e), false),
            }
            None
        })
    });
}

fn appendable_data_is_owned_impl(client: &Client,
                                 obj_cache: &ObjectCache,
                                 handle: ADHandle)
                                 -> FfiResult<bool> {
    let my_key = client.public_signing_key()?;
    Ok(match *obj_cache.get_ad(handle)? {
        AppendableData::Pub(ref mut elt) => elt.get_owner_keys().contains(&my_key),
        AppendableData::Priv(ref mut elt) => elt.get_owner_keys().contains(&my_key),
    })
}

/// See if AppendableData size is valid.
#[no_mangle]
pub unsafe extern "C" fn appendable_data_validate_size(session: *const Session,
                                                       handle: ADHandle,
                                                       user_data: *mut c_void,
                                                       o_cb: unsafe extern "C" fn(*mut c_void,
                                                                                  i32,
                                                                                  bool)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            match appendable_data_validate_size_impl(obj_cache, handle) {
                Ok(is_valid) => o_cb(user_data.0, 0, is_valid),
                Err(e) => o_cb(user_data.0, ffi_error_code!(e), false),
            }
            None
        })
    });
}

fn appendable_data_validate_size_impl(obj_cache: &ObjectCache,
                                      handle: ADHandle)
                                      -> FfiResult<bool> {
    Ok(match *obj_cache.get_ad(handle)? {
        AppendableData::Pub(ref elt) => elt.validate_size(),
        AppendableData::Priv(ref elt) => elt.validate_size(),
    })
}

/// Free AppendableData handle
#[no_mangle]
pub unsafe extern "C" fn appendable_data_free(session: *const Session,
                                              handle: ADHandle,
                                              user_data: *mut c_void,
                                              o_cb: unsafe extern "C" fn(*mut c_void, i32)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            match obj_cache.remove_ad(handle) {
                Ok(_) => o_cb(user_data.0, 0),
                Err(e) => o_cb(user_data.0, ffi_error_code!(e)),
            }
            None
        })
    });
}

// Convenience function to access n-th item from the given set, returning
// FfiError::InvalidIndex if not found.
fn nth<T>(items: &BTreeSet<T>, n: usize) -> Result<&T, FfiError> {
    items.iter().nth(n).ok_or(FfiError::InvalidIndex)
}

#[cfg(test)]
mod tests {
    use ffi::{AppHandle, AppendableDataHandle, DataIdHandle, ObjectHandle};
    use ffi::{FfiError, Session, test_utils};
    use ffi::low_level_api::misc::*;
    use rand;
    use routing::DataIdentifier;
    use rust_sodium::crypto::sign;
    use std::{panic, process};
    use std::collections::HashSet;
    use std::os::raw::c_void;
    use std::sync::mpsc;
    use super::*;

    type ADHandle = AppendableDataHandle;

    macro_rules! assert_num_of_data {
        ($sess:ident, $ad_h:ident, $expected:expr) => {
            let (mut num_tx, num_rx) = mpsc::channel::<(i32, usize)>();
            let num_tx: *mut _ = &mut num_tx;
            appendable_data_num_of_data(&$sess, $ad_h, num_tx as *mut c_void, num_cb);
            let (err_code, num) = unwrap!(num_rx.recv());
            assert_eq!(err_code, 0);
            assert_eq!(num, $expected);
        }
    }

    macro_rules! assert_num_of_deleted_data {
        ($sess:ident, $ad_h:ident, $expected:expr) => {
            let (mut num_tx, num_rx) = mpsc::channel::<(i32, usize)>();
            let num_tx: *mut _ = &mut num_tx;
            appendable_data_num_of_deleted_data(&$sess, $ad_h, num_tx as *mut c_void, num_cb);
            let (err_code, num) = unwrap!(num_rx.recv());
            assert_eq!(err_code, 0);
            assert_eq!(num, $expected);
        }
    }

    #[test]
    fn put_append_and_get() {
        let (sess, app_h, _sign_key_h) = create_test_client();
        let ad_name = rand::random();

        // Data to append
        let immut_id_0_h = generate_random_immutable_data_id(&sess);
        let immut_id_1_h = generate_random_immutable_data_id(&sess);

        let (mut handle_tx, handle_rx) = mpsc::channel::<(i32, ObjectHandle)>();
        let handle_tx: *mut _ = &mut handle_tx;
        let handle_tx = handle_tx as *mut c_void;

        let (mut err_code_tx, err_code_rx) = mpsc::channel::<i32>();
        let err_code_tx: *mut _ = &mut err_code_tx;
        let err_code_tx = err_code_tx as *mut c_void;

        let (mut bool_tx, bool_rx) = mpsc::channel::<(i32, bool)>();
        let bool_tx: *mut _ = &mut bool_tx;
        let bool_tx = bool_tx as *mut c_void;

        let (got_immut_id_0_h, got_immut_id_1_h) = unsafe {
            // Create
            appendable_data_new_pub(&sess, &ad_name, handle_tx, handle_cb);
            let (err_code, ad_h) = unwrap!(handle_rx.recv());
            assert_eq!(err_code, 0);

            appendable_data_extract_data_id(&sess, ad_h, handle_tx, handle_cb);
            let (err_code, ad_id_h) = unwrap!(handle_rx.recv());
            assert_eq!(err_code, 0);

            // PUT to the network
            appendable_data_put(&sess, ad_h, err_code_tx, err_code_cb);
            let err_code = unwrap!(err_code_rx.recv());
            assert_eq!(err_code, 0);

            // APPEND
            appendable_data_append(&sess, ad_h, immut_id_0_h, err_code_tx, err_code_cb);
            let err_code = unwrap!(err_code_rx.recv());
            assert_eq!(err_code, 0);

            appendable_data_append(&sess, ad_h, immut_id_1_h, err_code_tx, err_code_cb);
            let err_code = unwrap!(err_code_rx.recv());
            assert_eq!(err_code, 0);

            // GET back
            let (err_code, ad_h) = reload_ad(&sess, ad_id_h, ad_h);
            assert_eq!(err_code, 0);
            assert_num_of_data!(sess, ad_h, 2);

            appendable_data_nth_data_id(&sess, app_h, ad_h, 0, handle_tx, handle_cb);
            let (err_code, got_immut_id_0_h) = unwrap!(handle_rx.recv());
            assert_eq!(err_code, 0);

            appendable_data_nth_data_id(&sess, app_h, ad_h, 1, handle_tx, handle_cb);
            let (err_code, got_immut_id_1_h) = unwrap!(handle_rx.recv());
            assert_eq!(err_code, 0);

            // Check owners
            appendable_data_is_owned(&sess, ad_h, bool_tx, bool_cb);
            let (err_code, is_owner) = unwrap!(bool_rx.recv());
            assert_eq!(err_code, 0);
            assert_eq!(is_owner, true);

            let sess_fake = test_utils::create_session();
            let ad_id_h2 = copy_data_id(&sess, &sess_fake, ad_id_h);
            let (err_code, got_ad_h) = reload_ad(&sess_fake, ad_id_h2, 0);
            assert_eq!(err_code, 0);

            appendable_data_is_owned(&sess_fake, got_ad_h, bool_tx, bool_cb);
            let (err_code, is_owner) = unwrap!(bool_rx.recv());
            assert_eq!(err_code, 0);
            assert_eq!(is_owner, false);

            appendable_data_free(&sess_fake, got_ad_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            appendable_data_free(&sess, ad_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            (got_immut_id_0_h, got_immut_id_1_h)
        };

        // Verify the data items we got back are the same we put in.
        test_utils::run_now(&sess, move |_, object_cache| {
            let mut orig = HashSet::with_capacity(2);
            let _ = orig.insert(*unwrap!(object_cache.get_data_id(immut_id_0_h)));
            let _ = orig.insert(*unwrap!(object_cache.get_data_id(immut_id_1_h)));

            let mut got = HashSet::with_capacity(2);
            let _ = got.insert(*unwrap!(object_cache.get_data_id(got_immut_id_0_h)));
            let _ = got.insert(*unwrap!(object_cache.get_data_id(got_immut_id_1_h)));

            assert_eq!(orig, got);
        })
    }

    #[test]
    fn filter() {
        let (sess0, _app0, _) = create_test_client();
        let (sess1, _app1, sign_key1) = create_test_client();
        let (sess2, _app2, _) = create_test_client();

        let sign_key1_h = test_utils::run_now(&sess0, move |_, obj_cache| {
            obj_cache.insert_sign_key(sign_key1)
        });

        let ad_name = rand::random();

        let (mut handle_tx, handle_rx) = mpsc::channel::<(i32, ObjectHandle)>();
        let handle_tx: *mut _ = &mut handle_tx;
        let handle_tx = handle_tx as *mut c_void;

        let (mut err_code_tx, err_code_rx) = mpsc::channel::<i32>();
        let err_code_tx: *mut _ = &mut err_code_tx;
        let err_code_tx = err_code_tx as *mut c_void;

        let (mut filter_type_tx, filter_type_rx) = mpsc::channel::<(i32, FilterType)>();
        let filter_type_tx: *mut _ = &mut filter_type_tx;
        let filter_type_tx = filter_type_tx as *mut c_void;

        unsafe {
            appendable_data_new_pub(&sess0, &ad_name, handle_tx, handle_cb);
            let (err_code, ad0_h) = unwrap!(handle_rx.recv());
            assert_eq!(err_code, 0);

            appendable_data_extract_data_id(&sess0, ad0_h, handle_tx, handle_cb);
            let (err_code, ad_id_h) = unwrap!(handle_rx.recv());
            assert_eq!(err_code, 0);

            appendable_data_put(&sess0, ad0_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            // Copy AD to other app sessions
            let ad_id1_h = copy_data_id(&sess0, &sess1, ad_id_h);
            let ad_id2_h = copy_data_id(&sess0, &sess2, ad_id_h);

            let (err_code, ad1_h) = reload_ad(&sess1, ad_id1_h, 0);
            assert_eq!(err_code, 0);

            let (err_code, ad2_h) = reload_ad(&sess2, ad_id2_h, 0);
            assert_eq!(err_code, 0);

            // Anyone can append by default
            let immut_id_1_h = generate_random_immutable_data_id(&sess1);
            let immut_id_2_h = generate_random_immutable_data_id(&sess2);

            appendable_data_append(&sess1, ad1_h, immut_id_1_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            appendable_data_append(&sess2, ad2_h, immut_id_2_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            // Set blacklist
            let immut_id_1_h = generate_random_immutable_data_id(&sess1);
            let immut_id_2_h = generate_random_immutable_data_id(&sess2);

            appendable_data_filter_type(&sess0, ad0_h, filter_type_tx, filter_type_cb);
            let (err_code, filter_type) = unwrap!(filter_type_rx.recv());
            assert_eq!(err_code, 0);
            assert_eq!(filter_type, FilterType::BlackList);

            appendable_data_insert_to_filter(&sess0, ad0_h, sign_key1_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            appendable_data_post(&sess0, ad0_h, false, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            let (err_code, ad1_h) = reload_ad(&sess1, ad_id1_h, ad1_h);
            assert_eq!(err_code, 0);
            let (err_code, ad2_h) = reload_ad(&sess2, ad_id2_h, ad2_h);
            assert_eq!(err_code, 0);

            appendable_data_append(&sess1, ad1_h, immut_id_1_h, err_code_tx, err_code_cb);
            assert!(unwrap!(err_code_rx.recv()) != 0);
            appendable_data_append(&sess2, ad2_h, immut_id_2_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            let (err_code, ad0_h) = reload_ad(&sess0, ad_id_h, ad0_h);
            assert_eq!(err_code, 0);
            appendable_data_remove_from_filter(&sess0,
                                               ad0_h,
                                               sign_key1_h,
                                               err_code_tx,
                                               err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            appendable_data_post(&sess0, ad0_h, false, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            let (err_code, ad1_h) = reload_ad(&sess1, ad_id1_h, ad1_h);
            assert_eq!(err_code, 0);
            appendable_data_append(&sess1, ad1_h, immut_id_1_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            // Set whitelist
            let immut_id_1_h = generate_random_immutable_data_id(&sess1);
            let immut_id_2_h = generate_random_immutable_data_id(&sess2);

            let (err_code, ad0_h) = reload_ad(&sess0, ad_id_h, ad0_h);
            assert_eq!(err_code, 0);
            appendable_data_toggle_filter(&sess0, ad0_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            appendable_data_filter_type(&sess0, ad0_h, filter_type_tx, filter_type_cb);
            let (err_code, filter_type) = unwrap!(filter_type_rx.recv());
            assert_eq!(err_code, 0);
            assert_eq!(filter_type, FilterType::WhiteList);

            appendable_data_insert_to_filter(&sess0, ad0_h, sign_key1_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            appendable_data_post(&sess0, ad0_h, false, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            let (err_code, ad1_h) = reload_ad(&sess1, ad_id1_h, ad1_h);
            assert_eq!(err_code, 0);
            let (err_code, ad2_h) = reload_ad(&sess2, ad_id2_h, ad2_h);
            assert_eq!(err_code, 0);

            appendable_data_append(&sess1, ad1_h, immut_id_1_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);
            appendable_data_append(&sess2, ad2_h, immut_id_2_h, err_code_tx, err_code_cb);
            assert!(unwrap!(err_code_rx.recv()) != 0);

            let (err_code, ad0_h) = reload_ad(&sess0, ad_id_h, ad0_h);
            assert_eq!(err_code, 0);
            appendable_data_remove_from_filter(&sess0,
                                               ad0_h,
                                               sign_key1_h,
                                               err_code_tx,
                                               err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            appendable_data_post(&sess0, ad0_h, false, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            let (err_code, ad1_h) = reload_ad(&sess1, ad_id1_h, ad1_h);
            assert_eq!(err_code, 0);
            appendable_data_append(&sess1, ad1_h, immut_id_1_h, err_code_tx, err_code_cb);
            assert!(unwrap!(err_code_rx.recv()) != 0);

            // Toggle filter and ensure it's blacklist again
            appendable_data_toggle_filter(&sess0, ad0_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            appendable_data_filter_type(&sess0, ad0_h, filter_type_tx, filter_type_cb);
            let (err_code, filter_type) = unwrap!(filter_type_rx.recv());
            assert_eq!(err_code, 0);
            assert_eq!(filter_type, FilterType::BlackList);
        }
    }

    #[test]
    fn priv_appendable_data() {
        let (sess0, app0, _sign_key0) = create_test_client();
        let (sess1, _app1, sign_key1) = create_test_client();
        let (sess2, _app2, sign_key2) = create_test_client();

        let ad_name = rand::random();

        let (mut handle_tx, handle_rx) = mpsc::channel::<(i32, ObjectHandle)>();
        let handle_tx: *mut _ = &mut handle_tx;
        let handle_tx = handle_tx as *mut c_void;

        let (mut err_code_tx, err_code_rx) = mpsc::channel::<i32>();
        let err_code_tx: *mut _ = &mut err_code_tx;
        let err_code_tx = err_code_tx as *mut c_void;

        let (mut bool_tx, bool_rx) = mpsc::channel::<(i32, bool)>();
        let bool_tx: *mut _ = &mut bool_tx;
        let bool_tx = bool_tx as *mut c_void;

        let (mut filter_type_tx, filter_type_rx) = mpsc::channel::<(i32, FilterType)>();
        let filter_type_tx: *mut _ = &mut filter_type_tx;
        let filter_type_tx = filter_type_tx as *mut c_void;

        unsafe {
            // Create
            appendable_data_new_priv(&sess0, app0, &ad_name, handle_tx, handle_cb);
            let (err_code, ad_priv_h) = unwrap!(handle_rx.recv());
            assert_eq!(err_code, 0);

            appendable_data_extract_data_id(&sess0, ad_priv_h, handle_tx, handle_cb);
            let (err_code, ad_id_h) = unwrap!(handle_rx.recv());
            assert_eq!(err_code, 0);

            let ad_id_h1 = copy_data_id(&sess0, &sess1, ad_id_h);
            let ad_id_h2 = copy_data_id(&sess0, &sess2, ad_id_h);

            // Test PUT requests for private data
            appendable_data_put(&sess0, ad_priv_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            let immut_id_a_h = generate_random_immutable_data_id(&sess0);
            let immut_id_b_h = generate_random_immutable_data_id(&sess0);

            let immut_id_h1 = generate_random_immutable_data_id(&sess1);
            let immut_id_h2 = generate_random_immutable_data_id(&sess2);

            appendable_data_append(&sess0, ad_priv_h, immut_id_a_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            appendable_data_append(&sess0, ad_priv_h, immut_id_b_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            let (err_code, ad_priv_h) = reload_ad(&sess0, ad_id_h, ad_priv_h);
            assert_eq!(err_code, 0);
            assert_num_of_data!(sess0, ad_priv_h, 2);

            appendable_data_nth_data_id(&sess0, app0, ad_priv_h, 0, handle_tx, handle_cb);
            let (err_code, got_immut_id_a_h) = unwrap!(handle_rx.recv());
            assert_eq!(err_code, 0);

            appendable_data_nth_data_id(&sess0, app0, ad_priv_h, 1, handle_tx, handle_cb);
            let (err_code, got_immut_id_b_h) = unwrap!(handle_rx.recv());
            assert_eq!(err_code, 0);

            // Delete and restore private appendable data
            appendable_data_remove_nth_data(&sess0, ad_priv_h, 0, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            appendable_data_post(&sess0, ad_priv_h, true, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            let (err_code, ad_priv_h) = reload_ad(&sess0, ad_id_h, ad_priv_h);
            assert_eq!(err_code, 0);
            assert_num_of_data!(sess0, ad_priv_h, 1);
            assert_num_of_deleted_data!(sess0, ad_priv_h, 1);

            appendable_data_nth_deleted_data_id(&sess0, app0, ad_priv_h, 0, handle_tx, handle_cb);
            let (err_code, _deleted_data_h) = unwrap!(handle_rx.recv());
            assert_eq!(err_code, 0);

            appendable_data_restore_nth_deleted_data(&sess0,
                                                     ad_priv_h,
                                                     0,
                                                     err_code_tx,
                                                     err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            appendable_data_post(&sess0, ad_priv_h, true, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            let (err_code, ad_priv_h) = reload_ad(&sess0, ad_id_h, ad_priv_h);
            assert_eq!(err_code, 0);
            assert_num_of_data!(sess0, ad_priv_h, 2);
            assert_num_of_deleted_data!(sess0, ad_priv_h, 0);

            // Check owners of appendable data
            appendable_data_is_owned(&sess0, ad_priv_h, bool_tx, bool_cb);
            let (err_code, is_owner) = unwrap!(bool_rx.recv());
            assert_eq!(err_code, 0);
            assert_eq!(is_owner, true);

            let (err_code, ad_priv_h1) = reload_ad(&sess1, ad_id_h1, 0);
            assert_eq!(err_code, 0);

            appendable_data_is_owned(&sess1, ad_priv_h1, bool_tx, bool_cb);
            let (err_code, is_owner) = unwrap!(bool_rx.recv());
            assert_eq!(err_code, 0);
            assert_eq!(is_owner, false);

            // Other apps can append new data
            appendable_data_append(&sess1, ad_priv_h1, immut_id_h1, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            let (err_code, ad_priv_h2) = reload_ad(&sess2, ad_id_h2, 0);
            assert_eq!(err_code, 0);
            appendable_data_append(&sess2, ad_priv_h2, immut_id_h2, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            // Check blacklist filter for private appendable data
            let (err_code, ad_priv_h) = reload_ad(&sess0, ad_id_h, 0);
            assert_eq!(err_code, 0);

            appendable_data_filter_type(&sess0, ad_priv_h, filter_type_tx, filter_type_cb);
            let (err_code, filter_type) = unwrap!(filter_type_rx.recv());
            assert_eq!(err_code, 0);
            assert_eq!(filter_type, FilterType::BlackList);

            let (sign_key1_h, sign_key2_h) = test_utils::run_now(&sess0, move |_, obj_cache| {
                let h1 = obj_cache.insert_sign_key(sign_key1);
                let h2 = obj_cache.insert_sign_key(sign_key2);

                (h1, h2)
            });

            appendable_data_insert_to_filter(&sess0,
                                             ad_priv_h,
                                             sign_key1_h,
                                             err_code_tx,
                                             err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            appendable_data_insert_to_filter(&sess0,
                                             ad_priv_h,
                                             sign_key2_h,
                                             err_code_tx,
                                             err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            appendable_data_post(&sess0, ad_priv_h, false, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            let (err_code, ad_priv_h1) = reload_ad(&sess1, ad_id_h1, ad_priv_h1);
            assert_eq!(err_code, 0);
            appendable_data_append(&sess1, ad_priv_h, immut_id_h1, err_code_tx, err_code_cb);
            assert!(unwrap!(err_code_rx.recv()) != 0);

            let (err_code, ad_priv_h2) = reload_ad(&sess2, ad_id_h2, ad_priv_h2);
            assert_eq!(err_code, 0);
            appendable_data_append(&sess2, ad_priv_h, immut_id_h2, err_code_tx, err_code_cb);
            assert!(unwrap!(err_code_rx.recv()) != 0);

            // Check whitelist filter for private data
            let (err_code, ad_priv_h) = reload_ad(&sess0, ad_id_h, ad_priv_h);
            assert_eq!(err_code, 0);
            appendable_data_toggle_filter(&sess0, ad_priv_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            appendable_data_filter_type(&sess0, ad_priv_h, filter_type_tx, filter_type_cb);
            let (err_code, filter_type) = unwrap!(filter_type_rx.recv());
            assert_eq!(err_code, 0);
            assert_eq!(filter_type, FilterType::WhiteList);

            appendable_data_insert_to_filter(&sess0,
                                             ad_priv_h,
                                             sign_key2_h,
                                             err_code_tx,
                                             err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            appendable_data_post(&sess0, ad_priv_h, false, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            let (err_code, ad_priv_h2) = reload_ad(&sess2, ad_id_h2, ad_priv_h2);
            assert_eq!(err_code, 0);
            appendable_data_append(&sess2, ad_priv_h2, immut_id_h2, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            let (err_code, ad_priv_h1) = reload_ad(&sess1, ad_id_h1, ad_priv_h1);
            assert_eq!(err_code, 0);
            appendable_data_append(&sess1, ad_priv_h1, immut_id_h1, err_code_tx, err_code_cb);
            assert!(unwrap!(err_code_rx.recv()) != 0);

            // Verify the data items we got back are the same we put in.
            test_utils::run_now(&sess0, move |_, obj_cache| {
                let mut orig = HashSet::with_capacity(2);
                let _ = orig.insert(*unwrap!(obj_cache.get_data_id(immut_id_a_h)));
                let _ = orig.insert(*unwrap!(obj_cache.get_data_id(immut_id_b_h)));

                let mut got = HashSet::with_capacity(2);
                let _ = got.insert(*unwrap!(obj_cache.get_data_id(got_immut_id_a_h)));
                let _ = got.insert(*unwrap!(obj_cache.get_data_id(got_immut_id_b_h)));

                assert_eq!(orig, got);
            })
        }
    }

    #[test]
    fn delete_data() {
        let (sess, _app, _sign_key) = create_test_client();

        let ad_name = rand::random();

        let (mut handle_tx, handle_rx) = mpsc::channel::<(i32, ObjectHandle)>();
        let handle_tx: *mut _ = &mut handle_tx;
        let handle_tx = handle_tx as *mut c_void;

        let (mut err_code_tx, err_code_rx) = mpsc::channel::<i32>();
        let err_code_tx: *mut _ = &mut err_code_tx;
        let err_code_tx = err_code_tx as *mut c_void;

        let immut_id_0_h = generate_random_immutable_data_id(&sess);
        let immut_id_1_h = generate_random_immutable_data_id(&sess);

        unsafe {
            // Create AD and PUT it to the network.
            appendable_data_new_pub(&sess, &ad_name, handle_tx, handle_cb);
            let (err_code, ad_h) = unwrap!(handle_rx.recv());
            assert_eq!(err_code, 0);

            appendable_data_extract_data_id(&sess, ad_h, handle_tx, handle_cb);
            let (err_code, ad_id_h) = unwrap!(handle_rx.recv());
            assert_eq!(err_code, 0);

            appendable_data_put(&sess, ad_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            // Append stuff to it.
            appendable_data_append(&sess, ad_h, immut_id_0_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            appendable_data_append(&sess, ad_h, immut_id_1_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            // GET it back.
            let (err_code, ad_h) = reload_ad(&sess, ad_id_h, ad_h);
            assert_eq!(err_code, 0);
            assert_num_of_data!(sess, ad_h, 2);

            // Try to remove one of available versions first
            appendable_data_remove_nth_data(&sess, ad_h, 0, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            appendable_data_post(&sess, ad_h, true, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            let (err_code, ad_h) = reload_ad(&sess, ad_id_h, ad_h);
            assert_eq!(err_code, 0);
            assert_num_of_data!(sess, ad_h, 1);
            assert_num_of_deleted_data!(sess, ad_h, 1);

            // Try restoring deleted data
            appendable_data_restore_nth_deleted_data(&sess, ad_h, 0, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            appendable_data_post(&sess, ad_h, true, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            let (err_code, ad_h) = reload_ad(&sess, ad_id_h, ad_h);
            assert_eq!(err_code, 0);
            assert_num_of_data!(sess, ad_h, 2);

            // Permanently delete data
            appendable_data_remove_nth_data(&sess, ad_h, 0, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            appendable_data_remove_nth_deleted_data(&sess, ad_h, 0, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            appendable_data_post(&sess, ad_h, true, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            let (err_code, ad_h) = reload_ad(&sess, ad_id_h, ad_h);
            assert_eq!(err_code, 0);
            assert_num_of_deleted_data!(sess, ad_h, 0);

            // clear the data and POST it.
            appendable_data_clear_data(&sess, ad_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            appendable_data_post(&sess, ad_h, false, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            // GET it back.
            let (err_code, ad_h) = reload_ad(&sess, ad_id_h, ad_h);
            assert_eq!(err_code, 0);
            assert_num_of_data!(sess, ad_h, 0);
            assert_num_of_deleted_data!(sess, ad_h, 2);

            // Permanently clear deleted data
            appendable_data_clear_deleted_data(&sess, ad_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            appendable_data_post(&sess, ad_h, false, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            let (err_code, ad_h) = reload_ad(&sess, ad_id_h, ad_h);
            assert_eq!(err_code, 0);
            assert_num_of_deleted_data!(sess, ad_h, 0);

            appendable_data_free(&sess, ad_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);
        }
    }

    #[test]
    fn data_encrypt_key() {
        let (sess, app, _sign_key) = create_test_client();

        let (mut handle_tx, handle_rx) = mpsc::channel::<(i32, ObjectHandle)>();
        let handle_tx: *mut _ = &mut handle_tx;
        let handle_tx = handle_tx as *mut c_void;

        let (mut err_code_tx, err_code_rx) = mpsc::channel::<i32>();
        let err_code_tx: *mut _ = &mut err_code_tx;
        let err_code_tx = err_code_tx as *mut c_void;

        unsafe {
            // Initialise public appendable data
            appendable_data_new_pub(&sess, &rand::random(), handle_tx, handle_cb);
            let (err_code, ad_h) = unwrap!(handle_rx.recv());
            assert_eq!(err_code, 0);

            // Public appendable data doens't have a private owner key
            appendable_data_encrypt_key(&sess, ad_h, handle_tx, handle_cb);
            let (err_code, _) = unwrap!(handle_rx.recv());
            assert_eq!(err_code, FfiError::UnsupportedOperation.into());

            appendable_data_free(&sess, ad_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            // Initialise private appendable data
            appendable_data_new_priv(&sess, app, &rand::random(), handle_tx, handle_cb);
            let (err_code, ad_h) = unwrap!(handle_rx.recv());
            assert_eq!(err_code, 0);

            appendable_data_encrypt_key(&sess, ad_h, handle_tx, handle_cb);
            let (err_code, encrypt_key_h) = unwrap!(handle_rx.recv());
            assert_eq!(err_code, 0);

            misc_encrypt_key_free(&sess, encrypt_key_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);
        }
    }

    #[test]
    fn data_sign_key() {
        let (sess0, app0, _sign_key0) = create_test_client();
        let (sess1, _app1, sign_key1) = create_test_client();

        let (mut handle_tx, handle_rx) = mpsc::channel::<(i32, ObjectHandle)>();
        let handle_tx: *mut _ = &mut handle_tx;
        let handle_tx = handle_tx as *mut c_void;

        let (mut err_code_tx, err_code_rx) = mpsc::channel::<i32>();
        let err_code_tx: *mut _ = &mut err_code_tx;
        let err_code_tx = err_code_tx as *mut c_void;

        // Data to append
        let immut_id_0_h = generate_random_immutable_data_id(&sess1);
        let immut_id_1_h = generate_random_immutable_data_id(&sess1);

        unsafe {
            // Create test data
            appendable_data_new_pub(&sess0, &rand::random(), handle_tx, handle_cb);
            let (err_code, ad_h0) = unwrap!(handle_rx.recv());
            assert_eq!(err_code, 0);

            appendable_data_extract_data_id(&sess0, ad_h0, handle_tx, handle_cb);
            let (err_code, ad_id_h) = unwrap!(handle_rx.recv());
            assert_eq!(err_code, 0);

            appendable_data_put(&sess0, ad_h0, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            let ad_id_h1 = copy_data_id(&sess0, &sess1, ad_id_h);
            let (err_code, ad_h1) = reload_ad(&sess1, ad_id_h1, 0);
            assert_eq!(err_code, 0);

            appendable_data_append(&sess1, ad_h1, immut_id_0_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            let (err_code, ad_h0) = reload_ad(&sess0, ad_id_h, ad_h0);
            assert_eq!(err_code, 0);

            // Get a data key of app1
            appendable_data_nth_data_sign_key(&sess0, app0, ad_h0, 0, handle_tx, handle_cb);
            let (err_code, sign_key_h) = unwrap!(handle_rx.recv());
            assert_eq!(err_code, 0);

            test_utils::run_now(&sess0, move |_, obj_cache| {
                assert_eq!(*unwrap!(obj_cache.get_sign_key(sign_key_h)), sign_key1);
            });

            // Now try to get a data key from deleted data
            appendable_data_remove_nth_data(&sess0, ad_h0, 0, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            appendable_data_post(&sess0, ad_h0, true, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            let (err_code, ad_h0) = reload_ad(&sess0, ad_id_h, ad_h0);
            assert_eq!(err_code, 0);

            appendable_data_nth_deleted_data_sign_key(&sess0, app0, ad_h0, 0, handle_tx, handle_cb);
            let (err_code, deleted_sk_h) = unwrap!(handle_rx.recv());
            assert_eq!(err_code, 0);

            test_utils::run_now(&sess0, move |_, obj_cache| {
                assert_eq!(*unwrap!(obj_cache.get_sign_key(deleted_sk_h)), sign_key1);
            });

            // Filter out the key that we've got for an app1
            appendable_data_insert_to_filter(&sess0, ad_h0, deleted_sk_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            appendable_data_post(&sess0, ad_h0, false, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            appendable_data_append(&sess1, ad_h1, immut_id_1_h, err_code_tx, err_code_cb);
            assert!(unwrap!(err_code_rx.recv()) != 0);
        }
    }

    unsafe extern "C" fn err_code_cb(tx: *mut c_void, error_code: i32) {
        let res = panic::catch_unwind(|| {
            let tx = tx as *mut mpsc::Sender<i32>;
            unwrap!((*tx).send(error_code));
        });
        if res.is_err() {
            process::exit(-1);
        }
    }

    unsafe extern "C" fn bool_cb(tx: *mut c_void, error_code: i32, result: bool) {
        let res = panic::catch_unwind(|| {
            let tx = tx as *mut mpsc::Sender<(i32, bool)>;
            unwrap!((*tx).send((error_code, result)));
        });
        if res.is_err() {
            process::exit(-1);
        }
    }

    unsafe extern "C" fn num_cb(tx: *mut c_void, error_code: i32, result: usize) {
        let res = panic::catch_unwind(|| {
            let tx = tx as *mut mpsc::Sender<(i32, usize)>;
            unwrap!((*tx).send((error_code, result)));
        });
        if res.is_err() {
            process::exit(-1);
        }
    }

    unsafe extern "C" fn filter_type_cb(tx: *mut c_void, error_code: i32, result: FilterType) {
        let res = panic::catch_unwind(|| {
            let tx = tx as *mut mpsc::Sender<(i32, FilterType)>;
            unwrap!((*tx).send((error_code, result)));
        });
        if res.is_err() {
            process::exit(-1);
        }
    }

    unsafe extern "C" fn handle_cb(tx: *mut c_void, error_code: i32, handle: ObjectHandle) {
        let res = panic::catch_unwind(|| {
            let tx = tx as *mut mpsc::Sender<(i32, ObjectHandle)>;
            unwrap!((*tx).send((error_code, handle)));
        });
        if res.is_err() {
            process::exit(-1);
        }
    }

    // Copy data id to another session
    fn copy_data_id(src_sess: &Session, dst_sess: &Session, ad_id_h: DataIdHandle) -> DataIdHandle {
        let data_id = test_utils::run_now(src_sess, move |_, obj_cache| {
            unwrap!(obj_cache.get_data_id(ad_id_h)).clone()
        });

        test_utils::run_now(dst_sess,
                            move |_, obj_cache| obj_cache.insert_data_id(data_id))
    }

    fn generate_random_immutable_data_id(session: &Session) -> DataIdHandle {
        let name = rand::random();
        let id = DataIdentifier::Immutable(name);

        test_utils::run_now(session, move |_, obj_cache| obj_cache.insert_data_id(id))
    }

    unsafe fn reload_ad(sess: *const Session,
                        ad_id_h: DataIdHandle,
                        ad_h: ADHandle)
                        -> (i32, ADHandle) {
        if ad_h != 0 {
            let (mut err_code_tx, err_code_rx) = mpsc::channel::<i32>();
            let err_code_tx: *mut _ = &mut err_code_tx;

            appendable_data_free(sess, ad_h, err_code_tx as *mut c_void, err_code_cb);
            let err_code = unwrap!(err_code_rx.recv());
            assert_eq!(err_code, 0);
        }

        let (mut handle_tx, handle_rx) = mpsc::channel::<(i32, ObjectHandle)>();
        let handle_tx: *mut _ = &mut handle_tx;

        appendable_data_get(sess, ad_id_h, handle_tx as *mut c_void, handle_cb);
        unwrap!(handle_rx.recv())
    }

    fn create_test_client() -> (Session, AppHandle, sign::PublicKey) {
        let sess = test_utils::create_session();
        let app = test_utils::create_app(&sess, false);

        let (tx, rx) = mpsc::channel();
        let _ = unwrap!(sess.send(move |client, obj_cache| {
            let sign_key = unwrap!(client.public_signing_key());
            let app_h = obj_cache.insert_app(app);

            unwrap!(tx.send((sign_key, app_h)));
            None
        }));

        let (sign_key, app_h) = unwrap!(rx.recv());
        (sess, app_h, sign_key)
    }
}
