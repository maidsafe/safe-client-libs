// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use ffi::errors::FfiError;
use ffi::helper;
use ffi::low_level_api::DataIdHandle;
use ffi::low_level_api::object_cache::object_cache;
use routing::{DataIdentifier, XOR_NAME_LEN, XorName};
use std::ptr;

/// Construct DataIdentifier for StructuredData.
#[no_mangle]
pub unsafe extern "C" fn data_id_new_struct_data(type_tag: u64,
                                                 id: *const [u8; XOR_NAME_LEN],
                                                 o_handle: *mut DataIdHandle)
                                                 -> i32 {
    helper::catch_unwind_i32(|| {
        let xor_id = XorName(*id);
        let data_id = DataIdentifier::Structured(xor_id, type_tag);
        let handle = {
            let mut obj_cache = unwrap!(object_cache());
            obj_cache.insert_data_id(data_id)
        };

        ptr::write(o_handle, handle);
        0
    })
}

/// Construct DataIdentifier for ImmutableData.
#[no_mangle]
pub unsafe extern "C" fn data_id_new_immut_data(id: *const [u8; XOR_NAME_LEN],
                                                o_handle: *mut DataIdHandle)
                                                -> i32 {
    helper::catch_unwind_i32(|| {
        let xor_id = XorName(*id);
        let data_id = DataIdentifier::Immutable(xor_id);
        let handle = {
            let mut obj_cache = unwrap!(object_cache());
            obj_cache.insert_data_id(data_id)
        };

        ptr::write(o_handle, handle);
        0
    })
}

/// Construct DataIdentifier for AppendableData.
#[no_mangle]
pub unsafe extern "C" fn data_id_new_appendable_data(id: *const [u8; XOR_NAME_LEN],
                                                     is_private: bool,
                                                     o_handle: *mut DataIdHandle)
                                                     -> i32 {
    helper::catch_unwind_i32(|| {
        let xor_id = XorName(*id);
        let data_id = if is_private {
            DataIdentifier::PrivAppendable(xor_id)
        } else {
            DataIdentifier::PubAppendable(xor_id)
        };

        let handle = {
            let mut obj_cache = unwrap!(object_cache());
            obj_cache.insert_data_id(data_id)
        };

        ptr::write(o_handle, handle);
        0
    })
}

/// Free DataIdentifier handle
#[no_mangle]
pub extern "C" fn data_id_free(handle: DataIdHandle) -> i32 {
    helper::catch_unwind_i32(|| {
        let _ = ffi_try!(unwrap!(object_cache())
            .data_id
            .remove(&handle)
            .ok_or(FfiError::InvalidDataIdHandle));

        0
    })
}

#[cfg(test)]
mod tests {
    use ffi::errors::FfiError;
    use ffi::low_level_api::object_cache::object_cache;
    use rand;
    use routing::XOR_NAME_LEN;
    use super::*;

    #[test]
    fn create_and_free() {
        let type_tag = rand::random();
        let struct_id_arr: [u8; XOR_NAME_LEN] = rand::random();

        let immut_id_arr: [u8; XOR_NAME_LEN] = rand::random();

        let priv_app_id_arr: [u8; XOR_NAME_LEN] = rand::random();
        let pub_app_id_arr: [u8; XOR_NAME_LEN] = rand::random();

        let mut data_id_handle_immut = 0;
        let mut data_id_handle_struct = 0;
        let mut data_id_handle_priv_appendable = 0;
        let mut data_id_handle_pub_appendable = 0;

        unsafe {
            assert_eq!(data_id_new_struct_data(type_tag,
                                               &struct_id_arr,
                                               &mut data_id_handle_struct),
                       0);
            assert_eq!(data_id_new_immut_data(&immut_id_arr, &mut data_id_handle_immut),
                       0);
            assert_eq!(data_id_new_appendable_data(&priv_app_id_arr,
                                                   true,
                                                   &mut data_id_handle_priv_appendable),
                       0);
            assert_eq!(data_id_new_appendable_data(&pub_app_id_arr,
                                                   false,
                                                   &mut data_id_handle_pub_appendable),
                       0);
        }

        {
            let mut obj_cache = unwrap!(object_cache());
            assert!(obj_cache.data_id.contains_key(&data_id_handle_struct));
            assert!(obj_cache.data_id.contains_key(&data_id_handle_immut));
            assert!(obj_cache.data_id.contains_key(&data_id_handle_priv_appendable));
            assert!(obj_cache.data_id.contains_key(&data_id_handle_pub_appendable));
        }

        assert_eq!(data_id_free(data_id_handle_struct), 0);
        assert_eq!(data_id_free(data_id_handle_immut), 0);
        assert_eq!(data_id_free(data_id_handle_priv_appendable), 0);
        assert_eq!(data_id_free(data_id_handle_pub_appendable), 0);

        let err_code = FfiError::InvalidDataIdHandle.into();
        assert_eq!(data_id_free(data_id_handle_struct), err_code);
        assert_eq!(data_id_free(data_id_handle_immut), err_code);
        assert_eq!(data_id_free(data_id_handle_priv_appendable), err_code);
        assert_eq!(data_id_free(data_id_handle_pub_appendable), err_code);

        {
            let mut obj_cache = unwrap!(object_cache());
            assert!(!obj_cache.data_id.contains_key(&data_id_handle_struct));
            assert!(!obj_cache.data_id.contains_key(&data_id_handle_immut));
            assert!(!obj_cache.data_id.contains_key(&data_id_handle_priv_appendable));
            assert!(!obj_cache.data_id.contains_key(&data_id_handle_pub_appendable));
        }
    }
}
