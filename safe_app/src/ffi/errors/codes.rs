// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

#![allow(missing_docs)]

// These error codes are positive so as not to conflict with the shared error codes, which are
// negative.
pub const ERR_INVALID_CIPHER_OPT_HANDLE: i32 = 1;
pub const ERR_INVALID_ENCRYPT_PUB_KEY_HANDLE: i32 = 2;
pub const ERR_INVALID_MDATA_INFO_HANDLE: i32 = 3;
pub const ERR_INVALID_MDATA_ENTRIES_HANDLE: i32 = 4;
pub const ERR_INVALID_MDATA_ENTRY_ACTIONS_HANDLE: i32 = 5;
pub const ERR_INVALID_MDATA_PERMISSIONS_HANDLE: i32 = 6;
pub const ERR_INVALID_MDATA_PERMISSION_SET_HANDLE: i32 = 7;
pub const ERR_INVALID_SELF_ENCRYPTOR_HANDLE: i32 = 8;
pub const ERR_INVALID_SIGN_PUB_KEY_HANDLE: i32 = 9;
pub const ERR_INVALID_SELF_ENCRYPTOR_READ_OFFSETS: i32 = 10;
pub const ERR_INVALID_ENCRYPT_SEC_KEY_HANDLE: i32 = 11;
pub const ERR_INVALID_FILE_CONTEXT_HANDLE: i32 = 12;
pub const ERR_INVALID_FILE_MODE: i32 = 13;
pub const ERR_INVALID_SIGN_SEC_KEY_HANDLE: i32 = 14;
pub const ERR_UNREGISTERED_CLIENT_ACCESS: i32 = 15;
pub const ERR_INVALID_PUB_KEY_HANDLE: i32 = 16;
