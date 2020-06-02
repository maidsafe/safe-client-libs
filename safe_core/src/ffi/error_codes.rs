// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

#![allow(missing_docs)]

// Core errors
pub const ERR_ENCODE_DECODE_ERROR: i32 = -1;
pub const ERR_ASYMMETRIC_DECIPHER_FAILURE: i32 = -2;
pub const ERR_SYMMETRIC_DECIPHER_FAILURE: i32 = -3;
pub const ERR_RECEIVED_UNEXPECTED_DATA: i32 = -4;
pub const ERR_RECEIVED_UNEXPECTED_EVENT: i32 = -5;
pub const ERR_VERSION_CACHE_MISS: i32 = -6;
pub const ERR_ROOT_DIRECTORY_EXISTS: i32 = -7;
pub const ERR_RANDOM_DATA_GENERATION_FAILURE: i32 = -8;
pub const ERR_OPERATION_FORBIDDEN: i32 = -9;
pub const ERR_UNSUPPORTED_SALT_SIZE_FOR_PW_HASH: i32 = -10;
pub const ERR_UNSUCCESSFUL_PW_HASH: i32 = -11;
pub const ERR_OPERATION_ABORTED: i32 = -12;
pub const ERR_SELF_ENCRYPTION: i32 = -13;
pub const ERR_REQUEST_TIMEOUT: i32 = -14;
pub const ERR_CONFIG_FILE: i32 = -15;
pub const ERR_IO: i32 = -16;

// Data type errors
pub const ERR_ACCESS_DENIED: i32 = -100;
pub const ERR_NO_SUCH_DATA: i32 = -101;
pub const ERR_DATA_EXISTS: i32 = -102;
pub const ERR_NO_SUCH_ENTRY: i32 = -103;
pub const ERR_TOO_MANY_ENTRIES: i32 = -104;
pub const ERR_NO_SUCH_KEY: i32 = -105;
pub const ERR_INVALID_OWNERS: i32 = -106;
pub const ERR_INVALID_SUCCESSOR: i32 = -107;
pub const ERR_INVALID_OPERATION: i32 = -108;
pub const ERR_NETWORK_OTHER: i32 = -109;
pub const ERR_INVALID_ENTRY_ACTIONS: i32 = -110;
pub const ERR_DUPLICATE_MSG_ID: i32 = -111;
pub const ERR_DUPLICATE_ENTRY_KEYS: i32 = -112;
pub const ERR_KEYS_EXIST: i32 = -113;

// IPC errors.
pub const ERR_AUTH_DENIED: i32 = -200;
pub const ERR_CONTAINERS_DENIED: i32 = -201;
pub const ERR_INVALID_MSG: i32 = -202;
pub const ERR_ALREADY_AUTHORISED: i32 = -203;
pub const ERR_UNKNOWN_APP: i32 = -204;
pub const ERR_STRING_ERROR: i32 = -205;
pub const ERR_SHARE_MDATA_DENIED: i32 = -206;
pub const ERR_INVALID_OWNER: i32 = -207;
pub const ERR_INCOMPATIBLE_MOCK_STATUS: i32 = -208;

// NFS errors.
pub const ERR_FILE_EXISTS: i32 = -300;
pub const ERR_FILE_NOT_FOUND: i32 = -301;
pub const ERR_INVALID_RANGE: i32 = -302;

// IO error.
pub const ERR_IO_ERROR: i32 = -1013;

// Authenticator errors.
pub const ERR_NO_SUCH_CONTAINER: i32 = -1014;

// Unexpected error.
pub const ERR_UNEXPECTED: i32 = -2000;

// Identity & permission errors.
pub const ERR_INVALID_OWNERS_SUCCESSOR: i32 = -3001;
pub const ERR_INVALID_PERMISSIONS_SUCCESSOR: i32 = -3002;
pub const ERR_SIGN_KEYTYPE_MISMATCH: i32 = -3003;
pub const ERR_INVALID_SIGNATURE: i32 = -3004;

// Coin errors.
pub const ERR_LOSS_OF_PRECISION: i32 = -4000;
pub const ERR_EXCESSIVE_VALUE: i32 = -4001;
pub const ERR_FAILED_TO_PARSE: i32 = -4002;
pub const ERR_TRANSACTION_ID_EXISTS: i32 = -4003;
pub const ERR_INSUFFICIENT_BALANCE: i32 = -4004;
pub const ERR_BALANCE_EXISTS: i32 = -4005;
pub const ERR_NO_SUCH_BALANCE: i32 = -4006;
pub const ERR_NO_SUCH_SENDER: i32 = -4007;
pub const ERR_NO_SUCH_RECIPIENT: i32 = -4008;

// Login packet errors.
pub const ERR_EXCEEDED_SIZE: i32 = -5001;
pub const ERR_NO_SUCH_LOGIN_PACKET: i32 = -5002;
pub const ERR_LOGIN_PACKET_EXISTS: i32 = -5003;

// QuicP2P errors.
pub const ERR_QUIC_P2P: i32 = -6000;
