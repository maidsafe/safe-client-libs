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

use super::{CipherOptHandle, EncryptKeyHandle};
use super::object_cache::object_cache;
use core::errors::CoreError;
use ffi::app::App;
use ffi::errors::FfiError;
use ffi::helper;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use rust_sodium::crypto::{box_, sealedbox, secretbox};
use std::ptr;

/// Cipher Options
#[derive(Debug)]
pub enum CipherOpt {
    /// No encryption
    PlainText,
    /// Encrypt using symmetric keys (usually for private data)
    Symmetric,
    /// Encrypt using asymmetric encryption (encrypting for peer to read)
    Asymmetric {
        /// PublicKey of the peer to whom we want to encrypt
        peer_encrypt_key: box_::PublicKey,
    },
}

#[derive(Debug, Clone, RustcEncodable, RustcDecodable)]
enum WireFormat {
    Plain(Vec<u8>),
    Symmetric {
        nonce: secretbox::Nonce,
        cipher_text: Vec<u8>,
    },
    Asymmetric(Vec<u8>),
}

impl CipherOpt {
    /// Encrypt plain text
    pub fn encrypt(&self, app: &App, plain_text: &[u8]) -> Result<Vec<u8>, FfiError> {
        match *self {
            CipherOpt::PlainText => Ok(serialise(&WireFormat::Plain(plain_text.to_owned()))?),
            CipherOpt::Symmetric => {
                let sym_key = app.sym_key()?;
                let nonce = secretbox::gen_nonce();
                let cipher_text = secretbox::seal(plain_text, &nonce, sym_key);
                let wire_format = WireFormat::Symmetric {
                    nonce: nonce,
                    cipher_text: cipher_text,
                };

                Ok(serialise(&wire_format)?)
            }
            CipherOpt::Asymmetric { ref peer_encrypt_key } => {
                let cipher_text = sealedbox::seal(plain_text, peer_encrypt_key);
                Ok(serialise(&WireFormat::Asymmetric(cipher_text))?)
            }
        }
    }

    /// Decrypt something encrypted by CipherOpt::encrypt()
    pub fn decrypt(app: &App, raw_data: &[u8]) -> Result<Vec<u8>, FfiError> {
        match deserialise::<WireFormat>(raw_data)? {
            WireFormat::Plain(plain_text) => Ok(plain_text),
            WireFormat::Symmetric { nonce, cipher_text } => {
                let sym_key = app.sym_key()?;
                Ok(try!(secretbox::open(&cipher_text, &nonce, sym_key)
                    .map_err(|()| CoreError::SymmetricDecipherFailure)))
            }
            WireFormat::Asymmetric(cipher_text) => {
                let &(ref pk, ref sk) = app.asym_keys()?;
                Ok(try!(sealedbox::open(&cipher_text, pk, sk)
                    .map_err(|()| CoreError::SymmetricDecipherFailure)))
            }
        }
    }
}

/// Construct `CipherOpt::PlainText` handle
#[no_mangle]
#[cfg_attr(rustfmt, rustfmt_skip)]
pub unsafe extern "C" fn cipher_opt_new_plaintext(o_handle: *mut CipherOptHandle) -> i32 {
    helper::catch_unwind_i32(|| {
        let handle = unwrap!(object_cache()).insert_cipher_opt(CipherOpt::PlainText);
        ptr::write(o_handle, handle);

        0
    })
}

/// Construct `CipherOpt::Symmetric` handle
#[no_mangle]
#[cfg_attr(rustfmt, rustfmt_skip)]
pub unsafe extern "C" fn cipher_opt_new_symmetric(o_handle: *mut CipherOptHandle) -> i32 {
    helper::catch_unwind_i32(|| {
        let handle = unwrap!(object_cache()).insert_cipher_opt(CipherOpt::Symmetric);
        ptr::write(o_handle, handle);

        0
    })
}

/// Construct `CipherOpt::Asymmetric` handle
#[no_mangle]
pub unsafe extern "C" fn cipher_opt_new_asymmetric(peer_encrypt_key_h: EncryptKeyHandle,
                                                   o_handle: *mut CipherOptHandle)
                                                   -> i32 {
    helper::catch_unwind_i32(|| {
        let mut obj_cache = unwrap!(object_cache());
        let pk = *ffi_try!(obj_cache.get_encrypt_key(peer_encrypt_key_h));
        let handle = obj_cache.insert_cipher_opt(CipherOpt::Asymmetric { peer_encrypt_key: pk });
        ptr::write(o_handle, handle);

        0
    })
}

/// Free `CipherOpt` handle
#[no_mangle]
#[cfg_attr(rustfmt, rustfmt_skip)]
pub extern "C" fn cipher_opt_free(handle: CipherOptHandle) -> i32 {
    helper::catch_unwind_i32(|| {
        let _ = ffi_try!(unwrap!(object_cache()).remove_cipher_opt(handle));
        0
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::utility;
    use ffi::app::App;
    use ffi::errors::FfiError;
    use ffi::low_level_api::CipherOptHandle;
    use ffi::low_level_api::object_cache::object_cache;
    use ffi::test_utils;
    use rust_sodium::crypto::box_;

    fn decrypt_and_check(app: &App, raw_data: &[u8], orig_plain_text: &[u8]) -> bool {
        let plain_text_rx = match CipherOpt::decrypt(app, raw_data) {
            Ok(pt) => pt,
            Err(_) => return false,
        };
        orig_plain_text == &plain_text_rx[..]
    }

    #[test]
    fn app_0_to_app_0_plain() {
        let app_0 = test_utils::create_app(false);
        let plain_text = unwrap!(utility::generate_random_vector::<u8>(10));
        let mut cipher_opt_handle: CipherOptHandle = 0;
        unsafe {
            assert_eq!(cipher_opt_new_plaintext(&mut cipher_opt_handle), 0);
        }
        let raw_data = {
            let mut obj_cache = unwrap!(object_cache());
            let cipher_opt = unwrap!(obj_cache.get_cipher_opt(cipher_opt_handle));
            unwrap!(cipher_opt.encrypt(&app_0, &plain_text))
        };
        assert_eq!(cipher_opt_free(cipher_opt_handle), 0);
        assert!(unwrap!(object_cache())
                    .get_cipher_opt(cipher_opt_handle)
                    .is_err());
        assert!(raw_data != plain_text);

        assert!(decrypt_and_check(&app_0, &raw_data, &plain_text));
    }

    #[test]
    fn app_0_to_app_0_sym() {
        let app_0 = test_utils::create_app(false);
        let plain_text = unwrap!(utility::generate_random_vector::<u8>(10));
        let mut cipher_opt_handle: CipherOptHandle = 0;
        unsafe {
            assert_eq!(cipher_opt_new_symmetric(&mut cipher_opt_handle), 0);
        }
        let raw_data = {
            let mut obj_cache = unwrap!(object_cache());
            let cipher_opt = unwrap!(obj_cache.get_cipher_opt(cipher_opt_handle));
            unwrap!(cipher_opt.encrypt(&app_0, &plain_text))
        };
        assert_eq!(cipher_opt_free(cipher_opt_handle), 0);
        assert!(unwrap!(object_cache())
                    .get_cipher_opt(cipher_opt_handle)
                    .is_err());
        assert!(raw_data != plain_text);

        assert!(decrypt_and_check(&app_0, &raw_data, &plain_text));
    }

    #[test]
    fn app_0_to_app_1_asym() {
        // Setup
        let app_0 = test_utils::create_app(false);
        let app_1 = test_utils::create_app(false);

        let app_1_encrypt_key_handle = {
            let mut obj_cache = unwrap!(object_cache());
            let app_1_pub_encrypt_key = unwrap!(app_1.asym_keys()).0;
            obj_cache.insert_encrypt_key(app_1_pub_encrypt_key)
        };

        // Test
        // At app-0 end
        let plain_text = unwrap!(utility::generate_random_vector::<u8>(10));
        let mut cipher_opt_handle: CipherOptHandle = 0;
        unsafe {
            assert_eq!(cipher_opt_new_asymmetric(app_1_encrypt_key_handle, &mut cipher_opt_handle),
                       0);
        }

        let raw_data = {
            let mut obj_cache = unwrap!(object_cache());
            let cipher_opt = unwrap!(obj_cache.get_cipher_opt(cipher_opt_handle));
            unwrap!(cipher_opt.encrypt(&app_0, &plain_text))
        };
        assert_eq!(cipher_opt_free(cipher_opt_handle), 0);
        assert!(unwrap!(object_cache())
                    .get_cipher_opt(cipher_opt_handle)
                    .is_err());
        assert!(raw_data != plain_text);

        assert!(!decrypt_and_check(&app_0, &raw_data, &plain_text));
        assert!(decrypt_and_check(&app_1, &raw_data, &plain_text));
    }

    #[test]
    fn create_and_free() {
        let peer_encrypt_key_handle = {
            let (pk, _) = box_::gen_keypair();
            unwrap!(object_cache()).insert_encrypt_key(pk)
        };

        let mut cipher_opt_handle_pt = 0;
        let mut cipher_opt_handle_sym = 0;
        let mut cipher_opt_handle_asym = 0;

        unsafe {
            assert_eq!(cipher_opt_new_plaintext(&mut cipher_opt_handle_pt), 0);
            assert_eq!(cipher_opt_new_symmetric(&mut cipher_opt_handle_sym), 0);

            let err_code = FfiError::InvalidEncryptKeyHandle.into();
            assert_eq!(cipher_opt_new_asymmetric(29293290, &mut cipher_opt_handle_asym),
                       err_code);
            assert_eq!(cipher_opt_new_asymmetric(peer_encrypt_key_handle,
                                                 &mut cipher_opt_handle_asym),
                       0);
        }

        {
            let mut obj_cache = unwrap!(object_cache());
            let _ = unwrap!(obj_cache.get_cipher_opt(cipher_opt_handle_pt));
            let _ = unwrap!(obj_cache.get_cipher_opt(cipher_opt_handle_sym));
            let _ = unwrap!(obj_cache.get_cipher_opt(cipher_opt_handle_asym));
        }

        assert_eq!(cipher_opt_free(cipher_opt_handle_pt), 0);
        assert_eq!(cipher_opt_free(cipher_opt_handle_sym), 0);
        assert_eq!(cipher_opt_free(cipher_opt_handle_asym), 0);

        let err_code = FfiError::InvalidCipherOptHandle.into();
        assert_eq!(cipher_opt_free(cipher_opt_handle_pt), err_code);
        assert_eq!(cipher_opt_free(cipher_opt_handle_sym), err_code);
        assert_eq!(cipher_opt_free(cipher_opt_handle_asym), err_code);

        {
            let mut obj_cache = unwrap!(object_cache());
            assert!(obj_cache.get_cipher_opt(cipher_opt_handle_pt).is_err());
            assert!(obj_cache.get_cipher_opt(cipher_opt_handle_sym).is_err());
            assert!(obj_cache.get_cipher_opt(cipher_opt_handle_asym).is_err());
        }
    }
}
