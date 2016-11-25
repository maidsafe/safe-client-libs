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

use core::CoreError;
use ffi::{App, CipherOptHandle, EncryptKeyHandle, FfiError, OpaqueCtx, Session, helper};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use rust_sodium::crypto::{box_, sealedbox, secretbox};
use std::os::raw::c_void;

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
                let cipher_text = secretbox::seal(plain_text, &nonce, &sym_key);
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
        if raw_data.is_empty() {
            return Ok(Vec::new());
        }

        match deserialise::<WireFormat>(raw_data)? {
            WireFormat::Plain(plain_text) => Ok(plain_text),
            WireFormat::Symmetric { nonce, cipher_text } => {
                let sym_key = app.sym_key()?;
                Ok(try!(secretbox::open(&cipher_text, &nonce, &sym_key)
                    .map_err(|()| CoreError::SymmetricDecipherFailure)))
            }
            WireFormat::Asymmetric(cipher_text) => {
                let (pk, sk) = app.asym_enc_keys()?;
                Ok(try!(sealedbox::open(&cipher_text, &pk, &sk)
                    .map_err(|()| CoreError::SymmetricDecipherFailure)))
            }
        }
    }
}

/// Construct CipherOpt::PlainText handle
#[no_mangle]
pub unsafe extern "C" fn cipher_opt_new_plaintext(session: *const Session,
                                                  user_data: *mut c_void,
                                                  o_cb: unsafe extern "C" fn(*mut c_void,
                                                                             i32,
                                                                             CipherOptHandle)) {
    let user_data = OpaqueCtx(user_data);

    helper::catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            let handle = obj_cache.insert_cipher_opt(CipherOpt::PlainText);
            o_cb(user_data.0, 0, handle);
            None
        })
    });
}

/// Construct CipherOpt::Symmetric handle
#[no_mangle]
pub unsafe extern "C" fn cipher_opt_new_symmetric(session: *const Session,
                                                  user_data: *mut c_void,
                                                  o_cb: unsafe extern "C" fn(*mut c_void,
                                                                             i32,
                                                                             CipherOptHandle)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        (*session).send(move |_, obj_cache| {
            let handle = obj_cache.insert_cipher_opt(CipherOpt::Symmetric);
            o_cb(user_data.0, 0, handle);
            None
        })
    })
}

/// Construct CipherOpt::Asymmetric handle
#[no_mangle]
pub unsafe extern "C" fn cipher_opt_new_asymmetric(session: *const Session,
                                                   peer_encrypt_key_h: EncryptKeyHandle,
                                                   user_data: *mut c_void,
                                                   o_cb: unsafe extern "C" fn(*mut c_void,
                                                                              i32,
                                                                              CipherOptHandle)) {
    let user_data = OpaqueCtx(user_data);

    helper::catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            let pk = match obj_cache.get_encrypt_key(peer_encrypt_key_h) {
                Ok(pk) => *pk,
                Err(e) => {
                    o_cb(user_data.0, ffi_error_code!(e), 0);
                    return None;
                }
            };
            let handle =
                obj_cache.insert_cipher_opt(CipherOpt::Asymmetric { peer_encrypt_key: pk });
            o_cb(user_data.0, 0, handle);
            None
        })
    });
}

/// Free CipherOpt handle
#[no_mangle]
pub unsafe extern "C" fn cipher_opt_free(session: *const Session,
                                         handle: CipherOptHandle,
                                         user_data: *mut c_void,
                                         o_cb: unsafe extern "C" fn(*mut c_void, i32)) {
    let user_data = OpaqueCtx(user_data);

    helper::catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            let res = obj_cache.remove_cipher_opt(handle);
            o_cb(user_data.0, ffi_result_code!(res));
            None
        })
    });
}

#[cfg(test)]
mod tests {
    use core::utility;
    use ffi::{App, CipherOptHandle, FfiError, Session};
    use ffi::test_utils;
    use rust_sodium::crypto::box_;
    use std::os::raw::c_void;
    use std::sync::mpsc;
    use super::*;

    fn decrypt_and_check(app: &App, raw_data: &[u8], orig_plain_text: &[u8]) -> bool {
        let plain_text_rx = match CipherOpt::decrypt(&app, &raw_data) {
            Ok(pt) => pt,
            Err(_) => return false,
        };
        orig_plain_text == &plain_text_rx[..]
    }

    #[test]
    fn app_0_to_app_0_plain() {
        let sess = test_utils::create_session();
        let app_0 = test_utils::create_app(&sess, false);

        let (tx, rx) = mpsc::channel::<Result<CipherOptHandle, i32>>();
        let tx = Box::into_raw(Box::new(tx.clone())) as *mut c_void;

        let plain_text = unwrap!(utility::generate_random_vector::<u8>(10));
        let cipher_opt_handle: CipherOptHandle;
        unsafe {
            cipher_opt_new_plaintext(&sess, tx, handle_cb);
            cipher_opt_handle = unwrap!(unwrap!(rx.recv()));
        }
        let (app_0, plain_text, cipher_text) = test_utils::run_now(&sess, move |_, obj_cache| {
            let cipher_opt = unwrap!(obj_cache.get_cipher_opt(cipher_opt_handle));
            let cipher_text = unwrap!(cipher_opt.encrypt(&app_0, &plain_text));
            (app_0, plain_text, cipher_text)
        });
        assert_free(&sess, cipher_opt_handle, 0);

        test_utils::run_now(&sess, move |_, obj_cache| {
            assert!(obj_cache.get_cipher_opt(cipher_opt_handle).is_err());
        });
        assert!(cipher_text != plain_text);

        assert!(decrypt_and_check(&app_0, &cipher_text, &plain_text));
    }

    #[test]
    fn app_0_to_app_0_sym() {
        let sess = test_utils::create_session();
        let app_0 = test_utils::create_app(&sess, false);

        let (tx, rx) = mpsc::channel::<Result<CipherOptHandle, i32>>();
        let tx = Box::into_raw(Box::new(tx.clone())) as *mut c_void;

        let plain_text = unwrap!(utility::generate_random_vector::<u8>(10));
        let cipher_opt_handle: CipherOptHandle;
        unsafe {
            cipher_opt_new_symmetric(&sess, tx, handle_cb);
            cipher_opt_handle = unwrap!(unwrap!(rx.recv()));
        }
        let (app_0, plain_text, cipher_text) = test_utils::run_now(&sess, move |_, obj_cache| {
            let cipher_opt = unwrap!(obj_cache.get_cipher_opt(cipher_opt_handle));
            let cipher_text = unwrap!(cipher_opt.encrypt(&app_0, &plain_text));
            (app_0, plain_text, cipher_text)
        });
        assert_free(&sess, cipher_opt_handle, 0);

        test_utils::run_now(&sess, move |_, obj_cache| {
            assert!(obj_cache.get_cipher_opt(cipher_opt_handle).is_err());
        });
        assert!(cipher_text != plain_text);

        assert!(decrypt_and_check(&app_0, &cipher_text, &plain_text));
    }

    #[test]
    fn app_0_to_app_1_asym() {
        // Setup
        let sess = test_utils::create_session();
        let app_0 = test_utils::create_app(&sess, false);
        let app_1 = test_utils::create_app(&sess, false);

        let (app_1, app_1_encrypt_key_handle) = test_utils::run_now(&sess, move |_, obj_cache| {
            let app_1_pub_encrypt_key = unwrap!(app_1.asym_enc_keys()).0;
            let encrypt_key_h = obj_cache.insert_encrypt_key(app_1_pub_encrypt_key);
            (app_1, encrypt_key_h)
        });

        let (tx, rx) = mpsc::channel::<Result<CipherOptHandle, i32>>();
        let tx = Box::into_raw(Box::new(tx.clone())) as *mut c_void;

        // Test
        // At app-0 end
        let plain_text = unwrap!(utility::generate_random_vector::<u8>(10));
        let cipher_opt_handle: CipherOptHandle;
        unsafe {
            cipher_opt_new_asymmetric(&sess, app_1_encrypt_key_handle, tx, handle_cb);
            cipher_opt_handle = unwrap!(unwrap!(rx.recv()));
        }

        let (app_0, plain_text, cipher_text) = test_utils::run_now(&sess, move |_, obj_cache| {
            let cipher_opt = unwrap!(obj_cache.get_cipher_opt(cipher_opt_handle));
            let cipher_text = unwrap!(cipher_opt.encrypt(&app_0, &plain_text));
            (app_0, plain_text, cipher_text)
        });
        assert_free(&sess, cipher_opt_handle, 0);

        test_utils::run_now(&sess, move |_, obj_cache| {
            assert!(obj_cache.get_cipher_opt(cipher_opt_handle).is_err());
        });
        assert!(cipher_text != plain_text);

        assert!(!decrypt_and_check(&app_0, &cipher_text, &plain_text));
        assert!(decrypt_and_check(&app_1, &cipher_text, &plain_text));
    }

    #[test]
    fn create_and_free() {
        let sess = test_utils::create_session();

        let peer_encrypt_key_handle = test_utils::run_now(&sess, |_, obj_cache| {
            let (pk, _) = box_::gen_keypair();
            obj_cache.insert_encrypt_key(pk)
        });

        let (tx, rx) = mpsc::channel::<Result<CipherOptHandle, i32>>();
        let tx = Box::into_raw(Box::new(tx.clone())) as *mut c_void;

        let cipher_opt_handle_pt;
        let cipher_opt_handle_sym;
        let cipher_opt_handle_asym;

        unsafe {
            cipher_opt_new_plaintext(&sess, tx, handle_cb);
            cipher_opt_handle_pt = unwrap!(unwrap!(rx.recv()));

            cipher_opt_new_symmetric(&sess, tx, handle_cb);
            cipher_opt_handle_sym = unwrap!(unwrap!(rx.recv()));

            let err_code = FfiError::InvalidEncryptKeyHandle.into();
            cipher_opt_new_asymmetric(&sess, 29293290, tx, handle_cb);
            let res = unwrap!(rx.recv());
            assert!(res.is_err());
            assert_eq!(unwrap!(res.err()), err_code);

            cipher_opt_new_asymmetric(&sess, peer_encrypt_key_handle, tx, handle_cb);
            cipher_opt_handle_asym = unwrap!(unwrap!(rx.recv()));
        }

        test_utils::run_now(&sess, move |_, obj_cache| {
            let _ = unwrap!(obj_cache.get_cipher_opt(cipher_opt_handle_pt));
            let _ = unwrap!(obj_cache.get_cipher_opt(cipher_opt_handle_sym));
            let _ = unwrap!(obj_cache.get_cipher_opt(cipher_opt_handle_asym));
        });

        assert_free(&sess, cipher_opt_handle_pt, 0);
        assert_free(&sess, cipher_opt_handle_sym, 0);
        assert_free(&sess, cipher_opt_handle_asym, 0);

        let err_code = FfiError::InvalidCipherOptHandle.into();
        assert_free(&sess, cipher_opt_handle_pt, err_code);
        assert_free(&sess, cipher_opt_handle_sym, err_code);
        assert_free(&sess, cipher_opt_handle_asym, err_code);

        test_utils::run_now(&sess, move |_, obj_cache| {
            assert!(obj_cache.get_cipher_opt(cipher_opt_handle_pt).is_err());
            assert!(obj_cache.get_cipher_opt(cipher_opt_handle_sym).is_err());
            assert!(obj_cache.get_cipher_opt(cipher_opt_handle_asym).is_err());
        })
    }

    fn assert_free(sess_ptr: *const Session, cipher_opt_handle: CipherOptHandle, expected: i32) {
        let res = unsafe {
            test_utils::call_0(|user_data, cb| {
                cipher_opt_free(sess_ptr, cipher_opt_handle, user_data, cb)
            })
        };
        match res {
            Ok(()) => assert_eq!(expected, 0),
            Err(code) => assert_eq!(expected, code),
        }
    }

    unsafe extern "C" fn handle_cb(tx: *mut c_void, error_code: i32, handle: CipherOptHandle) {
        let tx = tx as *mut mpsc::Sender<Result<CipherOptHandle, i32>>;
        let res = if error_code == 0 {
            Ok(handle)
        } else {
            Err(error_code)
        };
        unwrap!((*tx).send(res));
    }
}
