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

use {App, AppContext};
use errors::AppError;
use ffi::object_cache::{CipherOptHandle, EncryptPubKeyHandle};
use ffi_utils::{FFI_RESULT_OK, FfiResult, OpaqueCtx, catch_unwind_cb};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use rust_sodium::crypto::{box_, sealedbox, secretbox};
use safe_core::{Client, CoreError};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub fn encrypt(&self, plain_text: &[u8], app_ctx: &AppContext) -> Result<Vec<u8>, AppError> {
        match *self {
            CipherOpt::PlainText => Ok(serialise(&WireFormat::Plain(plain_text.to_owned()))?),
            CipherOpt::Symmetric => {
                let nonce = secretbox::gen_nonce();
                let cipher_text = secretbox::seal(plain_text, &nonce, app_ctx.sym_enc_key()?);
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
    pub fn decrypt(
        cipher_text: &[u8],
        app_ctx: &AppContext,
        client: &Client<AppContext>,
    ) -> Result<Vec<u8>, AppError> {
        if cipher_text.is_empty() {
            return Ok(Vec::new());
        }

        match deserialise::<WireFormat>(cipher_text)? {
            WireFormat::Plain(plain_text) => Ok(plain_text),
            WireFormat::Symmetric { nonce, cipher_text } => {
                Ok(secretbox::open(&cipher_text, &nonce, app_ctx.sym_enc_key()?)
                    .map_err(|()| CoreError::SymmetricDecipherFailure)?)
            }
            WireFormat::Asymmetric(cipher_text) => {
                let (asym_pk, asym_sk) = client.encryption_keypair()?;
                Ok(sealedbox::open(&cipher_text, &asym_pk, &asym_sk)
                    .map_err(|()| CoreError::AsymmetricDecipherFailure)?)
            }
        }
    }
}

/// Construct `CipherOpt::PlainText` handle.
///
/// Callback parameters: user data, error code, cipher opt handle
#[no_mangle]
pub unsafe extern "C" fn cipher_opt_new_plaintext(
    app: *const App,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void,
                        result: *const FfiResult,
                        handle: CipherOptHandle),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*app).send(move |_, context| {
            let handle = context.object_cache().insert_cipher_opt(
                CipherOpt::PlainText,
            );
            o_cb(user_data.0, FFI_RESULT_OK, handle);
            None
        })
    });
}

/// Construct `CipherOpt::Symmetric` handle.
///
/// Callback parameters: user data, error code, cipher opt handle
#[no_mangle]
pub unsafe extern "C" fn cipher_opt_new_symmetric(
    app: *const App,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void,
                        result: *const FfiResult,
                        handle: CipherOptHandle),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        (*app).send(move |_, context| {
            let handle = context.object_cache().insert_cipher_opt(
                CipherOpt::Symmetric,
            );
            o_cb(user_data.0, FFI_RESULT_OK, handle);
            None
        })
    })
}

/// Construct `CipherOpt::Asymmetric` handle.
///
/// Callback parameters: user data, error code, cipher opt handle
#[no_mangle]
pub unsafe extern "C" fn cipher_opt_new_asymmetric(
    app: *const App,
    peer_encrypt_key_h: EncryptPubKeyHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void,
                        result: *const FfiResult,
                        handle: CipherOptHandle),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*app).send(move |_, context| {
            let pk = try_cb!(
                context.object_cache().get_encrypt_key(peer_encrypt_key_h),
                user_data,
                o_cb
            );
            let handle = context.object_cache().insert_cipher_opt(
                CipherOpt::Asymmetric {
                    peer_encrypt_key: *pk,
                },
            );
            o_cb(user_data.0, FFI_RESULT_OK, handle);
            None
        })
    });
}

/// Free `CipherOpt` handle.
///
/// Callback parameters: user data, error code
#[no_mangle]
pub unsafe extern "C" fn cipher_opt_free(
    app: *const App,
    handle: CipherOptHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*app).send(move |_, context| {
            let res = context.object_cache().remove_cipher_opt(handle);
            call_result_cb!(res, user_data, o_cb);
            None
        })
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use {App, AppContext};
    use errors::AppError;
    use ffi::object_cache::CipherOptHandle;
    use ffi_utils::ErrorCode;
    use ffi_utils::test_utils::{call_0, call_1};
    use rust_sodium::crypto::box_;
    use safe_core::{Client, utils};
    use test_utils::{create_app, run_now};

    // Test plaintext "encryption" and decryption.
    #[test]
    fn app_0_to_app_0_plain() {
        let app_0 = create_app();
        let plain_text = unwrap!(utils::generate_random_vector::<u8>(10));

        let cipher_opt_handle: CipherOptHandle =
            unsafe { unwrap!(call_1(|ud, cb| cipher_opt_new_plaintext(&app_0, ud, cb))) };

        let (plain_text, cipher_text) = run_now(&app_0, move |_, context| {
            let cipher_opt = unwrap!(context.object_cache().get_cipher_opt(cipher_opt_handle));
            let cipher_text = unwrap!(cipher_opt.encrypt(&plain_text, context));
            (plain_text, cipher_text)
        });
        assert_ne!(cipher_text, plain_text);
        assert_free(&app_0, cipher_opt_handle, 0);

        run_now(&app_0, move |client, context| {
            assert!(
                context
                    .object_cache()
                    .get_cipher_opt(cipher_opt_handle)
                    .is_err()
            );
            assert!(decrypt_and_check(
                client,
                context,
                &cipher_text,
                &plain_text,
            ));
        });
    }

    // Test symmetric encryption and decryption.
    #[test]
    fn app_0_to_app_0_sym() {
        let app_0 = create_app();

        let plain_text = unwrap!(utils::generate_random_vector::<u8>(10));
        let cipher_opt_handle: CipherOptHandle =
            unsafe { unwrap!(call_1(|ud, cb| cipher_opt_new_symmetric(&app_0, ud, cb))) };

        let (plain_text, cipher_text) = run_now(&app_0, move |_, context| {
            let cipher_opt = unwrap!(context.object_cache().get_cipher_opt(cipher_opt_handle));
            let cipher_text = unwrap!(cipher_opt.encrypt(&plain_text, context));
            (plain_text, cipher_text)
        });
        assert_ne!(cipher_text, plain_text);
        assert_free(&app_0, cipher_opt_handle, 0);

        run_now(&app_0, move |client, context| {
            assert!(
                context
                    .object_cache()
                    .get_cipher_opt(cipher_opt_handle)
                    .is_err()
            );
            assert!(decrypt_and_check(
                client,
                context,
                &cipher_text,
                &plain_text,
            ));
        });
    }

    // Test asymmetric encryption and decryption.
    // NOTE: rustfmt is behaving erratically on this function. Disabling it for now.
    #[cfg_attr(rustfmt, rustfmt_skip)]
    #[test]
    fn app_0_to_app_1_asym() {
        // Setup
        let app_0 = create_app();
        let app_1 = create_app();

        // Get encryption public key of App 1.
        let enc_pk = run_now(&app_1,
                             move |client, _| unwrap!(client.public_encryption_key()));

        // Insert it into App 0's object cache.
        let enc_pk_h = run_now(&app_0, move |_, context| {
            context.object_cache().insert_encrypt_key(enc_pk)
        });

        // Create asymmetric cypher opt on App 0's end.
        let cipher_opt_h = unsafe {
            unwrap!(call_1(|ud, cb| cipher_opt_new_asymmetric(&app_0, enc_pk_h, ud, cb)))
        };

        // Encrypt the plaintext on App 0's end.
        let plain_text = unwrap!(utils::generate_random_vector::<u8>(10));
        let (plain_text, cipher_text) = run_now(&app_0, move |_, context| {
            let cipher_opt = unwrap!(context.object_cache().get_cipher_opt(cipher_opt_h));
            let cipher_text = unwrap!(cipher_opt.encrypt(&plain_text, context));
            (plain_text, cipher_text)
        });

        assert_ne!(cipher_text, plain_text);
        assert_free(&app_0, cipher_opt_h, 0);

        run_now(&app_0, move |_, context| {
            assert!(context.object_cache().get_cipher_opt(cipher_opt_h).is_err());
        });

        // App 0 cannot decrypt the ciphertext, because it was encrypted with
        // App 1's public key.
        let (plain_text, cipher_text) = run_now(&app_0, move |client, context| {
            assert!(!decrypt_and_check(client, context, &cipher_text, &plain_text));
            (plain_text, cipher_text)
        });

        // App 1 can decrypt it.
        run_now(&app_1, move |client, context| {
            assert!(decrypt_and_check(client, context, &cipher_text, &plain_text));
        });
    }

    // Test creating and freeing the different possible cipher option handles.
    #[test]
    fn create_and_free() {
        let app = create_app();

        let peer_encrypt_key_handle = run_now(&app, |_, context| {
            let (pk, _) = box_::gen_keypair();
            context.object_cache().insert_encrypt_key(pk)
        });

        let cipher_opt_handle_pt =
            unsafe { unwrap!(call_1(|ud, cb| cipher_opt_new_plaintext(&app, ud, cb))) };
        let cipher_opt_handle_sym =
            unsafe { unwrap!(call_1(|ud, cb| cipher_opt_new_symmetric(&app, ud, cb))) };
        let cipher_opt_handle_asym = unsafe {
            let err_code = AppError::InvalidEncryptPubKeyHandle.error_code();
            let res: Result<CipherOptHandle, _> =
                call_1(|ud, cb| cipher_opt_new_asymmetric(&app, 29_293_290, ud, cb));
            assert_eq!(unwrap!(res.err()), err_code);

            unwrap!(call_1(|ud, cb| {
                cipher_opt_new_asymmetric(&app, peer_encrypt_key_handle, ud, cb)
            }))
        };

        run_now(&app, move |_, context| {
            let obj_cache = context.object_cache();
            let _ = unwrap!(obj_cache.get_cipher_opt(cipher_opt_handle_pt));
            let _ = unwrap!(obj_cache.get_cipher_opt(cipher_opt_handle_sym));
            let _ = unwrap!(obj_cache.get_cipher_opt(cipher_opt_handle_asym));
        });

        assert_free(&app, cipher_opt_handle_pt, 0);
        assert_free(&app, cipher_opt_handle_sym, 0);
        assert_free(&app, cipher_opt_handle_asym, 0);

        let err_code = AppError::InvalidCipherOptHandle.error_code();
        assert_free(&app, cipher_opt_handle_pt, err_code);
        assert_free(&app, cipher_opt_handle_sym, err_code);
        assert_free(&app, cipher_opt_handle_asym, err_code);

        run_now(&app, move |_, context| {
            let obj_cache = context.object_cache();
            assert!(obj_cache.get_cipher_opt(cipher_opt_handle_pt).is_err());
            assert!(obj_cache.get_cipher_opt(cipher_opt_handle_sym).is_err());
            assert!(obj_cache.get_cipher_opt(cipher_opt_handle_asym).is_err());
        })
    }

    fn decrypt_and_check(
        client: &Client<AppContext>,
        context: &AppContext,
        cipher_text: &[u8],
        orig_plain_text: &[u8],
    ) -> bool {
        let plain_text = match CipherOpt::decrypt(cipher_text, context, client) {
            Ok(text) => text,
            Err(_) => return false,
        };

        orig_plain_text == &plain_text[..]
    }

    fn assert_free(app_ptr: *const App, cipher_opt_handle: CipherOptHandle, expected: i32) {
        let res = unsafe {
            call_0(|user_data, cb| {
                cipher_opt_free(app_ptr, cipher_opt_handle, user_data, cb)
            })
        };
        match res {
            Ok(()) => assert_eq!(expected, 0),
            Err(code) => assert_eq!(expected, code),
        }
    }
}
