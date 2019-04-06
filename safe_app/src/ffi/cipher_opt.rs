// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::cipher_opt::CipherOpt;
use crate::ffi::object_cache::{CipherOptHandle, EncryptPubKeyHandle};
use ffi_utils::{catch_unwind_cb, FfiResult, OpaqueCtx, FFI_RESULT_OK};
use std::os::raw::c_void;
use crate::App;

/// Construct `CipherOpt::PlainText` handle.
#[no_mangle]
pub unsafe extern "C" fn cipher_opt_new_plaintext(
    app: *const App,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, handle: CipherOptHandle),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*app).send(move |_, context| {
            let handle = context
                .object_cache()
                .insert_cipher_opt(CipherOpt::PlainText);
            o_cb(user_data.0, FFI_RESULT_OK, handle);
            None
        })
    });
}

/// Construct `CipherOpt::Symmetric` handle.
#[no_mangle]
pub unsafe extern "C" fn cipher_opt_new_symmetric(
    app: *const App,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, handle: CipherOptHandle),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        (*app).send(move |_, context| {
            let handle = context
                .object_cache()
                .insert_cipher_opt(CipherOpt::Symmetric);
            o_cb(user_data.0, FFI_RESULT_OK, handle);
            None
        })
    })
}

/// Construct `CipherOpt::Asymmetric` handle.
#[no_mangle]
pub unsafe extern "C" fn cipher_opt_new_asymmetric(
    app: *const App,
    peer_encrypt_key_h: EncryptPubKeyHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, handle: CipherOptHandle),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*app).send(move |_, context| {
            let pk = try_cb!(
                context.object_cache().get_encrypt_key(peer_encrypt_key_h),
                user_data,
                o_cb
            );
            let handle = context
                .object_cache()
                .insert_cipher_opt(CipherOpt::Asymmetric {
                    peer_encrypt_key: *pk,
                });
            o_cb(user_data.0, FFI_RESULT_OK, handle);
            None
        })
    });
}

/// Free `CipherOpt` handle.
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
    use crate::client::AppClient;
    use crate::errors::AppError;
    use crate::ffi::object_cache::CipherOptHandle;
    use ffi_utils::test_utils::{call_0, call_1};
    use ffi_utils::ErrorCode;
    use rust_sodium::crypto::box_;
    use safe_core::{utils, Client};
    use crate::test_utils::{create_app, run_now};
    use crate::{App, AppContext};

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

            unwrap!(call_1(|ud, cb| cipher_opt_new_asymmetric(
                &app,
                peer_encrypt_key_handle,
                ud,
                cb
            )))
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
        client: &AppClient,
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
            call_0(|user_data, cb| cipher_opt_free(app_ptr, cipher_opt_handle, user_data, cb))
        };
        match res {
            Ok(()) => assert_eq!(expected, 0),
            Err(code) => assert_eq!(expected, code),
        }
    }
}
