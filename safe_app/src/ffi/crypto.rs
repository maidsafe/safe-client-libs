// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use errors::AppError;
use ffi::helper::send_sync;
use ffi::object_cache::{
    EncryptPubKeyHandle, EncryptSecKeyHandle, SignPubKeyHandle, SignSecKeyHandle,
    NULL_OBJECT_HANDLE,
};
use ffi_utils::{
    catch_unwind_cb, vec_clone_from_raw_parts, FfiResult, OpaqueCtx, SafePtr, FFI_RESULT_OK,
};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use rust_sodium::crypto::{box_, sealedbox, sign};
use safe_core::crypto::{shared_box, shared_sign};
use safe_core::ffi::arrays::{
    AsymNonce, AsymPublicKey, AsymSecretKey, SignPublicKey, SignSecretKey,
};
use safe_core::Client;
use std::os::raw::c_void;
use std::slice;
use tiny_keccak::sha3_256;
use App;

/// Special value that represents that a message should be signed by the app.
#[no_mangle]
pub static SIGN_WITH_APP: SignSecKeyHandle = NULL_OBJECT_HANDLE;

/// Get the public signing key of the app.
#[no_mangle]
pub unsafe extern "C" fn app_pub_sign_key(
    app: *const App,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, handle: SignPubKeyHandle),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |client, context| {
            let key = client
                .public_signing_key()
                .ok_or(AppError::UnregisteredClientAccess)?;
            Ok(context.object_cache().insert_pub_sign_key(key))
        })
    })
}

/// Generate a new sign key pair (public & private key).
#[no_mangle]
pub unsafe extern "C" fn sign_generate_key_pair(
    app: *const App,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        public_key_h: SignPubKeyHandle,
        secret_key_h: SignSecKeyHandle,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let (ourpk, oursk) = shared_sign::gen_keypair();
        let user_data = OpaqueCtx(user_data);

        (*app).send(move |_, context| {
            let pk_h = context.object_cache().insert_pub_sign_key(ourpk);
            let sk_h = context.object_cache().insert_sec_sign_key(oursk);

            o_cb(user_data.0, FFI_RESULT_OK, pk_h, sk_h);

            None
        })
    })
}

/// Create new public signing key from raw array.
#[no_mangle]
pub unsafe extern "C" fn sign_pub_key_new(
    app: *const App,
    data: *const SignPublicKey,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, handle: SignPubKeyHandle),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let key = sign::PublicKey(*data);
        send_sync(app, user_data, o_cb, move |_, context| {
            Ok(context.object_cache().insert_pub_sign_key(key))
        })
    })
}

/// Retrieve the public signing key as a raw array.
#[no_mangle]
pub unsafe extern "C" fn sign_pub_key_get(
    app: *const App,
    handle: SignPubKeyHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        pub_sign_key: *const SignPublicKey,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let key = context.object_cache().get_pub_sign_key(handle)?;
            Ok(&key.0)
        })
    })
}

/// Free public signing key from memory.
#[no_mangle]
pub unsafe extern "C" fn sign_pub_key_free(
    app: *const App,
    handle: SignPubKeyHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let _ = context.object_cache().remove_pub_sign_key(handle)?;
            Ok(())
        })
    })
}

/// Create new secret signing key from raw array.
#[no_mangle]
pub unsafe extern "C" fn sign_sec_key_new(
    app: *const App,
    data: *const SignSecretKey,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, handle: SignSecKeyHandle),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let key = shared_sign::SecretKey::from_raw(&*data);
        send_sync(app, user_data, o_cb, move |_, context| {
            Ok(context.object_cache().insert_sec_sign_key(key))
        })
    })
}

/// Retrieve the secret signing key as a raw array.
#[no_mangle]
pub unsafe extern "C" fn sign_sec_key_get(
    app: *const App,
    handle: SignSecKeyHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        pub_sign_key: *const SignSecretKey,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let key = context.object_cache().get_sec_sign_key(handle)?;
            Ok(&key.0)
        })
    })
}

/// Free secret signing key from memory.
#[no_mangle]
pub unsafe extern "C" fn sign_sec_key_free(
    app: *const App,
    handle: SignSecKeyHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let _ = context.object_cache().remove_sec_sign_key(handle)?;
            Ok(())
        })
    })
}

/// Get the public encryption key of the app.
#[no_mangle]
pub unsafe extern "C" fn app_pub_enc_key(
    app: *const App,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        public_key_h: EncryptPubKeyHandle,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |client, context| {
            let key = client
                .public_encryption_key()
                .ok_or(AppError::UnregisteredClientAccess)?;
            Ok(context.object_cache().insert_encrypt_key(key))
        })
    })
}

/// Generate a new encryption key pair (public & private key).
#[no_mangle]
pub unsafe extern "C" fn enc_generate_key_pair(
    app: *const App,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        public_key_h: EncryptPubKeyHandle,
        secret_key_h: EncryptSecKeyHandle,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let (ourpk, oursk) = shared_box::gen_keypair();
        let user_data = OpaqueCtx(user_data);

        (*app).send(move |_, context| {
            let pk_h = context.object_cache().insert_encrypt_key(ourpk);
            let sk_h = context.object_cache().insert_secret_key(oursk);

            o_cb(user_data.0, FFI_RESULT_OK, pk_h, sk_h);

            None
        })
    })
}

/// Create new public encryption key from raw array.
#[no_mangle]
pub unsafe extern "C" fn enc_pub_key_new(
    app: *const App,
    data: *const AsymPublicKey,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        public_key_h: EncryptPubKeyHandle,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let key = box_::PublicKey(*data);
        send_sync(app, user_data, o_cb, move |_, context| {
            Ok(context.object_cache().insert_encrypt_key(key))
        })
    })
}

/// Retrieve the public encryption key as a raw array.
#[no_mangle]
pub unsafe extern "C" fn enc_pub_key_get(
    app: *const App,
    handle: EncryptPubKeyHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        pub_enc_key: *const AsymPublicKey,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let key = context.object_cache().get_encrypt_key(handle)?;
            Ok(&key.0)
        })
    })
}

/// Free encryption key from memory.
#[no_mangle]
pub unsafe extern "C" fn enc_pub_key_free(
    app: *const App,
    handle: EncryptPubKeyHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let _ = context.object_cache().remove_encrypt_key(handle)?;
            Ok(())
        })
    })
}

/// Create new private encryption key from raw array.
#[no_mangle]
pub unsafe extern "C" fn enc_secret_key_new(
    app: *const App,
    data: *const AsymSecretKey,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        sk_h: EncryptSecKeyHandle,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let key = shared_box::SecretKey::from_raw(&*data);
        send_sync(app, user_data, o_cb, move |_, context| {
            Ok(context.object_cache().insert_secret_key(key))
        })
    })
}

/// Retrieve the private encryption key as a raw array.
#[no_mangle]
pub unsafe extern "C" fn enc_secret_key_get(
    app: *const App,
    handle: EncryptSecKeyHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        sec_enc_key: *const AsymSecretKey,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let key = context.object_cache().get_secret_key(handle)?;
            Ok(&key.0)
        })
    })
}

/// Free private key from memory.
#[no_mangle]
pub unsafe extern "C" fn enc_secret_key_free(
    app: *const App,
    handle: EncryptSecKeyHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let _ = context.object_cache().remove_secret_key(handle)?;
            Ok(())
        })
    })
}

/// Signs arbitrary data using a given secret sign key.
///
/// If `sign_sk_h` is `SIGN_WITH_APP`, then uses the app's own secret key to sign.
#[no_mangle]
pub unsafe extern "C" fn sign(
    app: *const App,
    data: *const u8,
    data_len: usize,
    sign_sk_h: SignSecKeyHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        signed_data: *const u8,
        signed_data_len: usize,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        let plaintext = vec_clone_from_raw_parts(data, data_len);

        (*app).send(move |client, context| {
            let sign_sk = if sign_sk_h == SIGN_WITH_APP {
                try_cb!(
                    client
                        .secret_signing_key()
                        .ok_or_else(|| AppError::Unexpected(
                            "Secret signing key not found".to_string()
                        )),
                    user_data,
                    o_cb
                )
            } else {
                let sign_sk = try_cb!(
                    context.object_cache().get_sec_sign_key(sign_sk_h),
                    user_data,
                    o_cb
                );
                sign_sk.clone()
            };

            let signed_text = sign::sign(&plaintext, &sign_sk);
            o_cb(
                user_data.0,
                FFI_RESULT_OK,
                signed_text.as_safe_ptr(),
                signed_text.len(),
            );

            None
        })
    })
}

/// Verifies signed data using a given public sign key.
/// Returns an error if the message could not be verified.
#[no_mangle]
pub unsafe extern "C" fn verify(
    app: *const App,
    signed_data: *const u8,
    signed_data_len: usize,
    sign_pk_h: SignPubKeyHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        verified_data: *const u8,
        verified_data_len: usize,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        let signed = vec_clone_from_raw_parts(signed_data, signed_data_len);

        (*app).send(move |_, context| {
            let sign_pk = try_cb!(
                context.object_cache().get_pub_sign_key(sign_pk_h),
                user_data,
                o_cb
            );

            let verified = try_cb!(
                sign::verify(&signed, &sign_pk).map_err(|()| AppError::EncodeDecodeError),
                user_data,
                o_cb
            );
            o_cb(
                user_data.0,
                FFI_RESULT_OK,
                verified.as_safe_ptr(),
                verified.len(),
            );

            None
        })
    })
}

/// Encrypts arbitrary data using a given key pair.
/// You should provide a recipient's public key and a sender's secret key.
#[no_mangle]
pub unsafe extern "C" fn encrypt(
    app: *const App,
    data: *const u8,
    data_len: usize,
    public_key_h: EncryptPubKeyHandle,
    secret_key_h: EncryptSecKeyHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        ciphertext: *const u8,
        ciphertext_len: usize,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        let plaintext = vec_clone_from_raw_parts(data, data_len);

        (*app).send(move |_, context| {
            let pk = try_cb!(
                context.object_cache().get_encrypt_key(public_key_h),
                user_data,
                o_cb
            );
            let sk = try_cb!(
                context.object_cache().get_secret_key(secret_key_h),
                user_data,
                o_cb
            );

            let nonce = box_::gen_nonce();

            let ciphertext = box_::seal(&plaintext, &nonce, &pk, &sk);

            match serialise(&(nonce, ciphertext)) {
                Ok(result) => o_cb(user_data.0, FFI_RESULT_OK, result.as_ptr(), result.len()),
                res @ Err(..) => {
                    call_result_cb!(res.map_err(AppError::from), user_data, o_cb);
                }
            }

            None
        })
    })
}

/// Decrypts arbitrary data using a given key pair.
/// You should provide a sender's public key and a recipient's secret key.
#[no_mangle]
pub unsafe extern "C" fn decrypt(
    app: *const App,
    data: *const u8,
    data_len: usize,
    public_key_h: EncryptPubKeyHandle,
    secret_key_h: EncryptSecKeyHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        plaintext: *const u8,
        plaintext_len: usize,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        let encrypted_text = vec_clone_from_raw_parts(data, data_len);

        (*app).send(move |_, context| {
            let pk = try_cb!(
                context.object_cache().get_encrypt_key(public_key_h),
                user_data,
                o_cb
            );
            let sk = try_cb!(
                context.object_cache().get_secret_key(secret_key_h),
                user_data,
                o_cb
            );

            match deserialise::<(box_::Nonce, Vec<u8>)>(&encrypted_text) {
                Ok((nonce, ciphertext)) => {
                    let plaintext = try_cb!(
                        box_::open(&ciphertext, &nonce, &pk, &sk)
                            .map_err(|()| AppError::EncodeDecodeError),
                        user_data,
                        o_cb
                    );
                    o_cb(
                        user_data.0,
                        FFI_RESULT_OK,
                        plaintext.as_ptr(),
                        plaintext.len(),
                    );
                }
                res @ Err(..) => {
                    call_result_cb!(res.map_err(AppError::from), user_data, o_cb);
                }
            }

            None
        })
    })
}

/// Encrypts arbitrary data for a single recipient.
/// You should provide a recipient's public key.
#[no_mangle]
pub unsafe extern "C" fn encrypt_sealed_box(
    app: *const App,
    data: *const u8,
    data_len: usize,
    public_key_h: EncryptPubKeyHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        ciphertext: *const u8,
        ciphertext_len: usize,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let plaintext = vec_clone_from_raw_parts(data, data_len);
        let user_data = OpaqueCtx(user_data);

        (*app).send(move |_, context| {
            let pk = *try_cb!(
                context.object_cache().get_encrypt_key(public_key_h),
                user_data,
                o_cb
            );

            let ciphertext = sealedbox::seal(&plaintext, &pk);
            o_cb(
                user_data.0,
                FFI_RESULT_OK,
                ciphertext.as_ptr(),
                ciphertext.len(),
            );

            None
        })
    })
}

/// Decrypts arbitrary data for a single recipient.
/// You should provide a recipients's private and public key.
#[no_mangle]
pub unsafe extern "C" fn decrypt_sealed_box(
    app: *const App,
    data: *const u8,
    data_len: usize,
    public_key_h: EncryptPubKeyHandle,
    secret_key_h: EncryptSecKeyHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        plaintext: *const u8,
        plaintext_len: usize,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        let plaintext = vec_clone_from_raw_parts(data, data_len);

        (*app).send(move |_, context| {
            let pk = try_cb!(
                context.object_cache().get_encrypt_key(public_key_h),
                user_data,
                o_cb
            );
            let sk = try_cb!(
                context.object_cache().get_secret_key(secret_key_h),
                user_data,
                o_cb
            );

            let plaintext = try_cb!(
                sealedbox::open(&plaintext, &pk, &sk).map_err(|()| AppError::EncodeDecodeError),
                user_data,
                o_cb
            );
            o_cb(
                user_data.0,
                FFI_RESULT_OK,
                plaintext.as_ptr(),
                plaintext.len(),
            );

            None
        })
    })
}

/// Returns a sha3 hash for a given data.
#[no_mangle]
pub unsafe extern "C" fn sha3_hash(
    data: *const u8,
    data_len: usize,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        hash: *const u8,
        hash_len: usize,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<(), AppError> {
        let plaintext = slice::from_raw_parts(data, data_len);

        let hash = sha3_256(plaintext);
        o_cb(user_data, FFI_RESULT_OK, hash.as_ptr(), hash.len());

        Ok(())
    });
}

/// Generates a unique nonce and returns the result.
#[no_mangle]
pub unsafe extern "C" fn generate_nonce(
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, nonce: *const AsymNonce),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<(), AppError> {
        let nonce = box_::gen_nonce();
        o_cb(user_data, FFI_RESULT_OK, &nonce.0);

        Ok(())
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use errors::ERR_INVALID_SIGN_PUB_KEY_HANDLE;
    use ffi::mutable_data::permissions::USER_ANYONE;
    use ffi_utils::test_utils::{call_0, call_1, call_2, call_vec_u8};
    use rust_sodium::crypto::box_;
    use safe_core::arrays::{AsymNonce, AsymPublicKey, SignPublicKey, SignSecretKey};
    use test_utils::{create_app, run_now};

    // Test signing and verifying messages between apps.
    #[test]
    fn sign_verify() {
        let app1 = create_app();
        let app2 = create_app();

        let (app1_pk_h, app1_sk_h): (SignPubKeyHandle, SignSecKeyHandle) =
            unsafe { unwrap!(call_2(|ud, cb| sign_generate_key_pair(&app1, ud, cb))) };

        // Copying app1 pubkey to app2 object cache
        let pk_raw: SignPublicKey =
            unsafe { unwrap!(call_1(|ud, cb| sign_pub_key_get(&app1, app1_pk_h, ud, cb))) };

        let app2_pk_h: SignPubKeyHandle =
            unsafe { unwrap!(call_1(|ud, cb| sign_pub_key_new(&app2, &pk_raw, ud, cb))) };

        // Trying to sign a message from app1
        let data = b"hi there";
        let signed = unsafe {
            unwrap!(call_vec_u8(|ud, cb| sign(
                &app1,
                data.as_ptr(),
                data.len(),
                app1_sk_h,
                ud,
                cb
            )))
        };

        // Trying to verify the message in app2
        let verified = unsafe {
            unwrap!(call_vec_u8(|ud, cb| verify(
                &app2,
                signed.as_ptr(),
                signed.len(),
                app2_pk_h,
                ud,
                cb
            )))
        };

        assert_eq!(&verified, data);

        // Trying to sign a message from app1 using its secret sign key
        let signed = unsafe {
            unwrap!(call_vec_u8(|ud, cb| sign(
                &app1,
                data.as_ptr(),
                data.len(),
                SIGN_WITH_APP,
                ud,
                cb
            )))
        };

        // Trying to verify the message in app2
        let app1_pk_h = unsafe { unwrap!(call_1(|ud, cb| app_pub_sign_key(&app1, ud, cb))) };
        // Copying app1 pubkey to app2 object cache
        let pk_raw: AsymPublicKey =
            unsafe { unwrap!(call_1(|ud, cb| sign_pub_key_get(&app1, app1_pk_h, ud, cb))) };

        let app2_pk2_h =
            unsafe { unwrap!(call_1(|ud, cb| sign_pub_key_new(&app2, &pk_raw, ud, cb))) };
        let verified = unsafe {
            unwrap!(call_vec_u8(|ud, cb| verify(
                &app2,
                signed.as_ptr(),
                signed.len(),
                app2_pk2_h,
                ud,
                cb
            )))
        };

        assert_eq!(&verified, data);
    }

    // Test encrypting and decrypting messages between apps.
    #[test]
    fn encrypt_decrypt() {
        let app1 = create_app();
        let app2 = create_app();

        let (app1_pk1_h, app1_sk1_h): (EncryptPubKeyHandle, EncryptSecKeyHandle) =
            unsafe { unwrap!(call_2(|ud, cb| enc_generate_key_pair(&app1, ud, cb))) };
        let (app2_pk2_h, app2_sk2_h): (EncryptPubKeyHandle, EncryptSecKeyHandle) =
            unsafe { unwrap!(call_2(|ud, cb| enc_generate_key_pair(&app2, ud, cb))) };

        // Copying app2 pubkey to app1 object cache
        // and app1 pubkey to app2 object cache
        let pk2_raw: AsymPublicKey =
            unsafe { unwrap!(call_1(|ud, cb| enc_pub_key_get(&app2, app2_pk2_h, ud, cb))) };
        let pk1_raw: AsymPublicKey =
            unsafe { unwrap!(call_1(|ud, cb| enc_pub_key_get(&app1, app1_pk1_h, ud, cb))) };

        let app1_pk2_h =
            unsafe { unwrap!(call_1(|ud, cb| enc_pub_key_new(&app1, &pk2_raw, ud, cb))) };
        let app2_pk1_h =
            unsafe { unwrap!(call_1(|ud, cb| enc_pub_key_new(&app2, &pk1_raw, ud, cb))) };

        // Trying to encrypt a message for app2 from app1
        let data = b"hi there";
        let encrypted = unsafe {
            unwrap!(call_vec_u8(|ud, cb| encrypt(
                &app1,
                data.as_ptr(),
                data.len(),
                app1_pk2_h,
                app1_sk1_h,
                ud,
                cb,
            )))
        };

        // Trying to decrypt the message in app2
        let decrypted = unsafe {
            unwrap!(call_vec_u8(|ud, cb| decrypt(
                &app2,
                encrypted.as_ptr(),
                encrypted.len(),
                app2_pk1_h,
                app2_sk2_h,
                ud,
                cb,
            )))
        };

        assert_eq!(&decrypted, data);
    }

    // Test encrypting and decrypting sealed box messages between apps.
    #[test]
    fn encrypt_decrypt_sealed() {
        let app1 = create_app();
        let app2 = create_app();

        let (app2_pk2_h, app2_sk2_h): (EncryptPubKeyHandle, EncryptSecKeyHandle) =
            unsafe { unwrap!(call_2(|ud, cb| enc_generate_key_pair(&app2, ud, cb))) };

        // Copying app2 pubkey to app1 object cache
        // and app1 pubkey to app2 object cache
        let pk2_raw: AsymPublicKey =
            unsafe { unwrap!(call_1(|ud, cb| enc_pub_key_get(&app2, app2_pk2_h, ud, cb))) };

        let app1_pk2_h =
            unsafe { unwrap!(call_1(|ud, cb| enc_pub_key_new(&app1, &pk2_raw, ud, cb))) };

        // Trying to encrypt a message for app2 from app1
        let data = b"sealed box message";
        let encrypted = unsafe {
            unwrap!(call_vec_u8(|ud, cb| encrypt_sealed_box(
                &app1,
                data.as_ptr(),
                data.len(),
                app1_pk2_h,
                ud,
                cb
            )))
        };

        // Trying to decrypt the message in app2
        let decrypted = unsafe {
            unwrap!(call_vec_u8(|ud, cb| decrypt_sealed_box(
                &app2,
                encrypted.as_ptr(),
                encrypted.len(),
                app2_pk2_h,
                app2_sk2_h,
                ud,
                cb,
            )))
        };

        assert_eq!(&decrypted, data);
    }

    // Test creating and fetching public sign keys.
    #[test]
    fn sign_public_key_basics() {
        let app = create_app();
        let app_sign_key1_h = unsafe { unwrap!(call_1(|ud, cb| app_pub_sign_key(&app, ud, cb))) };

        let app_sign_key1 = run_now(&app, move |client, context| {
            let app_sign_key1 = unwrap!(client.public_signing_key());
            let app_sign_key2 = unwrap!(context.object_cache().get_pub_sign_key(app_sign_key1_h));
            assert_eq!(app_sign_key1, *app_sign_key2);

            app_sign_key1
        });

        let app_sign_key1_raw: SignPublicKey = unsafe {
            unwrap!(call_1(|ud, cb| sign_pub_key_get(
                &app,
                app_sign_key1_h,
                ud,
                cb
            ),))
        };

        let app_sign_key2_h = unsafe {
            unwrap!(call_1(|ud, cb| sign_pub_key_new(
                &app,
                &app_sign_key1_raw,
                ud,
                cb
            ),))
        };

        let app_sign_key2 = run_now(&app, move |_, context| {
            *unwrap!(context.object_cache().get_pub_sign_key(app_sign_key2_h))
        });

        assert_eq!(app_sign_key1, app_sign_key2);

        unsafe {
            unwrap!(call_0(|ud, cb| sign_pub_key_free(
                &app,
                app_sign_key2_h,
                ud,
                cb
            ),))
        }

        // Test that calling `sign_pub_key_get` on `USER_ANYONE` returns an error.
        let user: Result<SignPublicKey, i32> =
            unsafe { call_1(|ud, cb| sign_pub_key_get(&app, USER_ANYONE, ud, cb)) };
        match user {
            Err(ERR_INVALID_SIGN_PUB_KEY_HANDLE) => (),
            Err(e) => panic!("Unexpected error: {:?}", e),
            Ok(_) => panic!("Unexpected success"),
        }
    }

    // Test creating and fetching private sign keys.
    #[test]
    fn sign_secret_key_basics() {
        let app = create_app();

        let app_sign_key1 = run_now(&app, move |client, _| {
            let app_sign_key1 = unwrap!(client.secret_signing_key());

            app_sign_key1
        });

        let app_sign_key1_h = unsafe {
            unwrap!(call_1(|ud, cb| sign_sec_key_new(
                &app,
                &app_sign_key1.0,
                ud,
                cb
            ),))
        };

        let app_sign_key1_raw: SignSecretKey = unsafe {
            unwrap!(call_1(|ud, cb| sign_sec_key_get(
                &app,
                app_sign_key1_h,
                ud,
                cb
            ),))
        };

        let app_sign_key2_h = unsafe {
            unwrap!(call_1(|ud, cb| sign_sec_key_new(
                &app,
                &app_sign_key1_raw,
                ud,
                cb
            ),))
        };

        run_now(&app, move |_, context| {
            let sign_key = unwrap!(context.object_cache().get_sec_sign_key(app_sign_key2_h));
            assert_eq!(*app_sign_key1, *sign_key.clone());
        });

        unsafe {
            unwrap!(call_0(|ud, cb| sign_sec_key_free(
                &app,
                app_sign_key2_h,
                ud,
                cb
            ),))
        }
    }

    // Test creating and fetching public encryption keys.
    #[test]
    fn enc_public_key_basics() {
        let app = create_app();
        let app_enc_key1_h = unsafe { unwrap!(call_1(|ud, cb| app_pub_enc_key(&app, ud, cb))) };

        let app_enc_key1 = run_now(&app, move |client, context| {
            let app_enc_key1 = unwrap!(client.public_encryption_key());
            let app_enc_key2 = unwrap!(context.object_cache().get_encrypt_key(app_enc_key1_h));
            assert_eq!(app_enc_key1, *app_enc_key2);

            app_enc_key1
        });

        let app_enc_key1_raw: AsymPublicKey = unsafe {
            unwrap!(call_1(|ud, cb| enc_pub_key_get(
                &app,
                app_enc_key1_h,
                ud,
                cb
            ),))
        };

        let app_enc_key2_h = unsafe {
            unwrap!(call_1(|ud, cb| enc_pub_key_new(
                &app,
                &app_enc_key1_raw,
                ud,
                cb
            ),))
        };

        let app_enc_key2 = run_now(&app, move |_, context| {
            *unwrap!(context.object_cache().get_encrypt_key(app_enc_key2_h))
        });

        assert_eq!(app_enc_key1, app_enc_key2);

        unsafe {
            unwrap!(call_0(|ud, cb| enc_pub_key_free(
                &app,
                app_enc_key2_h,
                ud,
                cb
            ),))
        }
    }

    // Test creating and fetching secret encryption keys.
    #[test]
    fn enc_secret_key_basics() {
        let app = create_app();
        let (app_public_key_h, app_secret_key1_h) =
            unsafe { unwrap!(call_2(|ud, cb| enc_generate_key_pair(&app, ud, cb))) };

        let app_public_key1: AsymPublicKey = unsafe {
            unwrap!(call_1(|ud, cb| enc_pub_key_get(
                &app,
                app_public_key_h,
                ud,
                cb
            ),))
        };
        let app_secret_key1: AsymSecretKey = unsafe {
            unwrap!(call_1(|ud, cb| enc_secret_key_get(
                &app,
                app_secret_key1_h,
                ud,
                cb
            ),))
        };

        let app_secret_key1 = run_now(&app, move |_client, context| {
            let app_public_key2 = unwrap!(context.object_cache().get_encrypt_key(app_public_key_h));
            assert_eq!(box_::PublicKey(app_public_key1), *app_public_key2);

            let app_secret_key2 = unwrap!(context.object_cache().get_secret_key(app_secret_key1_h));
            assert_eq!(app_secret_key1, app_secret_key2.0);

            app_secret_key1
        });

        let app_secret_key1_raw: AsymSecretKey = unsafe {
            unwrap!(call_1(|ud, cb| enc_secret_key_get(
                &app,
                app_secret_key1_h,
                ud,
                cb
            ),))
        };

        let app_secret_key2_h = unsafe {
            unwrap!(call_1(|ud, cb| enc_secret_key_new(
                &app,
                &app_secret_key1_raw,
                ud,
                cb
            )))
        };

        run_now(&app, move |_, context| {
            let app_secret_key2 = unwrap!(context.object_cache().get_secret_key(app_secret_key2_h));
            assert_eq!(app_secret_key1, app_secret_key2.0);
        });

        unsafe {
            unwrap!(call_0(|ud, cb| enc_secret_key_free(
                &app,
                app_secret_key2_h,
                ud,
                cb
            )))
        }
    }

    // Test that generated nonces are the correct length.
    #[test]
    fn nonce_smoke_test() {
        let nonce: AsymNonce = unsafe { unwrap!(call_1(|ud, cb| generate_nonce(ud, cb))) };
        assert_eq!(nonce.len(), box_::NONCEBYTES);
    }

    // Test that generated sha3 hashes are the correct length.
    #[test]
    fn sha3_smoke_test() {
        let data = b"test message";
        let sha3 = unsafe {
            unwrap!(call_vec_u8(|ud, cb| sha3_hash(
                data.as_ptr(),
                data.len(),
                ud,
                cb
            ),))
        };

        assert_eq!(sha3.len(), 256 / 8);

        let data = b"";
        let sha3 = unsafe {
            unwrap!(call_vec_u8(|ud, cb| sha3_hash(
                data.as_ptr(),
                data.len(),
                ud,
                cb
            ),))
        };

        assert_eq!(sha3.len(), 256 / 8);
    }
}
