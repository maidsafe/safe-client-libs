// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::errors::AppError;
use crate::ffi::helper::send_sync;
use crate::ffi::object_cache::{
    EncryptPubKeyHandle, EncryptSecKeyHandle, SignPubKeyHandle, SignSecKeyHandle,
    NULL_OBJECT_HANDLE,
};
use crate::App;
use bincode::{deserialize, serialize};
use ffi_utils::{catch_unwind_cb, vec_clone_from_raw_parts, FfiResult, OpaqueCtx, FFI_RESULT_OK};
use rand::thread_rng;
use safe_core::crypto::shared_box;
use safe_core::{AsymPublicKey, Client};
use safe_nd::{ClientFullId, PublicKey, Signature};
use std::os::raw::c_void;
use std::slice;
use threshold_crypto::{Ciphertext, PublicKey as AsymEncryptKey};
use tiny_keccak::sha3_256;

/// Special value that represents that a message should be signed by the app.
#[no_mangle]
pub static SIGN_WITH_APP: SignSecKeyHandle = NULL_OBJECT_HANDLE;

/// Special value that represents that a signature should be verified by the app.
#[no_mangle]
pub static VERIFY_WITH_APP: SignSecKeyHandle = NULL_OBJECT_HANDLE;

/// Gets the public signing key of the app.
#[no_mangle]
pub unsafe extern "C" fn app_pub_sign_key(
    app: *const App,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, handle: SignPubKeyHandle),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |client, context| {
            let key = client.public_key();
            Ok(context.object_cache().insert_pub_sign_key(key))
        })
    })
}

/// Generates a new sign key pair (public & private key).
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
        let full_id = ClientFullId::new_bls(&mut thread_rng());
        let public_key = *full_id.public_id().public_key();
        let user_data = OpaqueCtx(user_data);

        (*app).send(move |_, context| {
            let pk_h = context.object_cache().insert_pub_sign_key(public_key);
            let sk_h = context.object_cache().insert_sec_sign_key(full_id);

            o_cb(user_data.0, FFI_RESULT_OK, pk_h, sk_h);

            None
        })
    })
}

/// Creates new public signing key from raw array.
#[no_mangle]
pub unsafe extern "C" fn sign_pub_key_new(
    app: *const App,
    data: *const u8,
    data_len: usize,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, handle: SignPubKeyHandle),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let serialized_key = vec_clone_from_raw_parts(data, data_len);
        let key: PublicKey = unwrap!(deserialize(&serialized_key));
        send_sync(app, user_data, o_cb, move |_, context| {
            Ok(context.object_cache().insert_pub_sign_key(key))
        })
    })
}

/// Retrieves the public signing key as a raw array.
#[no_mangle]
pub unsafe extern "C" fn sign_pub_key_get(
    app: *const App,
    handle: SignPubKeyHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        pub_sign_key: *const u8,
        pub_sign_key_len: usize,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        (*app).send(move |_, context| {
            let key: PublicKey = {
                let sign_pk = try_cb!(
                    context.object_cache().get_pub_sign_key(handle),
                    user_data,
                    o_cb
                );
                *sign_pk
            };
            match serialize(&key) {
                Ok(result) => o_cb(user_data.0, FFI_RESULT_OK, result.as_ptr(), result.len()),
                res @ Err(..) => {
                    call_result_cb!(res.map_err(AppError::from), user_data, o_cb);
                }
            }
            None
        })
    })
}

/// Frees public signing key from memory.
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

/// Creates new secret signing key from raw array.
#[no_mangle]
pub unsafe extern "C" fn sign_sec_key_new(
    app: *const App,
    data: *const u8,
    data_len: usize,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, handle: SignSecKeyHandle),
) {
    let serialized_key = vec_clone_from_raw_parts(data, data_len);
    catch_unwind_cb(user_data, o_cb, || {
        let full_id: ClientFullId = deserialize(&serialized_key)?;
        send_sync(app, user_data, o_cb, move |_, context| {
            Ok(context.object_cache().insert_sec_sign_key(full_id))
        })
    })
}

/// Retrieves the secret signing key as a raw array.
#[no_mangle]
pub unsafe extern "C" fn sign_sec_key_get(
    app: *const App,
    handle: SignSecKeyHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        sec_sign_key: *const u8,
        sec_sign_key_len: usize,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        (*app).send(move |_, context| {
            let sign_sk = {
                let sign_sk = try_cb!(
                    context.object_cache().get_sec_sign_key(handle),
                    user_data,
                    o_cb
                );
                sign_sk.clone()
            };

            match serialize(&sign_sk) {
                Ok(result) => o_cb(user_data.0, FFI_RESULT_OK, result.as_ptr(), result.len()),
                res @ Err(..) => {
                    call_result_cb!(res.map_err(AppError::from), user_data, o_cb);
                }
            }
            None
        })
    })
}

/// Frees secret signing key from memory.
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

/// Gets the public encryption key of the app.
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
            let key = client.public_encryption_key();
            Ok(context.object_cache().insert_encrypt_key(key))
        })
    })
}

/// Generates a new encryption key pair (public & private key).
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

/// Creates new public encryption key from raw array.
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
        let raw = data.as_ref().ok_or_else(|| AppError::EncodeDecodeError)?;
        let key = AsymEncryptKey::from_bytes(raw).map_err(|_| AppError::EncodeDecodeError)?;
        send_sync(app, user_data, o_cb, move |_, context| {
            Ok(context.object_cache().insert_encrypt_key(key))
        })
    })
}

/// Retrieves the public encryption key as a raw array.
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
            let key: AsymEncryptKey = *context.object_cache().get_encrypt_key(handle)?;
            let buf = &key.to_bytes();
            Ok(buf)
        })
    })
}

/// Frees public encryption key from memory.
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

/// Creates new private encryption key from raw array.
#[no_mangle]
pub unsafe extern "C" fn enc_secret_key_new(
    app: *const App,
    sk: *const u8,
    sk_len: usize,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        sk_h: EncryptSecKeyHandle,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let raw = vec_clone_from_raw_parts(sk, sk_len);
        let key =
            shared_box::SecretKey::from_raw(&*raw).map_err(|_| AppError::EncodeDecodeError)?;
        send_sync(app, user_data, o_cb, move |_, context| {
            Ok(context.object_cache().insert_secret_key(key))
        })
    })
}

/// Retrieves the private encryption key as a raw array.
#[no_mangle]
pub unsafe extern "C" fn enc_secret_key_get(
    app: *const App,
    handle: EncryptSecKeyHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        sec_enc_key: *const u8,
        sec_enc_key_len: usize,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        (*app).send(move |_, context| {
            let key = try_cb!(
                context.object_cache().get_secret_key(handle),
                user_data,
                o_cb
            );
            let raw = try_cb!(
                serialize(&*key).map_err(|_| AppError::EncodeDecodeError),
                user_data,
                o_cb
            );
            o_cb(user_data.0, FFI_RESULT_OK, raw.as_ptr(), raw.len());
            None
        })
    })
}

/// Frees private encryption key from memory.
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
        signature: *const u8,
        signature_len: usize,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let plaintext = vec_clone_from_raw_parts(data, data_len);

        let user_data = OpaqueCtx(user_data);
        (*app).send(move |client, context| {
            let signature = if sign_sk_h == SIGN_WITH_APP {
                let safe_key = client.full_id();
                safe_key.sign(&plaintext)
            } else {
                let sign_sk = try_cb!(
                    context.object_cache().get_sec_sign_key(sign_sk_h),
                    user_data,
                    o_cb
                );
                sign_sk.sign(&plaintext)
            };
            match serialize(&signature) {
                Ok(result) => o_cb(user_data.0, FFI_RESULT_OK, result.as_ptr(), result.len()),
                res @ Err(..) => {
                    call_result_cb!(res.map_err(AppError::from), user_data, o_cb);
                }
            }
            None
        })
    })
}

/// Verifies signed data using a given public sign key.
///
/// If `sign_pk_h` is `VERIFY_WITH_APP`, then uses the app's own public key to verify.
#[no_mangle]
pub unsafe extern "C" fn verify(
    app: *const App,
    signed_data: *const u8,
    signed_data_len: usize,
    signature: *const u8,
    signature_len: usize,
    sign_pk_h: SignPubKeyHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, valid: u32),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        let signed = vec_clone_from_raw_parts(signed_data, signed_data_len);
        let signature_array = vec_clone_from_raw_parts(signature, signature_len);
        let signature: Signature = deserialize(&signature_array)?;

        (*app).send(move |client, context| {
            let sign_pk: PublicKey = if sign_pk_h == VERIFY_WITH_APP {
                client.public_key()
            } else {
                let sign_pk = try_cb!(
                    context.object_cache().get_pub_sign_key(sign_pk_h),
                    user_data,
                    o_cb
                );
                *sign_pk
            };
            let result = sign_pk.verify(&signature, &signed);

            o_cb(user_data.0, FFI_RESULT_OK, result.is_ok() as u32);
            None
        })
    })
}

// TODO: Implement PublicKey Encryption using the ring crate.
// These functions are not used internally by SCL.

/*
/// Encrypts arbitrary data using a given key pair.
///
/// You should provide a sender's secret key and a recipient's public key.
//#[no_mangle]
pub unsafe extern "C" fn encrypt(
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
        let user_data = OpaqueCtx(user_data);
        let plaintext = vec_clone_from_raw_parts(data, data_len);

        (*app).send(move |_, context| {
            let pk = try_cb!(
                context.object_cache().get_encrypt_key(public_key_h),
                user_data,
                o_cb
            );

            let ciphertext = pk.encrypt(plaintext);

            match serialize(&ciphertext) {
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
///
/// You should provide a sender's public key and a recipient's secret key.
#[no_mangle]
pub unsafe extern "C" fn decrypt(
    app: *const App,
    data: *const u8,
    data_len: usize,
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
            let sk = try_cb!(
                context.object_cache().get_secret_key(secret_key_h),
                user_data,
                o_cb
            );

            match deserialize::<Ciphertext>(&encrypted_text) {
                Ok(ciphertext) => {
                    let plaintext = try_cb!(
                        sk.decrypt(&ciphertext)
                            .ok_or_else(|| AppError::EncodeDecodeError),
                        user_data,
                        o_cb
                    );
                    o_cb(
                        user_data.0,
                        FFI_RESULT_OK,
                        plaintext.as_ptr(),
                        plaintext.len(),
                    )
                }
                res @ Err(..) => {
                    call_result_cb!(res.map_err(AppError::from), user_data, o_cb);
                }
            }

            None
        })
    })
}*/

/// Encrypts arbitrary data for a single recipient.
///
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
            let pk: AsymEncryptKey = *try_cb!(
                context.object_cache().get_encrypt_key(public_key_h),
                user_data,
                o_cb
            );

            match serialize(&pk.encrypt(plaintext)) {
                Ok(result) => o_cb(user_data.0, FFI_RESULT_OK, result.as_ptr(), result.len()),
                res @ Err(..) => {
                    call_result_cb!(res.map_err(AppError::from), user_data, o_cb);
                }
            }
            None
        })
    })
}

/// Decrypts arbitrary data for a single recipient.
///
/// You should provide a recipients's private key.
#[no_mangle]
pub unsafe extern "C" fn decrypt_sealed_box(
    app: *const App,
    data: *const u8,
    data_len: usize,
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
        let deserialized: Ciphertext = deserialize(plaintext.as_slice()).map_err(AppError::from)?;
        (*app).send(move |_, context| {
            let sk = try_cb!(
                context.object_cache().get_secret_key(secret_key_h),
                user_data,
                o_cb
            );

            let plaintext = try_cb!(
                sk.decrypt(&deserialized)
                    .ok_or_else(|| AppError::EncodeDecodeError),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ERR_INVALID_SIGN_PUB_KEY_HANDLE;
    use crate::ffi::mutable_data::permissions::USER_ANYONE;
    use crate::run;
    use crate::test_utils::create_app;
    use ffi_utils::test_utils::{call_0, call_1, call_2, call_vec_u8};
    use ffi_utils::vec_into_raw_parts;

    // Test signing and verifying messages between apps.
    #[test]
    fn sign_verify() {
        let app1 = create_app();
        let app2 = create_app();

        let (app1_pk_h, app1_sk_h): (SignPubKeyHandle, SignSecKeyHandle) =
            unsafe { unwrap!(call_2(|ud, cb| sign_generate_key_pair(&app1, ud, cb))) };

        // Copying app1 pubkey to app2 object cache
        let pk_raw = unsafe {
            unwrap!(call_vec_u8(|ud, cb| sign_pub_key_get(
                &app1, app1_pk_h, ud, cb
            )))
        };

        let app2_pk_h: SignPubKeyHandle = unsafe {
            unwrap!(call_1(|ud, cb| sign_pub_key_new(
                &app2,
                pk_raw.as_ptr(),
                pk_raw.len(),
                ud,
                cb
            )))
        };

        // Trying to sign a message from app1
        let data = b"hi there";
        let signature = unsafe {
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
        let verified: bool = unsafe {
            unwrap!(call_1(|ud, cb| verify(
                &app2,
                data.as_ptr(),
                data.len(),
                signature.as_ptr(),
                signature.len(),
                app2_pk_h,
                ud,
                cb
            )))
        };

        assert!(verified);

        // Trying to sign a message from app1 using its secret sign key
        let signature = unsafe {
            unwrap!(call_vec_u8(|ud, cb| sign(
                &app1,
                data.as_ptr(),
                data.len(),
                SIGN_WITH_APP,
                ud,
                cb
            )))
        };

        let verified: bool = unsafe {
            unwrap!(call_1(|ud, cb| verify(
                &app1,
                data.as_ptr(),
                data.len(),
                signature.as_ptr(),
                signature.len(),
                VERIFY_WITH_APP,
                ud,
                cb
            )))
        };

        assert!(verified);
    }

    // TODO: Fix this test when publickey encryption is fixed.

    /*   // Test encrypting and decrypting messages between apps.
    #[test]
    fn encrypt_decrypt() {
        let app1 = create_app();
        let app2 = create_app();

        let (app2_pk2_h, app2_sk2_h): (EncryptPubKeyHandle, EncryptSecKeyHandle) =
            unsafe { unwrap!(call_2(|ud, cb| enc_generate_key_pair(&app2, ud, cb))) };

        // Copying app2 pubkey to app1 object cache
        // and app1 pubkey to app2 object cache
        let pk2_raw: AsymPublicKey = unsafe {
            unwrap!(call_1(|ud, cb| enc_pub_key_get(
                &app2, app2_pk2_h, ud, cb
            )))
        };

        let app1_pk2_h = unsafe {
            unwrap!(call_1(|ud, cb| enc_pub_key_new(
                &app1,
                &pk2_raw,
                ud,
                cb
            )))
        };

        // Trying to encrypt a message for app2 from app1
        let data = b"hi there";
        let encrypted = unsafe {
            unwrap!(call_vec_u8(|ud, cb| encrypt(
                &app1,
                data.as_ptr(),
                data.len(),
                app1_pk2_h,
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
                app2_sk2_h,
                ud,
                cb,
            )))
        };

        assert_eq!(&decrypted, data);
    }*/

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

        let app_sign_key1 = unwrap!(run(&app, move |client, context| {
            let app_sign_key1 = client.public_key();
            let app_sign_key2 = unwrap!(context.object_cache().get_pub_sign_key(app_sign_key1_h));
            assert_eq!(app_sign_key1, *app_sign_key2);

            Ok(app_sign_key1)
        }));

        let app_sign_key1_raw = unsafe {
            unwrap!(call_vec_u8(|ud, cb| sign_pub_key_get(
                &app,
                app_sign_key1_h,
                ud,
                cb
            ),))
        };

        let app_sign_key2_h = unsafe {
            unwrap!(call_1(|ud, cb| sign_pub_key_new(
                &app,
                app_sign_key1_raw.as_ptr(),
                app_sign_key1_raw.len(),
                ud,
                cb
            ),))
        };

        let app_sign_key2 = unwrap!(run(&app, move |_, context| {
            Ok(*unwrap!(context
                .object_cache()
                .get_pub_sign_key(app_sign_key2_h)))
        }));

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
        let user: Result<Vec<u8>, i32> =
            unsafe { call_vec_u8(|ud, cb| sign_pub_key_get(&app, USER_ANYONE, ud, cb)) };
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
        let (_, app_sign_key1_h): (SignPubKeyHandle, SignSecKeyHandle) =
            unsafe { unwrap!(call_2(|ud, cb| sign_generate_key_pair(&app, ud, cb))) };

        let app_sign_key1_raw = unsafe {
            unwrap!(call_vec_u8(|ud, cb| sign_sec_key_get(
                &app,
                app_sign_key1_h,
                ud,
                cb
            ),))
        };

        let app_sign_key2_h = unsafe {
            unwrap!(call_1(|ud, cb| sign_sec_key_new(
                &app,
                app_sign_key1_raw.as_ptr(),
                app_sign_key1_raw.len(),
                ud,
                cb
            ),))
        };
        let sign_sk1 = unwrap!(run(&app, move |_, context| {
            let sign_sk = unwrap!(context.object_cache().get_sec_sign_key(app_sign_key1_h));
            Ok(sign_sk.clone())
        }));

        let sign_sk2 = unwrap!(run(&app, move |_, context| {
            let sign_sk = unwrap!(context.object_cache().get_sec_sign_key(app_sign_key2_h));
            Ok(sign_sk.clone())
        }));

        assert_eq!(sign_sk1, sign_sk2);

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

        let app_enc_key1 = unwrap!(run(&app, move |client, context| {
            let app_enc_key1 = client.public_encryption_key();
            let app_enc_key2 = unwrap!(context.object_cache().get_encrypt_key(app_enc_key1_h));
            assert_eq!(app_enc_key1, *app_enc_key2);

            Ok(app_enc_key1)
        }));

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

        let app_enc_key2 = unwrap!(run(&app, move |_, context| {
            Ok(*unwrap!(context
                .object_cache()
                .get_encrypt_key(app_enc_key2_h)))
        }));

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

        let app_public_key1_raw: AsymPublicKey = unsafe {
            unwrap!(call_1(|ud, cb| enc_pub_key_get(
                &app,
                app_public_key_h,
                ud,
                cb
            ),))
        };

        let app_public_key1 = unwrap!(AsymEncryptKey::from_bytes(app_public_key1_raw));

        let app_secret_key1 = unsafe {
            unwrap!(call_vec_u8(|ud, cb| enc_secret_key_get(
                &app,
                app_secret_key1_h,
                ud,
                cb,
            ),))
        };

        let app_secret_key1 = unwrap!(shared_box::SecretKey::from_raw(&app_secret_key1));

        let app_secret_key1 = unwrap!(run(&app, move |_client, context| {
            let app_public_key2 = unwrap!(context.object_cache().get_encrypt_key(app_public_key_h));
            assert_eq!(app_public_key1, *app_public_key2);

            let app_secret_key2 = unwrap!(context.object_cache().get_secret_key(app_secret_key1_h));
            assert_eq!(app_secret_key1, *app_secret_key2);

            Ok(app_secret_key1)
        }));

        let app_secret_key1_raw = unsafe {
            unwrap!(call_vec_u8(|ud, cb| enc_secret_key_get(
                &app,
                app_secret_key1_h,
                ud,
                cb,
            ),))
        };

        let (app_sk1, app_sk1_len) = vec_into_raw_parts(app_secret_key1_raw);

        let app_secret_key2_h = unsafe {
            unwrap!(call_1(|ud, cb| enc_secret_key_new(
                &app,
                app_sk1,
                app_sk1_len,
                ud,
                cb
            )))
        };

        unwrap!(run(&app, move |_, context| {
            let app_secret_key2 = unwrap!(context.object_cache().get_secret_key(app_secret_key2_h));
            assert_eq!(app_secret_key1, *app_secret_key2);
            Ok(())
        }));

        unsafe {
            unwrap!(call_0(|ud, cb| enc_secret_key_free(
                &app,
                app_secret_key2_h,
                ud,
                cb
            )))
        }
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
