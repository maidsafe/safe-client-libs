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

use App;
use errors::AppError;
use ffi::helper::send_sync;
use ffi_utils::{FFI_RESULT_OK, FfiResult, OpaqueCtx, catch_unwind_cb};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use object_cache::{EncryptPubKeyHandle, EncryptSecKeyHandle, SignKeyHandle};
use rust_sodium::crypto::{box_, sealedbox, sign};
use std::os::raw::c_void;
use std::ptr;
use std::slice;
use tiny_keccak::sha3_256;

type SecKey = [u8; box_::SECRETKEYBYTES];
type PubKey = [u8; box_::PUBLICKEYBYTES];
type Nonce = [u8; box_::NONCEBYTES];

/// Get the public signing key of the app.
#[no_mangle]
pub unsafe extern "C" fn app_pub_sign_key(app: *const App,
                                          user_data: *mut c_void,
                                          o_cb: extern "C" fn(*mut c_void,
                                                              FfiResult,
                                                              SignKeyHandle)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |client, context| {
            let key = client.public_signing_key()?;
            Ok(context.object_cache().insert_sign_key(key))
        })
    })
}

/// Create new public signing key from raw array.
#[no_mangle]
pub unsafe extern "C" fn sign_key_new(app: *const App,
                                      data: *const PubKey,
                                      user_data: *mut c_void,
                                      o_cb: extern "C" fn(*mut c_void, FfiResult, SignKeyHandle)) {
    catch_unwind_cb(user_data, o_cb, || {
        let key = sign::PublicKey(*data);
        send_sync(app,
                  user_data,
                  o_cb,
                  move |_, context| Ok(context.object_cache().insert_sign_key(key)))
    })
}

/// Retrieve the public signing key as raw array.
#[no_mangle]
pub unsafe extern "C" fn sign_key_get(app: *const App,
                                      handle: SignKeyHandle,
                                      user_data: *mut c_void,
                                      o_cb: extern "C" fn(*mut c_void, FfiResult, *const PubKey)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let key = context.object_cache().get_sign_key(handle)?;
            Ok(&key.0)
        })
    })
}

/// Free signing key from memory
#[no_mangle]
pub unsafe extern "C" fn sign_key_free(app: *const App,
                                       handle: SignKeyHandle,
                                       user_data: *mut c_void,
                                       o_cb: extern "C" fn(*mut c_void, FfiResult)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let _ = context.object_cache().remove_sign_key(handle)?;
            Ok(())
        })
    })
}

/// Get the public encryption key of the app.
#[no_mangle]
pub unsafe extern "C" fn app_pub_enc_key(app: *const App,
                                         user_data: *mut c_void,
                                         o_cb: extern "C" fn(*mut c_void,
                                                             FfiResult,
                                                             EncryptPubKeyHandle)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |client, context| {
            let key = client.public_encryption_key()?;
            Ok(context.object_cache().insert_encrypt_key(key))
        })
    })
}

/// Generate a new encryption key pair (public & private key).
#[no_mangle]
pub unsafe extern "C" fn enc_generate_key_pair(app: *const App,
                                               user_data: *mut c_void,
                                               o_cb: extern "C" fn(*mut c_void,
                                                                   FfiResult,
                                                                   EncryptPubKeyHandle,
                                                                   EncryptSecKeyHandle)) {
    catch_unwind_cb(user_data, o_cb, || {
        let (ourpk, oursk) = box_::gen_keypair();
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
pub unsafe extern "C" fn enc_pub_key_new(app: *const App,
                                         data: *const PubKey,
                                         user_data: *mut c_void,
                                         o_cb: extern "C" fn(*mut c_void,
                                                             FfiResult,
                                                             EncryptPubKeyHandle)) {
    catch_unwind_cb(user_data, o_cb, || {
        let key = box_::PublicKey(*data);
        send_sync(app,
                  user_data,
                  o_cb,
                  move |_, context| Ok(context.object_cache().insert_encrypt_key(key)))
    })
}

/// Retrieve the public encryption key as raw array.
#[no_mangle]
pub unsafe extern "C" fn enc_pub_key_get(app: *const App,
                                         handle: EncryptPubKeyHandle,
                                         user_data: *mut c_void,
                                         o_cb: extern "C" fn(*mut c_void,
                                                             FfiResult,
                                                             *const PubKey)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let key = context.object_cache().get_encrypt_key(handle)?;
            Ok(&key.0)
        })
    })
}

/// Retrieve the private encryption key as raw array.
#[no_mangle]
pub unsafe extern "C" fn enc_secret_key_get(app: *const App,
                                            handle: EncryptSecKeyHandle,
                                            user_data: *mut c_void,
                                            o_cb: extern "C" fn(*mut c_void,
                                                                FfiResult,
                                                                *const SecKey)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let key = context.object_cache().get_secret_key(handle)?;
            Ok(&key.0)
        })
    })
}

/// Create new public encryption key from raw array.
#[no_mangle]
pub unsafe extern "C" fn enc_secret_key_new(app: *const App,
                                            data: *const SecKey,
                                            user_data: *mut c_void,
                                            o_cb: extern "C" fn(*mut c_void,
                                                                FfiResult,
                                                                EncryptSecKeyHandle)) {
    catch_unwind_cb(user_data, o_cb, || {
        let key = box_::SecretKey(*data);
        send_sync(app,
                  user_data,
                  o_cb,
                  move |_, context| Ok(context.object_cache().insert_secret_key(key)))
    })
}

/// Free encryption key from memory
#[no_mangle]
pub unsafe extern "C" fn enc_pub_key_free(app: *const App,
                                          handle: EncryptPubKeyHandle,
                                          user_data: *mut c_void,
                                          o_cb: extern "C" fn(*mut c_void, FfiResult)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let _ = context.object_cache().remove_encrypt_key(handle)?;
            Ok(())
        })
    })
}

/// Free private key from memory
#[no_mangle]
pub unsafe extern "C" fn enc_secret_key_free(app: *const App,
                                             handle: EncryptSecKeyHandle,
                                             user_data: *mut c_void,
                                             o_cb: extern "C" fn(*mut c_void, FfiResult)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let _ = context.object_cache().remove_secret_key(handle)?;
            Ok(())
        })
    })
}

/// Encrypts arbitrary data using a given key pair.
/// You should provide a recipient's public key and a sender's secret key.
#[no_mangle]
pub unsafe extern "C" fn encrypt(app: *const App,
                                 data: *const u8,
                                 len: usize,
                                 pk_h: EncryptPubKeyHandle,
                                 sk_h: EncryptSecKeyHandle,
                                 user_data: *mut c_void,
                                 o_cb: extern "C" fn(*mut c_void, FfiResult, *const u8, usize)) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        let plaintext = slice::from_raw_parts(data, len);

        (*app).send(move |_, context| {
            let pk = try_cb!(context.object_cache().get_encrypt_key(pk_h),
                             user_data,
                             o_cb);
            let sk = try_cb!(context.object_cache().get_secret_key(sk_h), user_data, o_cb);

            let nonce = box_::gen_nonce();

            let ciphertext = box_::seal(plaintext, &nonce, &pk, &sk);

            match serialise(&(nonce, ciphertext)) {
                Ok(result) => o_cb(user_data.0, FFI_RESULT_OK, result.as_ptr(), result.len()),
                Err(e) => {
                    let e = AppError::from(e);
                    let (error_code, description) = ffi_error!(e);
                    o_cb(user_data.0,
                         FfiResult {
                             error_code,
                             description: description.as_ptr(),
                         },
                         ptr::null(),
                         0)
                }
            }

            None
        })
    })
}

/// Decrypts arbitrary data using a given key pair.
/// You should provide a sender's public key and a recipient's secret key.
#[no_mangle]
pub unsafe extern "C" fn decrypt(app: *const App,
                                 data: *const u8,
                                 len: usize,
                                 pk_h: EncryptPubKeyHandle,
                                 sk_h: EncryptSecKeyHandle,
                                 user_data: *mut c_void,
                                 o_cb: extern "C" fn(*mut c_void, FfiResult, *const u8, usize)) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        let plaintext = slice::from_raw_parts(data, len);

        (*app).send(move |_, context| {
            let pk = try_cb!(context.object_cache().get_encrypt_key(pk_h),
                             user_data,
                             o_cb);
            let sk = try_cb!(context.object_cache().get_secret_key(sk_h), user_data, o_cb);

            match deserialise::<(box_::Nonce, Vec<u8>)>(plaintext) {
                Ok((nonce, ciphertext)) => {
                    let plaintext =
                        try_cb!(box_::open(&ciphertext, &nonce, &pk, &sk)
                                .map_err(|()| AppError::EncodeDecodeError), user_data, o_cb);
                    o_cb(user_data.0,
                         FFI_RESULT_OK,
                         plaintext.as_ptr(),
                         plaintext.len());
                }
                Err(e) => {
                    let e = AppError::from(e);
                    let (error_code, description) = ffi_error!(e);
                    o_cb(user_data.0,
                         FfiResult {
                             error_code,
                             description: description.as_ptr(),
                         },
                         ptr::null(),
                         0)
                }
            }

            None
        })
    })
}

/// Encrypts arbitrary data for a single recipient.
/// You should provide a recipient's public key.
#[no_mangle]
pub unsafe extern "C" fn encrypt_sealed_box(app: *const App,
                                            data: *const u8,
                                            len: usize,
                                            pk_h: EncryptPubKeyHandle,
                                            user_data: *mut c_void,
                                            o_cb: extern "C" fn(*mut c_void,
                                                                FfiResult,
                                                                *const u8,
                                                                usize)) {
    catch_unwind_cb(user_data, o_cb, || {
        let plaintext = slice::from_raw_parts(data, len);
        let user_data = OpaqueCtx(user_data);

        (*app).send(move |_, context| {
            let pk = *try_cb!(context.object_cache().get_encrypt_key(pk_h),
                              user_data,
                              o_cb);

            let ciphertext = sealedbox::seal(plaintext, &pk);
            o_cb(user_data.0,
                 FFI_RESULT_OK,
                 ciphertext.as_ptr(),
                 ciphertext.len());

            None
        })
    })
}

/// Decrypts arbitrary data for a single recipient.
/// You should provide a recipients's private and public key.
#[no_mangle]
pub unsafe extern "C" fn decrypt_sealed_box(app: *const App,
                                            data: *const u8,
                                            len: usize,
                                            pk_h: EncryptPubKeyHandle,
                                            sk_h: EncryptSecKeyHandle,
                                            user_data: *mut c_void,
                                            o_cb: extern "C" fn(*mut c_void,
                                                                FfiResult,
                                                                *const u8,
                                                                usize)) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        let plaintext = slice::from_raw_parts(data, len);

        (*app).send(move |_, context| {
            let pk = try_cb!(context.object_cache().get_encrypt_key(pk_h),
                             user_data,
                             o_cb);
            let sk = try_cb!(context.object_cache().get_secret_key(sk_h), user_data, o_cb);

            let plaintext =
                try_cb!(sealedbox::open(plaintext, &pk, &sk)
                                    .map_err(|()| AppError::EncodeDecodeError), user_data, o_cb);
            o_cb(user_data.0,
                 FFI_RESULT_OK,
                 plaintext.as_ptr(),
                 plaintext.len());

            None
        })
    })
}

/// Returns a sha3 hash for a given data.
#[no_mangle]
pub unsafe extern "C" fn sha3_hash(data: *const u8,
                                   len: usize,
                                   user_data: *mut c_void,
                                   o_cb: extern "C" fn(*mut c_void, FfiResult, *const u8, usize)) {
    catch_unwind_cb(user_data, o_cb, || -> Result<(), AppError> {
        let plaintext = slice::from_raw_parts(data, len);

        let hash = sha3_256(plaintext);
        o_cb(user_data, FFI_RESULT_OK, hash.as_ptr(), hash.len());

        Ok(())
    });
}

/// Generates a unique nonce and returns the result.
#[no_mangle]
pub unsafe extern "C" fn generate_nonce(user_data: *mut c_void,
                                        o_cb: extern "C" fn(*mut c_void, FfiResult, *const Nonce)) {
    catch_unwind_cb(user_data, o_cb, || -> Result<(), AppError> {
        let nonce = box_::gen_nonce();
        o_cb(user_data, FFI_RESULT_OK, &nonce.0);

        Ok(())
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffi_utils::test_utils::{call_1, call_2, call_vec_u8};
    use rust_sodium::crypto::{box_, sign};
    use test_utils::{create_app, run_now};

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
        let pk2_raw: [u8; box_::PUBLICKEYBYTES] =
            unsafe { unwrap!(call_1(|ud, cb| enc_pub_key_get(&app2, app2_pk2_h, ud, cb))) };
        let pk1_raw: [u8; box_::PUBLICKEYBYTES] =
            unsafe { unwrap!(call_1(|ud, cb| enc_pub_key_get(&app1, app1_pk1_h, ud, cb))) };

        let app1_pk2_h =
            unsafe { unwrap!(call_1(|ud, cb| enc_pub_key_new(&app1, &pk2_raw, ud, cb))) };
        let app2_pk1_h =
            unsafe { unwrap!(call_1(|ud, cb| enc_pub_key_new(&app2, &pk1_raw, ud, cb))) };

        // Trying to encrypt a message for app2 from app1
        let data = b"hi there";
        let encrypted = unsafe {
            unwrap!(call_vec_u8(|ud, cb| {
                encrypt(&app1,
                        data.as_ptr(),
                        data.len(),
                        app1_pk2_h,
                        app1_sk1_h,
                        ud,
                        cb)
            }))
        };

        // Trying to decrypt the message in app2
        let decrypted = unsafe {
            unwrap!(call_vec_u8(|ud, cb| {
                decrypt(&app2,
                        encrypted.as_ptr(),
                        encrypted.len(),
                        app2_pk1_h,
                        app2_sk2_h,
                        ud,
                        cb)
            }))
        };

        assert_eq!(&decrypted, data);
    }

    #[test]
    fn encrypt_decrypt_sealed() {
        let app1 = create_app();
        let app2 = create_app();

        let (app2_pk2_h, app2_sk2_h): (EncryptPubKeyHandle, EncryptSecKeyHandle) =
            unsafe { unwrap!(call_2(|ud, cb| enc_generate_key_pair(&app2, ud, cb))) };

        // Copying app2 pubkey to app1 object cache
        // and app1 pubkey to app2 object cache
        let pk2_raw: [u8; box_::PUBLICKEYBYTES] =
            unsafe { unwrap!(call_1(|ud, cb| enc_pub_key_get(&app2, app2_pk2_h, ud, cb))) };

        let app1_pk2_h =
            unsafe { unwrap!(call_1(|ud, cb| enc_pub_key_new(&app1, &pk2_raw, ud, cb))) };

        // Trying to encrypt a message for app2 from app1
        let data = b"sealed box message";
        let encrypted = unsafe {
            unwrap!(call_vec_u8(|ud, cb| {
                                    encrypt_sealed_box(&app1,
                                                       data.as_ptr(),
                                                       data.len(),
                                                       app1_pk2_h,
                                                       ud,
                                                       cb)
                                }))
        };

        // Trying to decrypt the message in app2
        let decrypted = unsafe {
            unwrap!(call_vec_u8(|ud, cb| {
                decrypt_sealed_box(&app2,
                                   encrypted.as_ptr(),
                                   encrypted.len(),
                                   app2_pk2_h,
                                   app2_sk2_h,
                                   ud,
                                   cb)
            }))
        };

        assert_eq!(&decrypted, data);
    }

    #[test]
    fn sign_key_basics() {
        let app = create_app();
        let app_sign_key1_h = unsafe { unwrap!(call_1(|ud, cb| app_pub_sign_key(&app, ud, cb))) };

        let app_sign_key1 = run_now(&app, move |client, context| {
            let app_sign_key1 = unwrap!(client.public_signing_key());
            let app_sign_key2 = unwrap!(context.object_cache().get_sign_key(app_sign_key1_h));
            assert_eq!(app_sign_key1, *app_sign_key2);

            app_sign_key1
        });

        let app_sign_key1_raw: [u8; sign::PUBLICKEYBYTES] =
            unsafe { unwrap!(call_1(|ud, cb| sign_key_get(&app, app_sign_key1_h, ud, cb))) };

        let app_sign_key2_h =
            unsafe { unwrap!(call_1(|ud, cb| sign_key_new(&app, &app_sign_key1_raw, ud, cb))) };

        let app_sign_key2 = run_now(&app, move |_, context| {
            *unwrap!(context.object_cache().get_sign_key(app_sign_key2_h))
        });

        assert_eq!(app_sign_key1, app_sign_key2);
    }

    #[test]
    fn enc_key_basics() {
        let app = create_app();
        let app_enc_key1_h = unsafe { unwrap!(call_1(|ud, cb| app_pub_enc_key(&app, ud, cb))) };

        let app_enc_key1 = run_now(&app, move |client, context| {
            let app_enc_key1 = unwrap!(client.public_encryption_key());
            let app_enc_key2 = unwrap!(context.object_cache().get_encrypt_key(app_enc_key1_h));
            assert_eq!(app_enc_key1, *app_enc_key2);

            app_enc_key1
        });

        let app_enc_key1_raw: [u8; box_::PUBLICKEYBYTES] =
            unsafe { unwrap!(call_1(|ud, cb| enc_pub_key_get(&app, app_enc_key1_h, ud, cb))) };

        let app_enc_key2_h =
            unsafe { unwrap!(call_1(|ud, cb| enc_pub_key_new(&app, &app_enc_key1_raw, ud, cb))) };

        let app_enc_key2 = run_now(&app, move |_, context| {
            *unwrap!(context.object_cache().get_encrypt_key(app_enc_key2_h))
        });

        assert_eq!(app_enc_key1, app_enc_key2);
    }

    #[test]
    fn nonce_smoke_test() {
        let nonce: [u8; box_::NONCEBYTES] =
            unsafe { unwrap!(call_1(|ud, cb| generate_nonce(ud, cb))) };
        assert_eq!(nonce.len(), box_::NONCEBYTES);
    }
}
