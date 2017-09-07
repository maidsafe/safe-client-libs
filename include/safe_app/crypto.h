
#ifndef cheddar_generated_crypto_h
#define cheddar_generated_crypto_h


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>



/// Get the public signing key of the app.
void app_pub_sign_key(App const* app, void* user_data, void (*o_cb)(void* , FfiResult , SignKeyHandle ));

/// Create new public signing key from raw array.
void sign_key_new(App const* app, AsymPublicKey const* data, void* user_data, void (*o_cb)(void* , FfiResult , SignKeyHandle ));

/// Retrieve the public signing key as raw array.
void sign_key_get(App const* app, SignKeyHandle handle, void* user_data, void (*o_cb)(void* , FfiResult , AsymPublicKey const* ));

/// Free signing key from memory
void sign_key_free(App const* app, SignKeyHandle handle, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Get the public encryption key of the app.
void app_pub_enc_key(App const* app, void* user_data, void (*o_cb)(void* , FfiResult , EncryptPubKeyHandle ));

/// Generate a new encryption key pair (public & private key).
void enc_generate_key_pair(App const* app, void* user_data, void (*o_cb)(void* , FfiResult , EncryptPubKeyHandle , EncryptSecKeyHandle ));

/// Create new public encryption key from raw array.
void enc_pub_key_new(App const* app, AsymPublicKey const* data, void* user_data, void (*o_cb)(void* , FfiResult , EncryptPubKeyHandle ));

/// Retrieve the public encryption key as raw array.
void enc_pub_key_get(App const* app, EncryptPubKeyHandle handle, void* user_data, void (*o_cb)(void* , FfiResult , AsymPublicKey const* ));

/// Retrieve the private encryption key as raw array.
void enc_secret_key_get(App const* app, EncryptSecKeyHandle handle, void* user_data, void (*o_cb)(void* , FfiResult , AsymSecretKey const* ));

/// Create new public encryption key from raw array.
void enc_secret_key_new(App const* app, AsymSecretKey const* data, void* user_data, void (*o_cb)(void* , FfiResult , EncryptSecKeyHandle ));

/// Free encryption key from memory
void enc_pub_key_free(App const* app, EncryptPubKeyHandle handle, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Free private key from memory
void enc_secret_key_free(App const* app, EncryptSecKeyHandle handle, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Encrypts arbitrary data using a given key pair.
/// You should provide a recipient's public key and a sender's secret key.
void encrypt(App const* app, uint8_t const* data, uintptr_t len, EncryptPubKeyHandle pk_h, EncryptSecKeyHandle sk_h, void* user_data, void (*o_cb)(void* , FfiResult , uint8_t const* , uintptr_t ));

/// Decrypts arbitrary data using a given key pair.
/// You should provide a sender's public key and a recipient's secret key.
void decrypt(App const* app, uint8_t const* data, uintptr_t len, EncryptPubKeyHandle pk_h, EncryptSecKeyHandle sk_h, void* user_data, void (*o_cb)(void* , FfiResult , uint8_t const* , uintptr_t ));

/// Encrypts arbitrary data for a single recipient.
/// You should provide a recipient's public key.
void encrypt_sealed_box(App const* app, uint8_t const* data, uintptr_t len, EncryptPubKeyHandle pk_h, void* user_data, void (*o_cb)(void* , FfiResult , uint8_t const* , uintptr_t ));

/// Decrypts arbitrary data for a single recipient.
/// You should provide a recipients's private and public key.
void decrypt_sealed_box(App const* app, uint8_t const* data, uintptr_t len, EncryptPubKeyHandle pk_h, EncryptSecKeyHandle sk_h, void* user_data, void (*o_cb)(void* , FfiResult , uint8_t const* , uintptr_t ));

/// Returns a sha3 hash for a given data.
void sha3_hash(uint8_t const* data, uintptr_t len, void* user_data, void (*o_cb)(void* , FfiResult , uint8_t const* , uintptr_t ));

/// Generates a unique nonce and returns the result.
void generate_nonce(void* user_data, void (*o_cb)(void* , FfiResult , AsymNonce const* ));



#ifdef __cplusplus
}
#endif


#endif
