
#ifndef cheddar_generated_cipher_opt_h
#define cheddar_generated_cipher_opt_h


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>



/// Construct `CipherOpt::PlainText` handle
void cipher_opt_new_plaintext(App const* app, void* user_data, void (*o_cb)(void* , FfiResult , CipherOptHandle ));

/// Construct `CipherOpt::Symmetric` handle
void cipher_opt_new_symmetric(App const* app, void* user_data, void (*o_cb)(void* , FfiResult , CipherOptHandle ));

/// Construct `CipherOpt::Asymmetric` handle
void cipher_opt_new_asymmetric(App const* app, EncryptPubKeyHandle peer_encrypt_key_h, void* user_data, void (*o_cb)(void* , FfiResult , CipherOptHandle ));

/// Free `CipherOpt` handle
void cipher_opt_free(App const* app, CipherOptHandle handle, void* user_data, void (*o_cb)(void* , FfiResult ));



#ifdef __cplusplus
}
#endif


#endif
