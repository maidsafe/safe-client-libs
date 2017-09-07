
#ifndef cheddar_generated_mdata_info_h
#define cheddar_generated_mdata_info_h


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>



/// Create non-encrypted mdata info with explicit data name.
void mdata_info_new_public(App const* app, XorNameArray const* name, uint64_t type_tag, void* user_data, void (*o_cb)(void* , FfiResult , MDataInfoHandle ));

/// Create encrypted mdata info with explicit data name and a
/// provided private key.
void mdata_info_new_private(App const* app, XorNameArray const* name, uint64_t type_tag, SymSecretKey const* secret_key, SymNonce const* nonce, void* user_data, void (*o_cb)(void* , FfiResult , MDataInfoHandle ));

/// Create random, non-encrypted mdata info.
void mdata_info_random_public(App const* app, uint64_t type_tag, void* user_data, void (*o_cb)(void* , FfiResult , MDataInfoHandle ));

/// Create random, encrypted mdata info.
void mdata_info_random_private(App const* app, uint64_t type_tag, void* user_data, void (*o_cb)(void* , FfiResult , MDataInfoHandle ));

/// Encrypt mdata entry key using the corresponding mdata info.
void mdata_info_encrypt_entry_key(App const* app, MDataInfoHandle info_h, uint8_t const* input_ptr, uintptr_t input_len, void* user_data, void (*o_cb)(void* , FfiResult , uint8_t const* , uintptr_t ));

/// Encrypt mdata entry value using the corresponding mdata info.
void mdata_info_encrypt_entry_value(App const* app, MDataInfoHandle info_h, uint8_t const* input_ptr, uintptr_t input_len, void* user_data, void (*o_cb)(void* , FfiResult , uint8_t const* , uintptr_t ));

/// Decrypt mdata entry value or a key using the corresponding mdata info.
void mdata_info_decrypt(App const* app, MDataInfoHandle info_h, uint8_t const* input_ptr, uintptr_t input_len, void* user_data, void (*o_cb)(void* , FfiResult , uint8_t const* , uintptr_t ));

/// Extract name and type tag from the mdata info.
void mdata_info_extract_name_and_type_tag(App const* app, MDataInfoHandle info_h, void* user_data, void (*o_cb)(void* , FfiResult , XorNameArray const* , uint64_t ));

/// Serialise `MDataInfo`.
void mdata_info_serialise(App const* app, MDataInfoHandle info_h, void* user_data, void (*o_cb)(void* , FfiResult , uint8_t const* , uintptr_t ));

/// Deserialise `MDataInfo`.
void mdata_info_deserialise(App const* app, uint8_t const* ptr, uintptr_t len, void* user_data, void (*o_cb)(void* , FfiResult , MDataInfoHandle ));

/// Free `MDataInfo` from memory.
void mdata_info_free(App const* app, MDataInfoHandle info_h, void* user_data, void (*o_cb)(void* , FfiResult ));



#ifdef __cplusplus
}
#endif


#endif
