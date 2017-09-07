
#ifndef cheddar_generated_immutable_data_h
#define cheddar_generated_immutable_data_h


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>



/// Handle of a Self Encryptor Writer object
typedef SelfEncryptorWriterHandle SEWriterHandle;

/// Handle of a Self Encryptor Reader object
typedef SelfEncryptorReaderHandle SEReaderHandle;

/// Get a Self Encryptor
void idata_new_self_encryptor(App const* app, void* user_data, void (*o_cb)(void* , FfiResult , SEWriterHandle ));

/// Write to Self Encryptor
void idata_write_to_self_encryptor(App const* app, SEWriterHandle se_h, uint8_t const* data, uintptr_t size, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Close Self Encryptor
void idata_close_self_encryptor(App const* app, SEWriterHandle se_h, CipherOptHandle cipher_opt_h, void* user_data, void (*o_cb)(void* , FfiResult , XorNameArray const* ));

/// Fetch Self Encryptor
void idata_fetch_self_encryptor(App const* app, XorNameArray const* name, void* user_data, void (*o_cb)(void* , FfiResult , SEReaderHandle ));

/// Get serialised size of `ImmutableData`
void idata_serialised_size(App const* app, XorNameArray const* name, void* user_data, void (*o_cb)(void* , FfiResult , uint64_t ));

/// Get data size from Self Encryptor
void idata_size(App const* app, SEReaderHandle se_h, void* user_data, void (*o_cb)(void* , FfiResult , uint64_t ));

/// Read from Self Encryptor
/// Callback parameters are: user data, error code, data, size, capacity
void idata_read_from_self_encryptor(App const* app, SEReaderHandle se_h, uint64_t from_pos, uint64_t len, void* user_data, void (*o_cb)(void* , FfiResult , uint8_t const* , uintptr_t ));

/// Free Self Encryptor Writer handle
void idata_self_encryptor_writer_free(App const* app, SEWriterHandle handle, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Free Self Encryptor Reader handle
void idata_self_encryptor_reader_free(App const* app, SEReaderHandle handle, void* user_data, void (*o_cb)(void* , FfiResult ));



#ifdef __cplusplus
}
#endif


#endif
