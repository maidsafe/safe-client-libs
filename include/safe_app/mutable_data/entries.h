
#ifndef cheddar_generated_entries_h
#define cheddar_generated_entries_h


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>



/// Create new empty entries.
void mdata_entries_new(App const* app, void* user_data, void (*o_cb)(void* , FfiResult , MDataEntriesHandle ));

/// Insert an entry to the entries.
void mdata_entries_insert(App const* app, MDataEntriesHandle entries_h, uint8_t const* key_ptr, uintptr_t key_len, uint8_t const* value_ptr, uintptr_t value_len, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Returns the number of entries.
void mdata_entries_len(App const* app, MDataEntriesHandle entries_h, void* user_data, void (*o_cb)(void* , FfiResult , uintptr_t ));

/// Get the entry value at the given key.
/// The callbacks arguments are: user data, error code, pointer to value,
/// value length, entry version. The caller must NOT free the pointer.
void mdata_entries_get(App const* app, MDataEntriesHandle entries_h, uint8_t const* key_ptr, uintptr_t key_len, void* user_data, void (*o_cb)(void* , FfiResult , uint8_t const* , uintptr_t , uint64_t ));

/// Iterate over the entries.
///
/// The `entry_cb` callback is invoked once for each entry,
/// passing user data, pointer to key, key length, pointer to value, value length
/// and entry version in that order.
///
/// The `o_cb` callback is invoked after the iteration is done, or in case of error.
void mdata_entries_for_each(App const* app, MDataEntriesHandle entries_h, void (*entry_cb)(void* , uint8_t const* , uintptr_t , uint8_t const* , uintptr_t , uint64_t ), void* user_data, void (*o_cb)(void* , FfiResult ));

/// Free the entries from memory.
void mdata_entries_free(App const* app, MDataEntriesHandle entries_h, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Returns the number of keys.
void mdata_keys_len(App const* app, MDataKeysHandle keys_h, void* user_data, void (*o_cb)(void* , FfiResult , uintptr_t ));

/// Iterate over the keys.
///
/// The `key_cb` callback is invoked once for each key,
/// passing user data, pointer to key and key length.
///
/// The `o_cb` callback is invoked after the iteration is done, or in case of error.
void mdata_keys_for_each(App const* app, MDataKeysHandle keys_h, void (*key_cb)(void* , uint8_t const* , uintptr_t ), void* user_data, void (*o_cb)(void* , FfiResult ));

/// Free the keys from memory.
void mdata_keys_free(App const* app, MDataKeysHandle keys_h, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Returns the number of values.
void mdata_values_len(App const* app, MDataValuesHandle values_h, void* user_data, void (*o_cb)(void* , FfiResult , uintptr_t ));

/// Iterate over the values.
///
/// The `value_cb` callback is invoked once for each value,
/// passing user data, pointer to value, value length and entry version.
///
/// The `o_cb` callback is invoked after the iteration is done, or in case of error.
void mdata_values_for_each(App const* app, MDataValuesHandle values_h, void (*value_cb)(void* , uint8_t const* , uintptr_t , uint64_t ), void* user_data, void (*o_cb)(void* , FfiResult ));

/// Free the values from memory.
void mdata_values_free(App const* app, MDataValuesHandle values_h, void* user_data, void (*o_cb)(void* , FfiResult ));



#ifdef __cplusplus
}
#endif


#endif
