
#ifndef cheddar_generated_entry_actions_h
#define cheddar_generated_entry_actions_h


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>



/// Create new entry actions.
void mdata_entry_actions_new(App const* app, void* user_data, void (*o_cb)(void* , FfiResult , MDataEntryActionsHandle ));

/// Add action to insert new entry.
void mdata_entry_actions_insert(App const* app, MDataEntryActionsHandle actions_h, uint8_t const* key_ptr, uintptr_t key_len, uint8_t const* value_ptr, uintptr_t value_len, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Add action to update existing entry.
void mdata_entry_actions_update(App const* app, MDataEntryActionsHandle actions_h, uint8_t const* key_ptr, uintptr_t key_len, uint8_t const* value_ptr, uintptr_t value_len, uint64_t entry_version, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Add action to delete existing entry.
void mdata_entry_actions_delete(App const* app, MDataEntryActionsHandle actions_h, uint8_t const* key_ptr, uintptr_t key_len, uint64_t entry_version, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Free the entry actions from memory
void mdata_entry_actions_free(App const* app, MDataEntryActionsHandle actions_h, void* user_data, void (*o_cb)(void* , FfiResult ));



#ifdef __cplusplus
}
#endif


#endif
