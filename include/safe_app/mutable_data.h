
#ifndef cheddar_generated_mutable_data_h
#define cheddar_generated_mutable_data_h


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>



/// Create new mutable data and put it on the network.
///
/// `permissions_h` is a handle to permissions to be set on the mutable data.
/// If `PERMISSIONS_EMPTY`, the permissions will be empty.
///
/// `entries_h` is a handle to entries for the mutable data.
/// If `ENTRIES_EMPTY`, the entries will be empty.
void mdata_put(App const* app, MDataInfoHandle info_h, MDataPermissionsHandle permissions_h, MDataEntriesHandle entries_h, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Get version of the mutable data.
void mdata_get_version(App const* app, MDataInfoHandle info_h, void* user_data, void (*o_cb)(void* , FfiResult , uint64_t ));

/// Get size of serialised mutable data.
void mdata_serialised_size(App const* app, MDataInfoHandle info_h, void* user_data, void (*o_cb)(void* , FfiResult , uint64_t ));

/// Get value at the given key from the mutable data.
/// The arguments to the callback are:
///     1. user data
///     2. error code
///     3. pointer to content
///     4. content length
///     5. entry version
///
/// Please notice that if a value is fetched from a private `MutableData`,
/// it's not automatically decrypted.
void mdata_get_value(App const* app, MDataInfoHandle info_h, uint8_t const* key_ptr, uintptr_t key_len, void* user_data, void (*o_cb)(void* , FfiResult , uint8_t const* , uintptr_t , uint64_t ));

/// Get complete list of entries in the mutable data.
void mdata_list_entries(App const* app, MDataInfoHandle info_h, void* user_data, void (*o_cb)(void* , FfiResult , MDataEntriesHandle ));

/// Get list of keys in the mutable data.
void mdata_list_keys(App const* app, MDataInfoHandle info_h, void* user_data, void (*o_cb)(void* , FfiResult , MDataKeysHandle ));

/// Get list of values in the mutable data.
void mdata_list_values(App const* app, MDataInfoHandle info_h, void* user_data, void (*o_cb)(void* , FfiResult , MDataValuesHandle ));

/// Mutate entries of the mutable data.
void mdata_mutate_entries(App const* app, MDataInfoHandle info_h, MDataEntryActionsHandle actions_h, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Get list of all permissions set on the mutable data
void mdata_list_permissions(App const* app, MDataInfoHandle info_h, void* user_data, void (*o_cb)(void* , FfiResult , MDataPermissionsHandle ));

/// Get list of permissions set on the mutable data for the given user.
///
/// User is either handle to a signing key or `USER_ANYONE`.
void mdata_list_user_permissions(App const* app, MDataInfoHandle info_h, SignKeyHandle user_h, void* user_data, void (*o_cb)(void* , FfiResult , MDataPermissionSetHandle ));

/// Set permissions set on the mutable data for the given user.
///
/// User is either handle to a signing key or `USER_ANYONE`.
void mdata_set_user_permissions(App const* app, MDataInfoHandle info_h, SignKeyHandle user_h, MDataPermissionSetHandle permission_set_h, uint64_t version, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Delete permissions set on the mutable data for the given user.
///
/// User is either handle to a signing key or `USER_ANYONE`.
void mdata_del_user_permissions(App const* app, MDataInfoHandle info_h, SignKeyHandle user_h, uint64_t version, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Change owner of the mutable data.
void mdata_change_owner(App const* app, MDataInfoHandle info_h, SignKeyHandle new_owner_h, uint64_t version, void* user_data, void (*o_cb)(void* , FfiResult ));



#ifdef __cplusplus
}
#endif


#endif
