
#ifndef cheddar_generated_permissions_h
#define cheddar_generated_permissions_h


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>



/// Permission actions.
typedef enum MDataAction {
	/// Permission to insert new entries.
	MDataAction_Insert,
	/// Permission to update existing entries.
	MDataAction_Update,
	/// Permission to delete existing entries.
	MDataAction_Delete,
	/// Permission to manage permissions.
	MDataAction_ManagePermissions,
} MDataAction;

/// State of action in the permission set
typedef enum PermissionValue {
	/// Explicit permission is not set
	PermissionValue_NotSet,
	/// Permission is allowed
	PermissionValue_Allowed,
	/// Permission is denied
	PermissionValue_Denied,
} PermissionValue;

/// Create new permission set.
void mdata_permission_set_new(App const* app, void* user_data, void (*o_cb)(void* , FfiResult , MDataPermissionSetHandle ));

/// Allow the action in the permission set.
void mdata_permissions_set_allow(App const* app, MDataPermissionSetHandle set_h, MDataAction action, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Deny the action in the permission set.
void mdata_permissions_set_deny(App const* app, MDataPermissionSetHandle set_h, MDataAction action, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Clear the actions in the permission set.
void mdata_permissions_set_clear(App const* app, MDataPermissionSetHandle set_h, MDataAction action, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Read the permission set.
void mdata_permissions_set_is_allowed(App const* app, MDataPermissionSetHandle set_h, MDataAction action, void* user_data, void (*o_cb)(void* , FfiResult , PermissionValue ));

/// Free the permission set from memory.
void mdata_permissions_set_free(App const* app, MDataPermissionSetHandle set_h, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Create new permissions.
void mdata_permissions_new(App const* app, void* user_data, void (*o_cb)(void* , FfiResult , MDataPermissionsHandle ));

/// Get the number of entries in the permissions.
void mdata_permissions_len(App const* app, MDataPermissionsHandle permissions_h, void* user_data, void (*o_cb)(void* , FfiResult , uintptr_t ));

/// Get the permission set corresponding to the given user.
/// Use a constant `USER_ANYONE` for anyone.
void mdata_permissions_get(App const* app, MDataPermissionsHandle permissions_h, SignKeyHandle user_h, void* user_data, void (*o_cb)(void* , FfiResult , MDataPermissionSetHandle ));

/// Iterate over the permissions.
/// The `each_cb` is called for each (user, permission set) pair in the permissions.
/// The `done_cb` is called after the iterations is over, or in case of error.
void mdata_permissions_for_each(App const* app, MDataPermissionsHandle permissions_h, void (*each_cb)(void* , SignKeyHandle , MDataPermissionSetHandle ), void* user_data, void (*done_cb)(void* , FfiResult ));

/// Insert permission set for the given user to the permissions.
///
/// To insert permissions for "Anyone", pass `USER_ANYONE` as the user handle.
void mdata_permissions_insert(App const* app, MDataPermissionsHandle permissions_h, SignKeyHandle user_h, MDataPermissionSetHandle permission_set_h, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Free the permissions from memory.
void mdata_permissions_free(App const* app, MDataPermissionsHandle permissions_h, void* user_data, void (*o_cb)(void* , FfiResult ));



#ifdef __cplusplus
}
#endif


#endif
