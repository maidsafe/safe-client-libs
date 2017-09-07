
#ifndef cheddar_generated_apps_h
#define cheddar_generated_apps_h


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>



/// Application registered in the authenticator
typedef struct RegisteredApp {
	/// Unique application identifier
	FfiAppExchangeInfo app_info;
	/// List of containers that this application has access to
	ContainerPermissions const* containers;
	/// Length of the containers array
	uintptr_t containers_len;
	/// Capacity of the containers array. Internal data required
	/// for the Rust allocator.
	uintptr_t containers_cap;
} RegisteredApp;

/// Removes a revoked app from the authenticator config
void auth_rm_revoked_app(Authenticator const* auth, char const* app_id, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Get a list of apps revoked from authenticator
void auth_revoked_apps(Authenticator const* auth, void* user_data, void (*o_cb)(void* , FfiResult , FfiAppExchangeInfo const* , uintptr_t ));

/// Get a list of apps registered in authenticator
void auth_registered_apps(Authenticator const* auth, void* user_data, void (*o_cb)(void* , FfiResult , RegisteredApp const* , uintptr_t ));

/// Return a list of apps having access to an arbitrary MD object.
/// `md_name` and `md_type_tag` together correspond to a single MD.
void auth_apps_accessing_mutable_data(Authenticator const* auth, XorNameArray const* md_name, uint64_t md_type_tag, void* user_data, void (*o_cb)(void* , FfiResult , FfiAppAccess const* , uintptr_t ));



#ifdef __cplusplus
}
#endif


#endif
