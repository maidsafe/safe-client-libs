
#ifndef cheddar_generated_req_h
#define cheddar_generated_req_h


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>



/// Represents a requested set of changes to the permissions of a mutable data.
typedef struct PermissionSet {
	/// How to modify the read permission.
	bool read;
	/// How to modify the insert permission.
	bool insert;
	/// How to modify the update permission.
	bool update;
	/// How to modify the delete permission.
	bool delete;
	/// How to modify the manage permissions permission.
	bool manage_permissions;
} PermissionSet;

/// Represents an authorization request
typedef struct AuthReq {
	/// The application identifier for this request
	AppExchangeInfo app;
	/// `true` if the app wants dedicated container for itself. `false`
	/// otherwise.
	bool app_container;
	/// Array of `ContainerPermissions`
	ContainerPermissions const* containers;
	/// Size of container permissions array
	uintptr_t containers_len;
	/// Capacity of container permissions array. Internal field
	/// required for the Rust allocator.
	uintptr_t containers_cap;
} AuthReq;

/// Containers request
typedef struct ContainersReq {
	/// Exchange info
	AppExchangeInfo app;
	/// Requested containers
	ContainerPermissions const* containers;
	/// Size of requested containers array
	uintptr_t containers_len;
	/// Capacity of requested containers array. Internal field
	/// required for the Rust allocator.
	uintptr_t containers_cap;
} ContainersReq;

/// Represents an application ID in the process of asking permissions
typedef struct AppExchangeInfo {
	/// UTF-8 encoded id
	char const* id;
	/// Reserved by the frontend
	///
	/// null if not present
	char const* scope;
	/// UTF-8 encoded application friendly-name.
	char const* name;
	/// UTF-8 encoded application provider/vendor (e.g. MaidSafe)
	char const* vendor;
} AppExchangeInfo;

/// Represents the set of permissions for a given container
typedef struct ContainerPermissions {
	/// The UTF-8 encoded id
	char const* cont_name;
	/// The requested permission set
	PermissionSet access;
} ContainerPermissions;

/// Represents a request to share mutable data
typedef struct ShareMDataReq {
	/// Info about the app requesting shared access
	AppExchangeInfo app;
	/// List of MD names & type tags and permissions that need to be shared
	ShareMData const* mdata;
	/// Length of the mdata array
	uintptr_t mdata_len;
	/// Capacity of the mdata vec - internal implementation detail
	uintptr_t mdata_cap;
} ShareMDataReq;

/// For use in `ShareMDataReq`. Represents a specific `MutableData` that is being shared.
typedef struct ShareMData {
	/// The mutable data type.
	uint64_t type_tag;
	/// The mutable data name.
	XorName name;
	/// The permissions being requested.
	PermissionSet perms;
} ShareMData;



#ifdef __cplusplus
}
#endif


#endif
