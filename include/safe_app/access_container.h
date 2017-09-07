
#ifndef cheddar_generated_access_container_h
#define cheddar_generated_access_container_h


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>



/// Fetch access info from the network.
void access_container_refresh_access_info(App const* app, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Retrieve a list of container names that an app has access to.
void access_container_fetch(App const* app, void* user_data, void (*o_cb)(void* , FfiResult , ContainerPermissions const* , uintptr_t ));

/// Retrieve `MDataInfo` for the given container name from the access container.
void access_container_get_container_mdata_info(App const* app, char const* name, void* user_data, void (*o_cb)(void* , FfiResult , MDataInfoHandle ));



#ifdef __cplusplus
}
#endif


#endif
