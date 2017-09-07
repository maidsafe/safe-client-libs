
#ifndef cheddar_generated_safe_app_h
#define cheddar_generated_safe_app_h


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

#include "safe_app/access_container.h"
#include "safe_app/cipher_opt.h"
#include "safe_app/immutable_data.h"
#include "safe_app/ipc.h"
#include "safe_app/logging.h"
#include "safe_app/mdata_info.h"
#include "safe_app/crypto.h"
#include "safe_app/mutable_data.h"
#include "safe_app/mutable_data/entry_actions.h"
#include "safe_app/mutable_data/entries.h"
#include "safe_app/mutable_data/permissions.h"
#include "safe_app/mutable_data/metadata.h"
#include "safe_app/nfs.h"


/// Create unregistered app.
/// The `user_data` parameter corresponds to the first parameter of the
/// `o_cb` callback, while `network_cb_user_data` corresponds to the
/// first parameter of `o_network_observer_cb`.
void app_unregistered(uint8_t const* bootstrap_config_ptr, uintptr_t bootstrap_config_len, void* network_cb_user_data, void* user_data, void (*o_network_observer_cb)(void* , FfiResult , int32_t ), void (*o_cb)(void* , FfiResult , App* ));

/// Create a registered app.
/// The `user_data` parameter corresponds to the first parameter of the
/// `o_cb` callback, while `network_cb_user_data` corresponds to the
/// first parameter of `o_network_observer_cb`.
void app_registered(char const* app_id, FfiAuthGranted const* auth_granted, void* network_cb_user_data, void* user_data, void (*o_network_observer_cb)(void* , FfiResult , int32_t ), void (*o_cb)(void* , FfiResult , App* ));

/// Try to restore a failed connection with the network.
void app_reconnect(App* app, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Get the account usage statistics.
void app_account_info(App* app, void* user_data, void (*o_cb)(void* , FfiResult , FfiAccountInfo const* ));

/// Discard and clean up the previously allocated app instance.
/// Use this only if the app is obtained from one of the auth
/// functions in this crate. Using `app` after a call to this
/// function is undefined behaviour.
void app_free(App* app);



#ifdef __cplusplus
}
#endif


#endif
