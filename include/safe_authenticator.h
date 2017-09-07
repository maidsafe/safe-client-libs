
#ifndef cheddar_generated_safe_authenticator_h
#define cheddar_generated_safe_authenticator_h


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

#include "safe_authenticator/apps.h"
#include "safe_authenticator/ipc.h"
#include "safe_authenticator/logging.h"


/// Create a registered client. This or any one of the other companion
/// functions to get an authenticator instance must be called before initiating any
/// operation allowed by this module. The `user_data` parameter corresponds to the
/// first parameter of the `o_cb` callback, while `network_cb_user_data` corresponds
/// to the first parameter of the network events observer callback (`o_network_obs_cb`).
void create_acc(char const* account_locator, char const* account_password, char const* invitation, void* network_cb_user_data, void* user_data, void (*o_network_obs_cb)(void* , int32_t , int32_t ), void (*o_cb)(void* , FfiResult , Authenticator* ));

/// Log into a registered account. This or any one of the other companion
/// functions to get an authenticator instance must be called before initiating
/// any operation allowed for authenticator. The `user_data` parameter corresponds to the
/// first parameter of the `o_cb` callback, while `network_cb_user_data` corresponds
/// to the first parameter of the network events observer callback (`o_network_obs_cb`).
void login(char const* account_locator, char const* account_password, void* user_data, void* network_cb_user_data, void (*o_network_obs_cb)(void* , int32_t , int32_t ), void (*o_cb)(void* , FfiResult , Authenticator* ));

/// Try to restore a failed connection with the network.
void auth_reconnect(Authenticator* auth, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Get the account usage statistics.
void auth_account_info(Authenticator* auth, void* user_data, void (*o_cb)(void* , FfiResult , FfiAccountInfo const* ));

/// Discard and clean up the previously allocated authenticator instance.
/// Use this only if the authenticator is obtained from one of the auth
/// functions in this crate (`create_acc`, `login`, `create_unregistered`).
/// Using `auth` after a call to this function is undefined behaviour.
void auth_free(Authenticator* auth);



#ifdef __cplusplus
}
#endif


#endif
