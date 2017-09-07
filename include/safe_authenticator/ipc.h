
#ifndef cheddar_generated_ipc_h
#define cheddar_generated_ipc_h


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>



/// Decodes a given encoded IPC message without requiring an authorised account
void auth_unregistered_decode_ipc_msg(char const* msg, void* user_data, void (*o_unregistered)(void* , uint32_t ), void (*o_err)(void* , FfiResult , char const* ));

/// Decodes a given encoded IPC message and calls a corresponding callback
void auth_decode_ipc_msg(Authenticator const* auth, char const* msg, void* user_data, void (*o_auth)(void* , uint32_t , FfiAuthReq const* ), void (*o_containers)(void* , uint32_t , FfiContainersReq const* ), void (*o_unregistered)(void* , uint32_t ), void (*o_share_mdata)(void* , uint32_t , FfiShareMDataReq const* , FfiUserMetadata const* ), void (*o_err)(void* , FfiResult , char const* ));

/// Encode share mutable data response.
void encode_share_mdata_resp(Authenticator const* auth, FfiShareMDataReq const* req, uint32_t req_id, bool is_granted, void* user_data, void (*o_cb)(void* , FfiResult , char const* ));

/// Revoke app access
void auth_revoke_app(Authenticator const* auth, char const* app_id, void* user_data, void (*o_cb)(void* , FfiResult , char const* ));

/// Flush the revocation queue.
void auth_flush_app_revocation_queue(Authenticator const* auth, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Encodes a response to unregistered client authentication request
void encode_unregistered_resp(uint32_t req_id, bool is_granted, void* user_data, void (*o_cb)(void* , FfiResult , char const* ));

/// Provides and encodes an Authenticator response
void encode_auth_resp(Authenticator const* auth, FfiAuthReq const* req, uint32_t req_id, bool is_granted, void* user_data, void (*o_cb)(void* , FfiResult , char const* ));

/// Update containers permissions for an App
void encode_containers_resp(Authenticator const* auth, FfiContainersReq const* req, uint32_t req_id, bool is_granted, void* user_data, void (*o_cb)(void* , FfiResult , char const* ));



#ifdef __cplusplus
}
#endif


#endif
