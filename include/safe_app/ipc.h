
#ifndef cheddar_generated_ipc_h
#define cheddar_generated_ipc_h


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>



/// Encode `AuthReq`.
void encode_auth_req(FfiAuthReq const* req, void* user_data, void (*o_cb)(void* , FfiResult , uint32_t , char const* ));

/// Encode `ContainersReq`.
void encode_containers_req(FfiContainersReq const* req, void* user_data, void (*o_cb)(void* , FfiResult , uint32_t , char const* ));

/// Encode `AuthReq` for an unregistered client.
void encode_unregistered_req(void* user_data, void (*o_cb)(void* , FfiResult , uint32_t , char const* ));

/// Encode `ShareMDataReq`.
void encode_share_mdata_req(FfiShareMDataReq const* req, void* user_data, void (*o_cb)(void* , FfiResult , uint32_t , char const* ));

/// Decode IPC message.
void decode_ipc_msg(char const* msg, void* user_data, void (*o_auth)(void* , uint32_t , FfiAuthGranted const* ), void (*o_unregistered)(void* , uint32_t , uint8_t const* , uintptr_t ), void (*o_containers)(void* , uint32_t ), void (*o_share_mdata)(void* , uint32_t ), void (*o_revoked)(void* ), void (*o_err)(void* , FfiResult , uint32_t ));



#ifdef __cplusplus
}
#endif


#endif
