
#ifndef cheddar_generated_metadata_h
#define cheddar_generated_metadata_h


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>



/// Serialize metadata.
void mdata_encode_metadata(MetadataResponse const* metadata, void* user_data, void (*o_cb)(void* , FfiResult , uint8_t const* , uintptr_t ));



#ifdef __cplusplus
}
#endif


#endif
