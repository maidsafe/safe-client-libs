
#ifndef cheddar_generated_safe_core_h
#define cheddar_generated_safe_core_h


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

#include "safe_core/nfs.h"
#include "safe_core/ipc/req.h"
#include "safe_core/ipc/resp.h"


/// Represents the FFI-safe account info
typedef struct AccountInfo {
	/// Number of used mutations
	uint64_t mutations_done;
	/// Number of available mutations
	uint64_t mutations_available;
} AccountInfo;



#ifdef __cplusplus
}
#endif


#endif
