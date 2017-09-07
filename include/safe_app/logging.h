
#ifndef cheddar_generated_logging_h
#define cheddar_generated_logging_h


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>



/// This function should be called to enable logging to a file.
/// If `output_file_name_override` is provided, then this path will be used for
/// the log output file.
void app_init_logging(char const* output_file_name_override, void* user_data, void (*o_cb)(void* , FfiResult ));

/// This function should be called to find where log file will be created. It
/// will additionally create an empty log file in the path in the deduced
/// location and will return the file name along with complete path to it.
void app_output_log_path(char const* output_file_name, void* user_data, void (*o_cb)(void* , FfiResult , char const* ));



#ifdef __cplusplus
}
#endif


#endif
