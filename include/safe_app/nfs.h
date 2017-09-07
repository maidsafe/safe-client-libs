
#ifndef cheddar_generated_nfs_h
#define cheddar_generated_nfs_h


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>



/// Retrieve file with the given name, and its version, from the directory.
void dir_fetch_file(App const* app, MDataInfoHandle parent_h, char const* file_name, void* user_data, void (*o_cb)(void* , FfiResult , File const* , uint64_t ));

/// Insert the file into the parent directory.
void dir_insert_file(App const* app, MDataInfoHandle parent_h, char const* file_name, File const* file, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Replace the file in the parent directory.
/// If `version` is 0, the correct version is obtained automatically.
void dir_update_file(App const* app, MDataInfoHandle parent_h, char const* file_name, File const* file, uint64_t version, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Delete the file in the parent directory.
void dir_delete_file(App const* app, MDataInfoHandle parent_h, char const* file_name, uint64_t version, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Open the file to read of write its contents
void file_open(App const* app, MDataInfoHandle parent_h, File const* file, uint64_t open_mode, void* user_data, void (*o_cb)(void* , FfiResult , FileContextHandle ));

/// Get a size of file opened for read.
void file_size(App const* app, FileContextHandle file_h, void* user_data, void (*o_cb)(void* , FfiResult , uint64_t ));

/// Read data from file.
void file_read(App const* app, FileContextHandle file_h, uint64_t position, uint64_t len, void* user_data, void (*o_cb)(void* , FfiResult , uint8_t const* , uintptr_t ));

/// Write data to file in smaller chunks.
void file_write(App const* app, FileContextHandle file_h, uint8_t const* data, uintptr_t size, void* user_data, void (*o_cb)(void* , FfiResult ));

/// Close is invoked only after all the data is completely written. The
/// file is saved only when `close` is invoked.
///
/// If the file was opened in any of the read modes, returns the modified
/// file structure as a result. If the file was opened in the read mode,
/// returns the original file structure that was passed as an argument to
/// `file_open`.
void file_close(App const* app, FileContextHandle file_h, void* user_data, void (*o_cb)(void* , FfiResult , File const* ));



#ifdef __cplusplus
}
#endif


#endif
