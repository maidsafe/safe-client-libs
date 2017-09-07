
#ifndef cheddar_generated_resp_h
#define cheddar_generated_resp_h


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>



/// Represents the authentication response.
typedef struct AuthGranted {
	/// The access keys.
	AppKeys app_keys;
	/// Access container
	AccessContInfo access_container;
	/// Crust's bootstrap config
	uint8_t* bootstrap_config_ptr;
	/// `bootstrap_config`'s length
	uintptr_t bootstrap_config_len;
	/// Used by Rust memory allocator
	uintptr_t bootstrap_config_cap;
} AuthGranted;

/// Represents the needed keys to work with the data.
typedef struct AppKeys {
	/// Owner signing public key
	SignPublicKey owner_key;
	/// Data symmetric encryption key
	SymSecretKey enc_key;
	/// Asymmetric sign public key.
	///
	/// This is the identity of the App in the Network.
	SignPublicKey sign_pk;
	/// Asymmetric sign private key.
	SignSecretKey sign_sk;
	/// Asymmetric enc public key.
	AsymPublicKey enc_pk;
	/// Asymmetric enc private key.
	AsymSecretKey enc_sk;
} AppKeys;

/// Access container
typedef struct AccessContInfo {
	/// ID
	XorNameArray id;
	/// Type tag
	uint64_t tag;
	/// Nonce
	SymNonce nonce;
} AccessContInfo;

/// Information about an application that has access to an MD through `sign_key`
typedef struct AppAccess {
	/// App's or user's public key
	SignPublicKey sign_key;
	/// A list of permissions
	FfiPermissionSet permissions;
	/// App's user-facing name
	char const* name;
	/// App id.
	/// This is u8, as the app-id can contain non-printable characters.
	char const* app_id;
} AppAccess;

/// User metadata for mutable data
typedef struct MetadataResponse {
	/// Name or purpose of this mutable data.
	char const* name;
	/// Description of how this mutable data should or should not be shared.
	char const* description;
	/// Xor name of this struct's corresponding MData object.
	XorNameArray xor_name;
	/// Type tag of this struct's corresponding MData object.
	uint64_t type_tag;
} MetadataResponse;



#ifdef __cplusplus
}
#endif


#endif
