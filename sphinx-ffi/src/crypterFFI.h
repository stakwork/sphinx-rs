// This file was autogenerated by some hot garbage in the `uniffi` crate.
// Trust me, you don't want to mess with it!

#pragma once

#include <stdbool.h>
#include <stdint.h>

// The following structs are used to implement the lowest level
// of the FFI, and thus useful to multiple uniffied crates.
// We ensure they are declared exactly once, with a header guard, UNIFFI_SHARED_H.
#ifdef UNIFFI_SHARED_H
    // We also try to prevent mixing versions of shared uniffi header structs.
    // If you add anything to the #else block, you must increment the version suffix in UNIFFI_SHARED_HEADER_V4
    #ifndef UNIFFI_SHARED_HEADER_V4
        #error Combining helper code from multiple versions of uniffi is not supported
    #endif // ndef UNIFFI_SHARED_HEADER_V4
#else
#define UNIFFI_SHARED_H
#define UNIFFI_SHARED_HEADER_V4
// ⚠️ Attention: If you change this #else block (ending in `#endif // def UNIFFI_SHARED_H`) you *must* ⚠️
// ⚠️ increment the version suffix in all instances of UNIFFI_SHARED_HEADER_V4 in this file.           ⚠️

typedef struct RustBuffer
{
    int32_t capacity;
    int32_t len;
    uint8_t *_Nullable data;
} RustBuffer;

typedef int32_t (*ForeignCallback)(uint64_t, int32_t, RustBuffer, RustBuffer *_Nonnull);

typedef struct ForeignBytes
{
    int32_t len;
    const uint8_t *_Nullable data;
} ForeignBytes;

// Error definitions
typedef struct RustCallStatus {
    int8_t code;
    RustBuffer errorBuf;
} RustCallStatus;

// ⚠️ Attention: If you change this #else block (ending in `#endif // def UNIFFI_SHARED_H`) you *must* ⚠️
// ⚠️ increment the version suffix in all instances of UNIFFI_SHARED_HEADER_V4 in this file.           ⚠️
#endif // def UNIFFI_SHARED_H

RustBuffer crypter_5b86_pubkey_from_secret_key(
      RustBuffer my_secret_key,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer crypter_5b86_derive_shared_secret(
      RustBuffer their_pubkey,RustBuffer my_secret_key,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer crypter_5b86_encrypt(
      RustBuffer plaintext,RustBuffer secret,RustBuffer nonce,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer crypter_5b86_decrypt(
      RustBuffer ciphertext,RustBuffer secret,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer crypter_5b86_node_keys(
      RustBuffer net,RustBuffer seed,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer crypter_5b86_mnemonic_from_entropy(
      RustBuffer seed,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer crypter_5b86_entropy_from_mnemonic(
      RustBuffer mnemonic,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer crypter_5b86_get_nonce_request(
      RustBuffer secret,uint64_t nonce,
    RustCallStatus *_Nonnull out_status
    );
uint64_t crypter_5b86_get_nonce_response(
      RustBuffer bytes,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer crypter_5b86_reset_wifi_request(
      RustBuffer secret,uint64_t nonce,
    RustCallStatus *_Nonnull out_status
    );
void crypter_5b86_reset_wifi_response(
      RustBuffer bytes,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer crypter_5b86_reset_keys_request(
      RustBuffer secret,uint64_t nonce,
    RustCallStatus *_Nonnull out_status
    );
void crypter_5b86_reset_keys_response(
      RustBuffer bytes,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer crypter_5b86_reset_all_request(
      RustBuffer secret,uint64_t nonce,
    RustCallStatus *_Nonnull out_status
    );
void crypter_5b86_reset_all_response(
      RustBuffer bytes,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer crypter_5b86_get_policy_request(
      RustBuffer secret,uint64_t nonce,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer crypter_5b86_get_policy_response(
      RustBuffer bytes,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer crypter_5b86_update_policy_request(
      RustBuffer secret,uint64_t nonce,RustBuffer policy,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer crypter_5b86_update_policy_response(
      RustBuffer bytes,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer crypter_5b86_get_allowlist_request(
      RustBuffer secret,uint64_t nonce,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer crypter_5b86_get_allowlist_response(
      RustBuffer bytes,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer crypter_5b86_update_allowlist_request(
      RustBuffer secret,uint64_t nonce,RustBuffer allowlist,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer crypter_5b86_update_allowlist_response(
      RustBuffer bytes,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer crypter_5b86_ota_request(
      RustBuffer secret,uint64_t nonce,uint64_t version,RustBuffer url,
    RustCallStatus *_Nonnull out_status
    );
uint64_t crypter_5b86_ota_response(
      RustBuffer bytes,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer ffi_crypter_5b86_rustbuffer_alloc(
      int32_t size,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer ffi_crypter_5b86_rustbuffer_from_bytes(
      ForeignBytes bytes,
    RustCallStatus *_Nonnull out_status
    );
void ffi_crypter_5b86_rustbuffer_free(
      RustBuffer buf,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer ffi_crypter_5b86_rustbuffer_reserve(
      RustBuffer buf,int32_t additional,
    RustCallStatus *_Nonnull out_status
    );
