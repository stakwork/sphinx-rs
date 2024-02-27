// This file was autogenerated by some hot garbage in the `uniffi` crate.
// Trust me, you don't want to mess with it!

#pragma once

#include <stdbool.h>
#include <stddef.h>
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

typedef int32_t (*ForeignCallback)(uint64_t, int32_t, const uint8_t *_Nonnull, int32_t, RustBuffer *_Nonnull);

// Task defined in Rust that Swift executes
typedef void (*UniFfiRustTaskCallback)(const void * _Nullable);

// Callback to execute Rust tasks using a Swift Task
//
// Args:
//   executor: ForeignExecutor lowered into a size_t value
//   delay: Delay in MS
//   task: UniFfiRustTaskCallback to call
//   task_data: data to pass the task callback
typedef void (*UniFfiForeignExecutorCallback)(size_t, uint32_t, UniFfiRustTaskCallback _Nullable, const void * _Nullable);

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

// Callbacks for UniFFI Futures
typedef void (*UniFfiFutureCallbackRustBuffer)(const void * _Nonnull, RustBuffer, RustCallStatus);

// Scaffolding functions
RustBuffer uniffi_sphinxrs_fn_func_pubkey_from_secret_key(RustBuffer my_secret_key, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_derive_shared_secret(RustBuffer their_pubkey, RustBuffer my_secret_key, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_encrypt(RustBuffer plaintext, RustBuffer secret, RustBuffer nonce, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_decrypt(RustBuffer ciphertext, RustBuffer secret, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_node_keys(RustBuffer net, RustBuffer seed, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_mnemonic_from_entropy(RustBuffer entropy, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_entropy_from_mnemonic(RustBuffer mnemonic, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_mnemonic_to_seed(RustBuffer mnemonic, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_entropy_to_seed(RustBuffer entropy, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_build_request(RustBuffer msg, RustBuffer secret, uint64_t nonce, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_parse_response(RustBuffer res, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_make_auth_token(uint32_t ts, RustBuffer secret, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_run(RustBuffer topic, RustBuffer args, RustBuffer state, RustBuffer msg1, RustBuffer expected_sequence, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_sha_256(RustBuffer msg, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_create_onion(RustBuffer seed, uint64_t idx, RustBuffer time, RustBuffer network, RustBuffer hops, RustBuffer payload, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_create_onion_msg(RustBuffer seed, uint64_t idx, RustBuffer time, RustBuffer network, RustBuffer hops, RustBuffer json, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_create_keysend(RustBuffer seed, uint64_t idx, RustBuffer time, RustBuffer network, RustBuffer hops, uint64_t msat, RustBuffer rhash, RustBuffer payload, uint32_t curr_height, RustBuffer preimage, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_create_keysend_msg(RustBuffer seed, uint64_t idx, RustBuffer time, RustBuffer network, RustBuffer hops, uint64_t msat, RustBuffer rhash, RustBuffer msg_json, uint32_t curr_height, RustBuffer preimage, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_peel_onion(RustBuffer seed, uint64_t idx, RustBuffer time, RustBuffer network, RustBuffer payload, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_peel_onion_msg(RustBuffer seed, uint64_t idx, RustBuffer time, RustBuffer network, RustBuffer payload, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_peel_payment(RustBuffer seed, uint64_t idx, RustBuffer time, RustBuffer network, RustBuffer payload, RustBuffer rhash, uint32_t cur_height, uint32_t cltv_expiry, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_peel_payment_msg(RustBuffer seed, uint64_t idx, RustBuffer time, RustBuffer network, RustBuffer payload, RustBuffer rhash, uint32_t cur_height, uint32_t cltv_expiry, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_sign_ms(RustBuffer seed, uint64_t idx, RustBuffer time, RustBuffer network, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_sign_bytes(RustBuffer seed, uint64_t idx, RustBuffer time, RustBuffer network, RustBuffer msg, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_pubkey_from_seed(RustBuffer seed, uint64_t idx, RustBuffer time, RustBuffer network, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_root_sign_ms(RustBuffer seed, RustBuffer time, RustBuffer network, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_xpub_from_seed(RustBuffer seed, RustBuffer time, RustBuffer network, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_set_network(RustBuffer network, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_set_blockheight(uint32_t blockheight, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_add_contact(RustBuffer seed, RustBuffer unique_time, RustBuffer state, RustBuffer to_pubkey, RustBuffer route_hint, RustBuffer my_alias, RustBuffer my_img, uint64_t amt_msat, RustBuffer invite_code, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_get_contact(RustBuffer state, RustBuffer pubkey, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_list_contacts(RustBuffer state, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_get_subscription_topic(RustBuffer seed, RustBuffer unique_time, RustBuffer state, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_get_tribe_management_topic(RustBuffer seed, RustBuffer unique_time, RustBuffer state, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_initial_setup(RustBuffer seed, RustBuffer unique_time, RustBuffer state, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_fetch_msgs(RustBuffer seed, RustBuffer unique_time, RustBuffer state, uint64_t last_msg_idx, RustBuffer limit, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_handle(RustBuffer topic, RustBuffer payload, RustBuffer seed, RustBuffer unique_time, RustBuffer state, RustBuffer my_alias, RustBuffer my_img, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_send(RustBuffer seed, RustBuffer unique_time, RustBuffer to, uint8_t msg_type, RustBuffer msg_json, RustBuffer state, RustBuffer my_alias, RustBuffer my_img, uint64_t amt_msat, int8_t is_tribe, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_make_media_token(RustBuffer seed, RustBuffer unique_time, RustBuffer state, RustBuffer host, RustBuffer muid, RustBuffer to, uint32_t expiry, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_make_media_token_with_meta(RustBuffer seed, RustBuffer unique_time, RustBuffer state, RustBuffer host, RustBuffer muid, RustBuffer to, uint32_t expiry, RustBuffer meta, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_make_media_token_with_price(RustBuffer seed, RustBuffer unique_time, RustBuffer state, RustBuffer host, RustBuffer muid, RustBuffer to, uint32_t expiry, uint64_t price, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_make_invoice(RustBuffer seed, RustBuffer unique_time, RustBuffer state, uint64_t amt_msat, RustBuffer preimage, RustBuffer description, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_create_tribe(RustBuffer seed, RustBuffer unique_time, RustBuffer state, RustBuffer tribe_server_pubkey, RustBuffer tribe_json, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_join_tribe(RustBuffer seed, RustBuffer unique_time, RustBuffer state, RustBuffer tribe_pubkey, RustBuffer tribe_route_hint, RustBuffer alias, uint64_t amt_msat, int8_t is_private, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_list_tribe_members(RustBuffer seed, RustBuffer unique_time, RustBuffer state, RustBuffer tribe_server_pubkey, RustBuffer tribe_pubkey, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_make_invite(RustBuffer seed, RustBuffer unique_time, RustBuffer state, RustBuffer host, uint64_t amt_msat, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_process_invite(RustBuffer seed, RustBuffer unique_time, RustBuffer state, RustBuffer invite_qr, RustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_sphinxrs_fn_func_code_from_invite(RustBuffer invite_qr, RustCallStatus *_Nonnull out_status
);
RustBuffer ffi_sphinxrs_rustbuffer_alloc(int32_t size, RustCallStatus *_Nonnull out_status
);
RustBuffer ffi_sphinxrs_rustbuffer_from_bytes(ForeignBytes bytes, RustCallStatus *_Nonnull out_status
);
void ffi_sphinxrs_rustbuffer_free(RustBuffer buf, RustCallStatus *_Nonnull out_status
);
RustBuffer ffi_sphinxrs_rustbuffer_reserve(RustBuffer buf, int32_t additional, RustCallStatus *_Nonnull out_status
);
uint16_t uniffi_sphinxrs_checksum_func_pubkey_from_secret_key(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_derive_shared_secret(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_encrypt(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_decrypt(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_node_keys(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_mnemonic_from_entropy(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_entropy_from_mnemonic(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_mnemonic_to_seed(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_entropy_to_seed(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_build_request(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_parse_response(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_make_auth_token(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_run(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_sha_256(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_create_onion(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_create_onion_msg(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_create_keysend(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_create_keysend_msg(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_peel_onion(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_peel_onion_msg(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_peel_payment(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_peel_payment_msg(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_sign_ms(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_sign_bytes(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_pubkey_from_seed(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_root_sign_ms(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_xpub_from_seed(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_set_network(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_set_blockheight(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_add_contact(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_get_contact(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_list_contacts(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_get_subscription_topic(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_get_tribe_management_topic(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_initial_setup(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_fetch_msgs(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_handle(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_send(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_make_media_token(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_make_media_token_with_meta(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_make_media_token_with_price(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_make_invoice(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_create_tribe(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_join_tribe(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_list_tribe_members(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_make_invite(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_process_invite(void
    
);
uint16_t uniffi_sphinxrs_checksum_func_code_from_invite(void
    
);
uint32_t ffi_sphinxrs_uniffi_contract_version(void
    
);

