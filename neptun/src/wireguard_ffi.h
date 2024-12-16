// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#ifndef WIREGUARD_FFI_H
#define WIREGUARD_FFI_H
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct wireguard_tunnel; // This corresponds to the Rust type

enum
{
    MAX_WIREGUARD_PACKET_SIZE = 65536 + 64,
    HANDSHAKE_INIT_SZ = 148,
};

enum result_type
{
    WIREGUARD_DONE = 0,
    WRITE_TO_NETWORK = 1,
    WIREGUARD_ERROR = 2,
    WRITE_TO_TUNNEL_IPV4 = 4,
    WRITE_TO_TUNNEL_IPV6 = 6,
};

struct wireguard_result
{
    enum result_type op;
    size_t size;
};

struct wireguard_stats
{
    int64_t time_since_last_handshake;
    size_t tx_bytes;
    size_t rx_bytes;
    float estimated_loss;
    int32_t estimated_rtt; // rtt estimated on time it took to complete latest initiated handshake in ms
    uint8_t reserved[56];  // decrement appropriately when adding new fields
};

struct wireguard_x25519_key
{
    uint8_t key[32];
};

// Generates a fresh x25519 secret key
struct wireguard_x25519_key wireguard_x25519_secret_key();
// Computes an x25519 public key from a secret key
struct wireguard_x25519_key wireguard_x25519_public_key(struct wireguard_x25519_key private_key);
// Encodes a public or private x25519 key to base64. Must be freed with x25519_key_to_str_free.
const char *wireguard_x25519_key_to_base64(struct wireguard_x25519_key key);
// Encodes a public or private x25519 key to hex. Must be freed with x25519_key_to_str_free.
const char *wireguard_x25519_key_to_hex(struct wireguard_x25519_key key);
// Free string pointer obtained from either x25519_key_to_base64 or x25519_key_to_hex
void wireguard_x25519_key_to_str_free(const char *key_str);
// Check if a null terminated string represents a valid x25519 key
// Returns 0 if not
int wireguard_check_base64_encoded_x25519_key(const char *key);

/// Sets the default tracing_subscriber to write to `log_func`.
///
/// Uses Compact format without level, target, thread ids, thread names, or ansi control characters.
/// Subscribes to TRACE level events.
///
/// This function should only be called once as setting the default tracing_subscriber
/// more than once will result in an error.
///
/// Returns false on failure.
///
/// # Safety
///
/// `c_char` will be freed by the library after calling `log_func`. If the value needs
/// to be stored then `log_func` needs to create a copy, e.g. `strcpy`.
bool wireguard_set_logging_function(void (*log_func)(const char *));

// Allocate a new tunnel
struct wireguard_tunnel *wireguard_new_tunnel(const struct wireguard_x25519_key *static_private,
                                    const struct wireguard_x25519_key *server_static_public,
                                    const struct wireguard_x25519_key *preshared_key,
                                    uint16_t keep_alive, // Keep alive interval in seconds
                                    uint32_t index);      // The 24bit index prefix to be used for session indexes

// Deallocate the tunnel
void wireguard_tunnel_free(struct wireguard_tunnel *);

struct wireguard_result wireguard_write(const struct wireguard_tunnel *tunnel,
                                        const uint8_t *src,
                                        uint32_t src_size,
                                        uint8_t *dst,
                                        uint32_t dst_size);

struct wireguard_result wireguard_read(const struct wireguard_tunnel *tunnel,
                                       const uint8_t *src,
                                       uint32_t src_size,
                                       uint8_t *dst,
                                       uint32_t dst_size);

struct wireguard_result wireguard_tick(const struct wireguard_tunnel *tunnel,
                                       uint8_t *dst,
                                       uint32_t dst_size);

struct wireguard_result wireguard_force_handshake(const struct wireguard_tunnel *tunnel,
                                                  uint8_t *dst,
                                                  uint32_t dst_size);

int32_t wireguard_parse_handshake_anon(const struct wireguard_x25519_key *private_key,
                                    const struct wireguard_x25519_key *public_key,
                                    const uint8_t *src,
                                    uint32_t src_size,
                                    struct wireguard_x25519_key *peer_key);

#ifdef __cplusplus
}
#endif
