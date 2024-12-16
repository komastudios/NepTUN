#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "wireguard_ffi.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#ifndef PATH_MAX
#   define PATH_MAX 4096
#endif

#define KEYFILE_EXT ".key"
#define PUBKEY_EXT ".pub"

#define DEFAULT_PORT 5123
#define DEFAULT_KEEPALIVE 15
#define DEFAULT_HEXDUMP_LINE_LENGTH 16

int setup_signal_handlers(void);

int read_signal(int* signal);

void setup_logging_callback(void);

bool is_file(const char* path);

int load_keypair(const char* name, struct wireguard_x25519_key* key, struct wireguard_x25519_key* pubkey);

int save_key(const char* name, struct wireguard_x25519_key* key, struct wireguard_x25519_key* pubkey);

void dump_key(const char* name, struct wireguard_x25519_key* pubkey);

void dump_bytes(const uint8_t* buffer, size_t buffer_size);

void dump_result(struct wireguard_result result, const uint8_t* buffer);

const char* print_key(struct wireguard_x25519_key* pubkey);

int load_key_base64(struct wireguard_x25519_key* key, const char* input);

int sleep_ms(uint32_t ms);

#ifdef __cplusplus
}
#endif
