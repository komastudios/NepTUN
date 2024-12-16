#include "common.h"
#include <assert.h>
#include <threads.h>
#include <signal.h>

#define BASE64_PAD '='
#define BASE64DE_FIRST '+'
#define BASE64DE_LAST 'z'

static const uint8_t base64de[] = {
    /* nul, soh, stx, etx, eot, enq, ack, bel, */
    255, 255, 255, 255, 255, 255, 255, 255,
 /*  bs,  ht,  nl,  vt,  np,  cr,  so,  si, */
    255, 255, 255, 255, 255, 255, 255, 255,
 /* dle, dc1, dc2, dc3, dc4, nak, syn, etb, */
    255, 255, 255, 255, 255, 255, 255, 255,
 /* can,  em, sub, esc,  fs,  gs,  rs,  us, */
    255, 255, 255, 255, 255, 255, 255, 255,
 /*  sp, '!', '"', '#', '$', '%', '&', ''', */
    255, 255, 255, 255, 255, 255, 255, 255,
 /* '(', ')', '*', '+', ',', '-', '.', '/', */
    255, 255, 255,  62, 255, 255, 255,  63,
 /* '0', '1', '2', '3', '4', '5', '6', '7', */
     52,  53,  54,  55,  56,  57,  58,  59,
 /* '8', '9', ':', ';', '<', '=', '>', '?', */
     60,  61, 255, 255, 255, 255, 255, 255,
 /* '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', */
    255,   0,   1,  2,   3,   4,   5,    6,
 /* 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', */
      7,   8,   9,  10,  11,  12,  13,  14,
 /* 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', */
     15,  16,  17,  18,  19,  20,  21,  22,
 /* 'X', 'Y', 'Z', '[', '\', ']', '^', '_', */
     23,  24,  25, 255, 255, 255, 255, 255,
 /* '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', */
    255,  26,  27,  28,  29,  30,  31,  32,
 /* 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', */
     33,  34,  35,  36,  37,  38,  39,  40,
 /* 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', */
     41,  42,  43,  44,  45,  46,  47,  48,
 /* 'x', 'y', 'z', '{', '|', '}', '~', del, */
     49,  50,  51, 255, 255, 255, 255, 255
};

bool is_file(const char* path)
{
    FILE* f = fopen(path, "rb");
    if (f) {
        fclose(f);
    }
    return !!f;
}

int load_keypair(const char* name, struct x25519_key* key, struct x25519_key* pubkey)
{
    int err = -1;
    char keyfile[PATH_MAX];
    snprintf(keyfile, sizeof(keyfile), "%s%s", name, KEYFILE_EXT);
    FILE* f = key ? fopen(keyfile, "rb") : NULL;
    struct x25519_key kbuf;
    if (f) {
        err = fread(&kbuf, sizeof(kbuf), 1, f) ? 0 : -1;
        fclose(f);
    }
    else {
        snprintf(keyfile, sizeof(keyfile), "%s%s", name, PUBKEY_EXT);
        f = fopen(keyfile, "rb");
        if (f) {
            err = fread(&kbuf, sizeof(kbuf), 1, f) ? 1 : -1;
            fclose(f);
        }
    }
    if (err == 0) {
        if (key) {
            *key = kbuf;
        }
        if (pubkey) {
            *pubkey = x25519_public_key(kbuf);
        }
    }
    else if (err == 1) {
        if (pubkey) {
            *pubkey = kbuf;
        }
    }
    return err;
}

int save_key(const char* name, struct x25519_key* key, struct x25519_key* pubkey)
{
    assert(key);
    assert(pubkey);
    int err = -1;
    char keyfile[PATH_MAX];
    snprintf(keyfile, sizeof(keyfile), "%s%s", name, KEYFILE_EXT);
    FILE* f = fopen(keyfile, "wb");
    if (f) {
        err = fwrite(key, sizeof(struct x25519_key), 1, f) == 1 ? 0 : -1;
        fclose(f);
    }
    snprintf(keyfile, sizeof(keyfile), "%s%s", name, PUBKEY_EXT);
    f = fopen(keyfile, "wb");
    if (f) {
        err = fwrite(pubkey, sizeof(struct x25519_key), 1, f) == 1 ? 0 : -1;
        fclose(f);
    }
    return err;
}

void dump_key(const char* name, struct x25519_key* pubkey)
{
    assert(pubkey);
    const char* str = x25519_key_to_base64(*pubkey);
    assert(str);
    fprintf(stdout, "%s %s\n", name, str);
    x25519_key_to_str_free(str);
}

static const char* result_type_str(int type)
{
    switch (type) {
        case WIREGUARD_DONE:
            return "WIREGUARD_DONE";
        case WRITE_TO_NETWORK:
            return "WRITE_TO_NETWORK";
        case WIREGUARD_ERROR:
            return "WIREGUARD_ERROR";
        case WRITE_TO_TUNNEL_IPV4:
            return "WRITE_TO_TUNNEL_IPV4";
        case WRITE_TO_TUNNEL_IPV6:
            return "WRITE_TO_TUNNEL_IPV6";
        default:
            break;
    }
    return "UNKNOWN";
}

void dump_result(struct wireguard_result result, const uint8_t* buffer, size_t buffer_size)
{
    fprintf(stderr, "[wg] result (op=%s): [%d bytes] \n", result_type_str(result.op), (int)result.size);
}

const char* print_key(struct x25519_key* pubkey)
{
    static char result[45];
    memset(result, 0, sizeof(result));
    if (pubkey) {
        const char* str = x25519_key_to_base64(*pubkey);
        assert(str);
        snprintf(result, sizeof(result), "%s", str);
        x25519_key_to_str_free(str);
    }
    return result;
}

int load_key_base64(struct x25519_key* key, const char* input)
{
    assert(input);
    struct x25519_key kbuf;
    memset(&kbuf, 0, sizeof(kbuf));

    uint8_t* out = &kbuf.key[0];

    uint32_t i;
    uint32_t j;
    uint8_t c;

    for (i = j = 0; input[i]; i++) {
        uint8_t in = input[i];
        if (in == BASE64_PAD) {
            break;
        }
        if (in < BASE64DE_FIRST || in > BASE64DE_LAST) {
            return -1;
        }

        c = base64de[in];
        if (c == 255) {
            return -1;
        }

        switch (i & 0x3) {
            case 0:
                out[j] = (c << 2) & 0xFF;
            break;
            case 1:
                out[j++] |= (c >> 4) & 0x3;
            out[j] = (c & 0xF) << 4;
            break;
            case 2:
                out[j++] |= (c >> 2) & 0xF;
            out[j] = (c & 0x3) << 6;
            break;
            case 3:
                out[j++] |= c;
            break;

            default:
                break;
        }
    }

    if (j != sizeof(kbuf)) {
        return -1;
    }

    if (key)
        *key = kbuf;

    return 0;
}

void wg_log_print(const char *ch)
{
    fprintf("[wg] %s", ch);
}

volatile sig_atomic_t gSignalStatus;

void signal_handler(int signal)
{
    gSignalStatus = signal;
}

int setup_signal_handlers(void)
{
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    return 0;
}

int read_signal(int* signal)
{
    // TODO: use atomics for this
    int status = gSignalStatus;
    gSignalStatus = status;
    if (signal)
        *signal = status;
    return status != 0;
}

void setup_logging_callback(void)
{
    set_logging_function(&wg_log_print);
}

int sleep_ms(uint32_t ms)
{
    struct timespec tv = {
        .tv_sec = ms / 1000,
        .tv_nsec = (ms % 1000) * 1000000
    };
    return thrd_sleep(&tv, NULL);
}
