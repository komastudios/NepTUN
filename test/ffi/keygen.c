#include "common.h"

#define PROGRAM_NAME "keygen"

int generate_key(const char* keyname)
{
    int err;
    struct x25519_key key, pubkey;

    err = load_keypair(keyname, &key, &pubkey);
    if (err != 0) {
        key = x25519_secret_key();
        pubkey = x25519_public_key(key);
        err = save_key(keyname, &key, &pubkey);
        if (err != 0) {
            fprintf(stderr, "WARN: failed to write key file!\n");
            exit(1);
        }
    }

    dump_key(keyname, &pubkey);

    return 0;
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <keyname> (<keyname> ...)\n", PROGRAM_NAME);
    }

    for (int i=1;i<argc;++i) {
        generate_key(argv[i]);
    }

    return 0;
}
