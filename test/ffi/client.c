#include "common.h"

#define PROGRAM_NAME "client"

int main(int argc, char** argv)
{
    int err;
    const char* keyname = argc > 1 ? argv[1] : "client";
    const char* keyname_server = argc > 2 ? argv[2] : "server";

    struct x25519_key key, pubkey;
    struct x25519_key server_pubkey;
    err = load_keypair(keyname, &key, &pubkey);
    if (err != 0) {
        fprintf(stderr, "Failed to load keypair: %s\n", keyname);
        return 1;
    }
    fprintf(stderr, "loaded client key pair (PUB:%s,PRIV:********************************************)\n",
        print_key(&pubkey));

    err = load_keypair(keyname_server, NULL, &server_pubkey);
    if (err < 0) {
        fprintf(stderr, "Failed to load public key: %s\n", keyname);
        return 1;
    }

    fprintf(stderr, "loaded server key (PUB:%s)\n",
        print_key(&server_pubkey));

    return 0;
}
