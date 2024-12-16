#include <assert.h>
#include "common.h"

#define PROGRAM_NAME "server"

struct client {
    const char* name;
    struct wireguard_tunnel *tunnel;
    struct x25519_key pubkey;
};

int main(int argc, char** argv)
{
    const char* default_keynames[] = { "client", NULL };

    int err = 0;
    const char* keyname = argc > 1 ? argv[1] : "server";
    const char** client_keynames = argc > 2 ? &argv[2] : &default_keynames[0];
    size_t num_clients = 0;
    while (default_keynames[num_clients]) {
        num_clients++;
    }

    struct client* clients = malloc(sizeof(struct client) * (num_clients+1));
    assert(clients);
    memset(clients, 0, sizeof(struct client) * (num_clients+1));

    struct x25519_key key, pubkey;
    err = load_keypair(keyname, &key, &pubkey);
    if (err != 0) {
        fprintf(stderr, "failed to load keypair: %s\n", keyname);
        err = 1;
        goto teardown;
    }
    fprintf(stderr, "loaded server key pair (PUB:%s,PRIV:********************************************)\n",
        print_key(&pubkey));

    setup_signal_handlers();
    setup_logging_callback();

    for (size_t i=0;i<num_clients;++i) {
        struct client* c = &clients[i];
        c->name = client_keynames[i];
        err = load_keypair(c->name, NULL, &c->pubkey);
        if (err < 0) {
            fprintf(stderr, "failed to load public key: %s\n", c->name);
            err = 1;
            goto teardown;
        }
        fprintf(stderr, "loaded client key: %s (PUB:%s)\n",
            client_keynames[i], print_key(&c->pubkey));

        c->tunnel = new_tunnel(&key, &pubkey, NULL, DEFAULT_KEEPALIVE, 0);
        if (!c->tunnel) {
            fprintf(stderr, "failed to open tunnel to client: %s\n", c->name);
            err = 1;
            goto teardown;
        }
        fprintf(stderr, "tunnel to client created: %s\n", c->name);
    }

    struct wireguard_result res;
    int done = 0;
    while (!done) {
        fprintf(stderr, "tick!\n");
        for (size_t i=0;i<num_clients;++i) {
            struct client* c = &clients[i];
            if (!c->tunnel) {
                continue;
            }
            uint8_t buffer[MAX_WIREGUARD_PACKET_SIZE];
            res = wireguard_tick(c->tunnel, buffer, sizeof(buffer));
            dump_result(res, buffer, sizeof(buffer));
        }
        fprintf(stderr, "sleeping...\n");
        err = sleep_ms(1000);
        if (err != 0) {
            fprintf(stderr, "interrupted!\n");
            done = 1;
        }
    }

    teardown:
    if (clients) {
        for (size_t i=0;i<num_clients;++i) {
            struct client* c = &clients[i];
            if (!c->tunnel) {
                continue;
            }

            assert(c->name);
            fprintf(stderr, "closing tunnel: %s\n", c->name);
            tunnel_free(c->tunnel);
            c->tunnel = NULL;
        }
        free(clients);
        clients = NULL;
    }

    return err;
}
