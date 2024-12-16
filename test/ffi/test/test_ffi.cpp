#include "common.h"

#include "TestCommon.h"

struct PtrDeleter {
    void operator()(struct wireguard_tunnel *t) const
    {
        tunnel_free(t);
    }
};

using TunnelPtr = std::unique_ptr<struct wireguard_tunnel, PtrDeleter>;

namespace {

using ::testing::Eq;

TEST(Keys, GenerateAndRoundtrip)
{
    auto key = x25519_secret_key();
    auto pubkey = x25519_public_key(key);

    std::string keyBase64 { print_key(&key) };
    struct x25519_key k {};
    EXPECT_EQ(load_key_base64(&k, keyBase64.c_str()), 0);
    EXPECT_EQ(keyBase64, print_key(&k));

    std::string pubkeyBase64 { print_key(&pubkey) };
    struct x25519_key pubk {};
    EXPECT_EQ(load_key_base64(&pubk, pubkeyBase64.c_str()), 0);
    EXPECT_EQ(pubkeyBase64, print_key(&pubk));

    auto pubkd = x25519_public_key(k);
    EXPECT_EQ(pubkeyBase64, print_key(&pubkd));
}

TEST(Tunnel, CreateAndDestroy)
{
    auto key = x25519_secret_key();
    auto pubkeyServer = x25519_public_key(x25519_secret_key());

    TunnelPtr tunnel {new_tunnel(&key, &pubkeyServer, nullptr, 0, 0)};
    EXPECT_TRUE(tunnel.get());

    tunnel.reset();
    EXPECT_FALSE(tunnel.get());
}

} // namespace
