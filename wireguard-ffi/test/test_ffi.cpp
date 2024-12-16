#include "common.h"

#include "TestCommon.h"

struct PtrDeleter {
    void operator()(struct wireguard_tunnel *t) const
    {
        wireguard_tunnel_free(t);
    }
};

using TunnelPtr = std::unique_ptr<struct wireguard_tunnel, PtrDeleter>;
using ByteVec = std::vector<uint8_t>;

namespace {

using ::testing::Eq;

TEST(Keys, GenerateAndRoundtrip)
{
    auto key = wireguard_x25519_secret_key();
    auto pubkey = wireguard_x25519_public_key(key);

    std::string keyBase64 { print_key(&key) };
    struct wireguard_x25519_key k {};
    EXPECT_EQ(load_key_base64(&k, keyBase64.c_str()), 0);
    EXPECT_EQ(keyBase64, print_key(&k));

    std::string pubkeyBase64 { print_key(&pubkey) };
    struct wireguard_x25519_key pubk {};
    EXPECT_EQ(load_key_base64(&pubk, pubkeyBase64.c_str()), 0);
    EXPECT_EQ(pubkeyBase64, print_key(&pubk));

    auto pubkd = wireguard_x25519_public_key(k);
    EXPECT_EQ(pubkeyBase64, print_key(&pubkd));
}

struct Tunnel : testing::Test {
    std::array<uint8_t, MAX_WIREGUARD_PACKET_SIZE> buffer {};
    wireguard_result result {};

    ByteVec getBytes()
    {
        ByteVec bytes;
        bytes.resize(result.size);
        if (!bytes.empty())
            memcpy(bytes.data(), buffer.data(), result.size);
        return bytes;
    }
};

TEST_F(Tunnel, CreateAndDestroy)
{
    auto key = wireguard_x25519_secret_key();
    auto pubkeyServer = wireguard_x25519_public_key(wireguard_x25519_secret_key());

    TunnelPtr tunnel {wireguard_new_tunnel(&key, &pubkeyServer, nullptr, 0, 0)};
    EXPECT_TRUE(tunnel.get());

    tunnel.reset();
    EXPECT_FALSE(tunnel.get());
}

TEST_F(Tunnel, HandleAnonHandshake)
{
    auto key = wireguard_x25519_secret_key();
    auto pubkey = wireguard_x25519_public_key(key);
    auto serverKey = wireguard_x25519_secret_key();
    auto pubkeyServer = wireguard_x25519_public_key(serverKey);

    TunnelPtr tunnel {wireguard_new_tunnel(&key, &pubkeyServer, nullptr, 0, 0)};
    EXPECT_TRUE(tunnel.get());

    result = wireguard_force_handshake(tunnel.get(),
      buffer.data(),
      buffer.size());

    dump_result(result, buffer.data());
    EXPECT_EQ(result.op, WRITE_TO_NETWORK);
    auto msgHandshake = getBytes();
    EXPECT_EQ(msgHandshake.size(), result.size);

    struct wireguard_x25519_key k {};
    int32_t err = wireguard_parse_handshake_anon(&serverKey, &pubkeyServer,
        msgHandshake.data(), msgHandshake.size(), &k);
    EXPECT_EQ(err, 0);

    std::string expectedKey { print_key(&pubkey) };
    std::string parsedKey { print_key(&k) };
    EXPECT_EQ(parsedKey, expectedKey);
}

} // namespace
