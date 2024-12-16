#include "common.h"

#include "TestCommon.h"

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

} // namespace
