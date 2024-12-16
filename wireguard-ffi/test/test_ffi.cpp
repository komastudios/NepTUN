#include "common.h"

#include "TestCommon.h"

#include <utility>
#include <optional>
#include <span>

#include <vector>
#include <cstdint>
#include <cstring> // for memcpy
#include <stdexcept>

#define IPV4(a, b, c, d) ((static_cast<uint32_t>(a) << 24) | \
    (static_cast<uint32_t>(b) << 16) | \
    (static_cast<uint32_t>(c) << 8) | \
    static_cast<uint32_t>(d))

// Helper function to compute checksum (used for both IPv4 and UDP headers)
uint16_t computeChecksum(const uint8_t* data, size_t length) {
    uint32_t sum = 0;
    for (size_t i = 0; i < length; i += 2) {
        uint16_t word = data[i] << 8;
        if (i + 1 < length) {
            word |= data[i + 1];
        }
        sum += word;
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }
    return static_cast<uint16_t>(~sum);
}

std::vector<uint8_t> createIPv4UDPFrame(
    const std::vector<uint8_t>& payload,
    uint32_t srcIP,
    uint32_t destIP,
    uint16_t srcPort,
    uint16_t destPort
) {
    // Constants
    const size_t IPV4_HEADER_SIZE = 20;
    const size_t UDP_HEADER_SIZE = 8;

    // Validate input
    if (payload.size() > 65507) { // Max UDP payload size: 65535 - 20 (IP header) - 8 (UDP header)
        throw std::invalid_argument("Payload size exceeds maximum allowed for UDP.");
    }

    size_t totalLength = IPV4_HEADER_SIZE + UDP_HEADER_SIZE + payload.size();
    std::vector<uint8_t> frame(totalLength);

    // Construct IPv4 header
    frame[0] = 0x45; // Version (4) and IHL (5, which is 20 bytes)
    frame[1] = 0x00; // DSCP and ECN
    frame[2] = (totalLength >> 8) & 0xFF; // Total length (high byte)
    frame[3] = totalLength & 0xFF;        // Total length (low byte)
    frame[4] = 0x00; // Identification (high byte)
    frame[5] = 0x00; // Identification (low byte)
    frame[6] = 0x40; // Flags (Don't Fragment) and Fragment Offset (high byte)
    frame[7] = 0x00; // Fragment Offset (low byte)
    frame[8] = 0x40; // Time to Live (TTL)
    frame[9] = 0x11; // Protocol (UDP = 17)

    // Source IP
    frame[12] = (srcIP >> 24) & 0xFF;
    frame[13] = (srcIP >> 16) & 0xFF;
    frame[14] = (srcIP >> 8) & 0xFF;
    frame[15] = srcIP & 0xFF;

    // Destination IP
    frame[16] = (destIP >> 24) & 0xFF;
    frame[17] = (destIP >> 16) & 0xFF;
    frame[18] = (destIP >> 8) & 0xFF;
    frame[19] = destIP & 0xFF;

    // Compute IPv4 header checksum
    uint16_t ipChecksum = computeChecksum(frame.data(), IPV4_HEADER_SIZE);
    frame[10] = (ipChecksum >> 8) & 0xFF; // Header checksum (high byte)
    frame[11] = ipChecksum & 0xFF;        // Header checksum (low byte)

    // Construct UDP header
    size_t udpStart = IPV4_HEADER_SIZE;
    frame[udpStart + 0] = (srcPort >> 8) & 0xFF; // Source port (high byte)
    frame[udpStart + 1] = srcPort & 0xFF;        // Source port (low byte)
    frame[udpStart + 2] = (destPort >> 8) & 0xFF; // Destination port (high byte)
    frame[udpStart + 3] = destPort & 0xFF;        // Destination port (low byte)
    size_t udpLength = UDP_HEADER_SIZE + payload.size();
    frame[udpStart + 4] = (udpLength >> 8) & 0xFF; // Length (high byte)
    frame[udpStart + 5] = udpLength & 0xFF;        // Length (low byte)
    frame[udpStart + 6] = 0x00; // Checksum placeholder (high byte)
    frame[udpStart + 7] = 0x00; // Checksum placeholder (low byte)

    // Copy payload
    std::copy(payload.begin(), payload.end(), frame.begin() + IPV4_HEADER_SIZE + UDP_HEADER_SIZE);

    // Compute UDP checksum (pseudo-header + UDP header + payload)
    uint32_t pseudoHeaderSum = 0;
    pseudoHeaderSum += (srcIP >> 16) & 0xFFFF;
    pseudoHeaderSum += srcIP & 0xFFFF;
    pseudoHeaderSum += (destIP >> 16) & 0xFFFF;
    pseudoHeaderSum += destIP & 0xFFFF;
    pseudoHeaderSum += 0x0011; // Protocol (UDP)
    pseudoHeaderSum += udpLength;

    // Prepare UDP checksum computation buffer
    std::vector<uint8_t> udpChecksumBuffer(UDP_HEADER_SIZE + payload.size() + 12);
    memcpy(udpChecksumBuffer.data(), frame.data() + 12, 8); // Pseudo-header
    memcpy(udpChecksumBuffer.data() + 12, frame.data() + udpStart, UDP_HEADER_SIZE + payload.size());

    uint16_t udpChecksum = computeChecksum(udpChecksumBuffer.data(), udpChecksumBuffer.size());
    frame[udpStart + 6] = (udpChecksum >> 8) & 0xFF; // Checksum (high byte)
    frame[udpStart + 7] = udpChecksum & 0xFF;        // Checksum (low byte)

    return frame;
}

struct PtrDeleter {
    void operator()(struct wireguard_tunnel *t) const
    {
        wireguard_tunnel_free(t);
    }
};

using TunnelHnd = std::unique_ptr<struct wireguard_tunnel, PtrDeleter>;

struct StaticKey {
    struct wireguard_x25519_key key {};
};

struct PublicKey {
    struct wireguard_x25519_key key {};
};

struct PrivateKey {
    StaticKey priv {};
    PublicKey pub {};

    static PrivateKey Generate()
    {
        auto key = wireguard_x25519_secret_key();
        return { key, wireguard_x25519_public_key(key) };
    }
};

struct TunnelResult {
    struct wireguard_result res {};
    ByteVec data;
    void read(const uint8_t* src, size_t capa)
    {
        data.resize(res.size < capa ? res.size : capa);
        if (!data.empty())
            memcpy(data.data(), src, data.size());
    }

    void dump()
    {
        dump_result(res, data.data());
    }
};

struct Tunnel {
    TunnelHnd hnd;
    PrivateKey key;
    PublicKey serverKey;

    std::array<uint8_t, MAX_WIREGUARD_PACKET_SIZE> buffer {};

    static Tunnel Create(const PrivateKey& key, const PublicKey& serverKey,
        const std::optional<StaticKey>& sharedKey, uint16_t keep_alive, uint32_t index)
    {
        return Tunnel {
            .hnd = TunnelHnd {wireguard_new_tunnel(&key.priv.key, &serverKey.key,
                sharedKey.has_value() ? &sharedKey->key : nullptr, keep_alive, index) },
            .key = key,
            .serverKey = serverKey
        };
    }

    TunnelResult forceHandshake()
    {
        TunnelResult r;
        r.res = wireguard_force_handshake(hnd.get(), buffer.data(), buffer.size());
        r.read(buffer.data(), buffer.size());
        return r;
    }

    TunnelResult readMsg(ByteSpan msg)
    {
        TunnelResult r;
        r.res = wireguard_read(hnd.get(), msg.data(), msg.size(), buffer.data(), buffer.size());
        r.read(buffer.data(), buffer.size());
        return r;
    }

    TunnelResult writeMsg(ByteSpan msg)
    {
        TunnelResult r;
        r.res = wireguard_write(hnd.get(), msg.data(), msg.size(), buffer.data(), buffer.size());
        r.read(buffer.data(), buffer.size());
        return r;
    }

    static std::pair<bool, PublicKey> ParseHandshakeAnon(const PrivateKey& key, ByteSpan data)
    {
        PublicKey k {};
        int err = wireguard_parse_handshake_anon(&key.priv.key, &key.pub.key, data.data(), data.size(), &k.key);
        return std::make_pair(err == 0, k);
    }

    void close()
    {
        hnd.reset();
    }
};

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

struct TunnelTest : testing::Test {
};

TEST_F(TunnelTest, CreateAndDestroy)
{
    auto key = PrivateKey::Generate();
    auto serverKey = PrivateKey::Generate();
    auto tunnel = Tunnel::Create(key, serverKey.pub, {}, 0, 0);
    EXPECT_TRUE(tunnel.hnd.get());

    tunnel.close();
    EXPECT_FALSE(tunnel.hnd.get());
}

TEST_F(TunnelTest, HandleAnonHandshake)
{
    auto key = PrivateKey::Generate();
    auto serverKey = PrivateKey::Generate();

    auto tunnel = Tunnel::Create(key, serverKey.pub, {}, 0, 0);
    EXPECT_TRUE(tunnel.hnd.get());

    auto r = tunnel.forceHandshake();
    EXPECT_EQ(r.res.op, WRITE_TO_NETWORK);
    auto msgHandshake = r.data;
    EXPECT_EQ(msgHandshake.size(), r.res.size);

    auto [success, peerKey] = Tunnel::ParseHandshakeAnon(serverKey, msgHandshake);
    EXPECT_TRUE(success);

    std::string expectedKey { print_key(&key.pub.key) };
    std::string parsedKey { print_key(&peerKey.key) };
    EXPECT_EQ(parsedKey, expectedKey);
}

struct TwoTunnelTest : TunnelTest
{
    PrivateKey keyA;
    PrivateKey keyB;
    std::optional<StaticKey> sharedKey;
    uint16_t keepAlive {};
    uint32_t index {};

    Tunnel tunnelA;
    Tunnel tunnelB;

    void SetUp() override
    {
        TunnelTest::SetUp();

        keyA = PrivateKey::Generate();
        keyB = PrivateKey::Generate();
    }

    void CreateTunnels()
    {
        tunnelA = Tunnel::Create(keyA, keyB.pub, sharedKey, keepAlive, index);
        tunnelB = Tunnel::Create(keyB, keyA.pub, sharedKey, keepAlive, index);
    }
};

TEST_F(TwoTunnelTest, Handshake)
{
    CreateTunnels();

    TunnelResult msg;

    auto initMsg = tunnelA.forceHandshake();
    initMsg.dump();
    EXPECT_EQ(initMsg.res.op, WRITE_TO_NETWORK);

    auto responseMsg = tunnelB.readMsg(initMsg.data);
    responseMsg.dump();
    EXPECT_EQ(responseMsg.res.op, WRITE_TO_NETWORK);
    msg = tunnelB.readMsg({});
    msg.dump();
    EXPECT_EQ(msg.res.op, WIREGUARD_DONE);

    auto keepAliveMsg = tunnelA.readMsg(responseMsg.data);
    keepAliveMsg.dump();
    EXPECT_EQ(keepAliveMsg.res.op, WRITE_TO_NETWORK);
    msg = tunnelA.readMsg({});
    msg.dump();
    EXPECT_EQ(msg.res.op, WIREGUARD_DONE);
}

TEST_F(TwoTunnelTest, SendPacket)
{
    CreateTunnels();

    TunnelResult msg;

    auto initMsg = tunnelA.forceHandshake();
    auto responseMsg = tunnelB.readMsg(initMsg.data);
    msg = tunnelB.readMsg({});
    EXPECT_EQ(msg.res.op, WIREGUARD_DONE);
    auto keepAliveMsg = tunnelA.readMsg(responseMsg.data);
    EXPECT_EQ(keepAliveMsg.res.op, WRITE_TO_NETWORK);
    msg = tunnelA.readMsg({});
    EXPECT_EQ(msg.res.op, WIREGUARD_DONE);

    ByteVec payload { 0x01, 0x02, 0x03, 0x04 };
    uint32_t srcIP = IPV4(192, 168, 1, 1); // 192.168.1.1
    uint32_t destIP = IPV4(192, 168, 1, 2); // 192.168.1.2
    uint16_t srcPort = 12345;
    uint16_t destPort = 80;
    auto packet = createIPv4UDPFrame(payload, srcIP, destIP, srcPort, destPort);
    auto packetMsg = tunnelA.writeMsg(packet);
    packetMsg.dump();
    EXPECT_EQ(packetMsg.res.op, WRITE_TO_NETWORK);

    auto packetReadMsg = tunnelB.readMsg(packetMsg.data);
    packetReadMsg.dump();
    EXPECT_EQ(packetReadMsg.res.op, WRITE_TO_TUNNEL_IPV4);

    EXPECT_EQ(Base64Encode(packetReadMsg.data), Base64Encode(packet));
}

} // namespace
