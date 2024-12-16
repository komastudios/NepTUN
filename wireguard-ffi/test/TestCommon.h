#pragma once

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include <vector>
#include <cstdint>
#include <array>
#include <span>

using ByteVec = std::vector<uint8_t>;
using ByteSpan = std::span<const uint8_t>;

static constexpr const char* Base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static constexpr char PadCharacter = '=';

// based on https://en.wikibooks.org/wiki/Algorithm_Implementation/Miscellaneous/Base64
inline std::string Base64Encode(ByteSpan inputBuffer)
{
    std::string encodedString;
    encodedString.reserve(((inputBuffer.size()/3) + (inputBuffer.size() % 3 > 0)) * 4);
    uint32_t temp {};
    auto cursor = inputBuffer.begin();
    for (size_t idx=0;idx<inputBuffer.size()/3;++idx) {
        temp  = static_cast<uint32_t>(*cursor++) << 16; //Convert to big endian
        temp += static_cast<uint32_t>(*cursor++) << 8;
        temp += static_cast<uint32_t>(*cursor++);
        encodedString.append(1, Base64Chars[(temp & 0x00FC0000) >> 18]);
        encodedString.append(1, Base64Chars[(temp & 0x0003F000) >> 12]);
        encodedString.append(1, Base64Chars[(temp & 0x00000FC0) >> 6 ]);
        encodedString.append(1, Base64Chars[(temp & 0x0000003F)      ]);
    }
    switch(inputBuffer.size() % 3)
    {
        case 1:
            temp  = static_cast<uint32_t>(*cursor++) << 16; //Convert to big endian
        encodedString.append(1, Base64Chars[(temp & 0x00FC0000) >> 18]);
        encodedString.append(1, Base64Chars[(temp & 0x0003F000) >> 12]);
        encodedString.append(2, PadCharacter);
        break;
        case 2:
            temp  = static_cast<uint32_t>(*cursor++) << 16; //Convert to big endian
        temp += static_cast<uint32_t>(*cursor++) << 8;
        encodedString.append(1, Base64Chars[(temp & 0x00FC0000) >> 18]);
        encodedString.append(1, Base64Chars[(temp & 0x0003F000) >> 12]);
        encodedString.append(1, Base64Chars[(temp & 0x00000FC0) >> 6 ]);
        encodedString.append(1, PadCharacter);
        break;
    }

    return encodedString;
}

// #include "absl/strings/str_cat.h"
// #include "absl/strings/str_format.h"
// #include "absl/strings/str_replace.h"
// #include "absl/strings/str_join.h"
