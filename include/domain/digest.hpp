// include/domain/digest.hpp
#pragma once
#include <array>
#include <cstdint>
#include <string_view>
struct Digest { std::array<uint8_t,32> bytes{}; bool operator==(const Digest&) const = default; };
inline uint32_t fnv1a32(std::string_view s) {
  uint32_t h = 2166136261u;
  for (unsigned char c : s) { h ^= c; h *= 16777619u; }
  return h;
}
inline Digest sha256stub(std::string_view s) {
  Digest d{};
  uint32_t h = fnv1a32(s);
  for (size_t i = 0; i < 32; ++i) d.bytes[i] = static_cast<uint8_t>((h >> ((i % 4) * 8)) ^ (i * 31));
  return d;
}