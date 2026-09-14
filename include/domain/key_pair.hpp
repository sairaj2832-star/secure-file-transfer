#pragma once
#include <array>
#include <cstdint>

struct KeyPair {
  std::array<uint8_t, 32> pub{};
  std::array<uint8_t, 32> priv{};
  static KeyPair generate();
};
