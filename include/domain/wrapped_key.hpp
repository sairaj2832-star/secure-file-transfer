// include/domain/wrapped_key.hpp
#pragma once
#include <cstdint>
#include <string>
#include <vector>
struct WrappedKey { int kekVersion = 1; std::string alg = "FAKE-XOR-FNV"; std::vector<uint8_t> nonce; std::vector<uint8_t> bytes; };