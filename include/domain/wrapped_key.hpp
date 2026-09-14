#pragma once
#include "domain/ids.hpp"
#include "domain/exceptions.hpp"
#include <string>
#include <vector>
#include <utility>

struct WrappedKey {
  UserId recipientId;
  std::vector<uint8_t> nonce; // 12 bytes
  std::vector<uint8_t> bytes; // sealed DEK
  std::string alg = "X25519-AES-GCM-Seal";

  WrappedKey() = default;

  WrappedKey(const UserId& rid, std::vector<uint8_t> n, std::vector<uint8_t> b, std::string a = "X25519-AES-GCM-Seal")
      : recipientId(rid), nonce(std::move(n)), bytes(std::move(b)), alg(std::move(a)) {
    if (nonce.size() != 12) throw ValidationException("nonce must be 12");
    if (bytes.empty()) throw ValidationException("wrapped bytes empty");
  }
};
