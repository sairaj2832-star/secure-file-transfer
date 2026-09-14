// include/infrastructure/fake_crypto.hpp
#pragma once
#include "ports/crypto.hpp"
#include "domain/digest.hpp"
#include "domain/exceptions.hpp"
class FakeCrypto : public IEncryptionProvider {
 public:
  EncryptOut encrypt(const std::vector<uint8_t>& p) override {
    EncryptOut o; o.cipher = p;
    for (auto& b : o.cipher) b ^= 0x5A;
    // Use new WrappedKey with valid 12-byte nonce and non-empty bytes; recipient is dummy
    o.wrapped = WrappedKey{UserId{"fake-recipient"}, std::vector<uint8_t>(12, 0x5A), std::vector<uint8_t>(32, 0x42), "X25519-AES-GCM-Seal"};
    std::string s(p.begin(), p.end());
    o.digest = sha256stub(s);
    return o;
  }
  std::vector<uint8_t> decryptAndVerify(const std::vector<uint8_t>& c, const WrappedKey&, const Digest& d) override {
    std::vector<uint8_t> p = c;
    for (auto& b : p) b ^= 0x5A;
    std::string s(p.begin(), p.end());
    if (!(sha256stub(s) == d)) throw IntegrityException("tag mismatch");
    return p;
  }
};