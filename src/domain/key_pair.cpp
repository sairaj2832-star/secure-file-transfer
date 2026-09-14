#include "domain/key_pair.hpp"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <stdexcept>

KeyPair KeyPair::generate() {
  KeyPair kp{};
  if (RAND_bytes(kp.priv.data(), static_cast<int>(kp.priv.size())) != 1) {
    throw std::runtime_error("RAND_bytes failed for priv");
  }
  // Derive X25519 pub from priv via OpenSSL EVP_PKEY (real curve, not random)
  EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, kp.priv.data(), kp.priv.size());
  if (!pkey) throw std::runtime_error("EVP_PKEY_new_raw_private_key failed");
  size_t len = kp.pub.size();
  if (EVP_PKEY_get_raw_public_key(pkey, kp.pub.data(), &len) != 1 || len != kp.pub.size()) {
    EVP_PKEY_free(pkey);
    throw std::runtime_error("EVP_PKEY_get_raw_public_key failed");
  }
  EVP_PKEY_free(pkey);
  return kp;
}
