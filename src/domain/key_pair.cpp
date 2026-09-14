#include "domain/key_pair.hpp"
#include <openssl/rand.h>
#include <stdexcept>

KeyPair KeyPair::generate() {
  KeyPair kp{};
  // Use OpenSSL RAND_bytes for CSPRNG (32B pub/priv). No hardcode.
  if (RAND_bytes(kp.pub.data(), static_cast<int>(kp.pub.size())) != 1) {
    throw std::runtime_error("RAND_bytes failed for pub");
  }
  if (RAND_bytes(kp.priv.data(), static_cast<int>(kp.priv.size())) != 1) {
    throw std::runtime_error("RAND_bytes failed for priv");
  }
  return kp;
}
