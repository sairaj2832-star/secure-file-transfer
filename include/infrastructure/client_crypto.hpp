// include/infrastructure/client_crypto.hpp — ClientCryptoProvider (real E2E)
// Design choice (port compat):
// - IEncryptionProvider::encrypt(plain) kept for FakeCompat / unit tests that inject FakeCrypto.
//   ClientCryptoProvider implements it by using a stored recipient pub if ctor provided one,
//   otherwise throws ValidationException("recipient pub required"). This keeps domain/app
//   polymorphic without changing IEncryptionProvider signature.
// - Real E2E uses per-call overloads encrypt(plain, recipientPub) and decryptAndVerify(..., priv)
//   which expose sealed-box semantics. The overloads are the preferred API for TransferService
//   and tests; the base virtuals delegate to stored pub where possible.
// - WrappedKey.nonce is the AES-GCM 96-bit nonce; WrappedKey.bytes is sealed DEK (64B: ephPub32||encDEK32)
//   with alg="X25519-AES-GCM-Seal". This avoids new port types while keeping WrappedKey stable.
// - Crypto: per-file DEK 32B RAND_bytes, nonce 12B RAND_bytes, AES-256-GCM via OpenSSL EVP
//   (cipher = ciphertext || tag16), DEK sealed via X25519 ECDH + SHA256 KDF (OpenSSL EVP_PKEY_X25519).
//   No libsodium dependency at build time — OpenSSL 3.x is already required via vcpkg.
//   Libsodium FetchContent remains a documented stretch (see plan Task 4); current impl provides
//   real X25519 + AES-GCM security and passes 10k nonce uniq / tag / wrong-key checks.
//   If libsodium is later added, seal/unseal can be swapped to crypto_box_seal without API change.
#pragma once
#include "ports/crypto.hpp"
#include "domain/digest.hpp"
#include "domain/wrapped_key.hpp"
#include "domain/ids.hpp"
#include <array>
#include <vector>
#include <string>

class ClientCryptoProvider : public IEncryptionProvider {
public:
  ClientCryptoProvider() = default;
  explicit ClientCryptoProvider(const std::vector<uint8_t>& recipientPub);
  explicit ClientCryptoProvider(const std::array<uint8_t,32>& recipientPub);

  // IEncryptionProvider compat (uses stored pub)
  EncryptOut encrypt(const std::vector<uint8_t>& plain) override;
  std::vector<uint8_t> decryptAndVerify(const std::vector<uint8_t>& cipher,
                                        const WrappedKey& wrapped,
                                        const Digest& d) override;

  // Real E2E overloads — preferred
  EncryptOut encrypt(const std::vector<uint8_t>& plain,
                     const std::vector<uint8_t>& recipientPub);
  EncryptOut encrypt(const std::vector<uint8_t>& plain,
                     const std::array<uint8_t,32>& recipientPub);
  EncryptOut encrypt(const std::vector<uint8_t>& plain,
                     const UserId& recipientId,
                     const std::vector<uint8_t>& recipientPub);
  EncryptOut encrypt(const std::vector<uint8_t>& plain,
                     const UserId& recipientId,
                     const std::array<uint8_t,32>& recipientPub);

  std::vector<uint8_t> decryptAndVerify(const std::vector<uint8_t>& cipher,
                                        const WrappedKey& wrapped,
                                        const Digest& d,
                                        const std::array<uint8_t,32>& priv);
  std::vector<uint8_t> decryptAndVerify(const std::vector<uint8_t>& cipher,
                                        const WrappedKey& wrapped,
                                        const Digest& d,
                                        const std::vector<uint8_t>& priv);

private:
  std::vector<uint8_t> storedPub_;
  bool hasStoredPub_ = false;
};
