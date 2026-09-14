#include "infrastructure/client_crypto.hpp"
#include "domain/exceptions.hpp"
#include "domain/digest.hpp"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <stdexcept>
#include <cstring>

namespace {

// Compute SHA256 via OpenSSL (binary safe)
std::array<uint8_t,32> sha256_bytes(const std::vector<uint8_t>& data) {
  std::array<uint8_t,32> out{};
  SHA256(data.data(), data.size(), out.data());
  return out;
}
std::array<uint8_t,32> sha256_bytes(const uint8_t* d, size_t n) {
  std::array<uint8_t,32> out{};
  SHA256(d, n, out.data());
  return out;
}

Digest digestFromPlain(const std::vector<uint8_t>& plain) {
  Digest d;
  d.bytes = sha256_bytes(plain);
  return d;
}

// X25519 ECDH helper: derive shared secret (32B) from priv(32) + pub(32) via OpenSSL EVP_PKEY_X25519
// Throws IntegrityException on failure.
std::array<uint8_t,32> x25519Shared(const uint8_t priv[32], const uint8_t pub[32]) {
  EVP_PKEY* pkeyPriv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv, 32);
  if (!pkeyPriv) throw IntegrityException("X25519 priv init failed");
  EVP_PKEY* pkeyPub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, pub, 32);
  if (!pkeyPub) { EVP_PKEY_free(pkeyPriv); throw IntegrityException("X25519 pub init failed"); }
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkeyPriv, nullptr);
  if (!ctx) { EVP_PKEY_free(pkeyPriv); EVP_PKEY_free(pkeyPub); throw IntegrityException("X25519 ctx failed"); }
  if (EVP_PKEY_derive_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pkeyPriv); EVP_PKEY_free(pkeyPub); throw IntegrityException("derive_init failed"); }
  if (EVP_PKEY_derive_set_peer(ctx, pkeyPub) <= 0) { EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pkeyPriv); EVP_PKEY_free(pkeyPub); throw IntegrityException("derive_set_peer failed"); }
  size_t slen = 32;
  unsigned char secret[32];
  if (EVP_PKEY_derive(ctx, secret, &slen) <= 0 || slen != 32) {
    EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pkeyPriv); EVP_PKEY_free(pkeyPub);
    throw IntegrityException("X25519 derive failed");
  }
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(pkeyPriv);
  EVP_PKEY_free(pkeyPub);
  std::array<uint8_t,32> out;
  std::memcpy(out.data(), secret, 32);
  OPENSSL_cleanse(secret, 32);
  return out;
}

// Derive ephemeral pub from priv via EVP_PKEY
std::array<uint8_t,32> x25519PubFromPriv(const uint8_t priv[32]) {
  EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv, 32);
  if (!pkey) throw IntegrityException("X25519 priv->pub init failed");
  size_t len = 32;
  std::array<uint8_t,32> pub{};
  if (EVP_PKEY_get_raw_public_key(pkey, pub.data(), &len) <= 0 || len != 32) {
    EVP_PKEY_free(pkey);
    throw IntegrityException("X25519 get pub failed");
  }
  EVP_PKEY_free(pkey);
  return pub;
}

// Seal DEK (32B) to recipientPub (32B): sealed = ephPub(32) || (DEK xor SHA256(shared))
// shared = X25519(ephPriv, recipientPub)
std::vector<uint8_t> sealDEK(const uint8_t dek[32], const uint8_t recipientPub[32]) {
  uint8_t ephPriv[32];
  if (RAND_bytes(ephPriv, 32) != 1) throw std::runtime_error("RAND_bytes ephPriv failed");
  auto ephPub = x25519PubFromPriv(ephPriv);
  auto shared = x25519Shared(ephPriv, recipientPub);
  auto k = sha256_bytes(shared.data(), shared.size()); // KDF = SHA256(shared)
  OPENSSL_cleanse(ephPriv, 32);
  OPENSSL_cleanse(shared.data(), 32);
  std::vector<uint8_t> sealed;
  sealed.reserve(64);
  sealed.insert(sealed.end(), ephPub.begin(), ephPub.end());
  for (int i=0;i<32;i++) sealed.push_back(dek[i] ^ k[i]);
  OPENSSL_cleanse(k.data(), 32);
  return sealed;
}

std::vector<uint8_t> sealDEK(const uint8_t dek[32], const std::vector<uint8_t>& pubVec) {
  if (pubVec.size()!=32) throw ValidationException("recipient pubkey must be 32");
  return sealDEK(dek, pubVec.data());
}
std::vector<uint8_t> sealDEK(const uint8_t dek[32], const std::array<uint8_t,32>& pub) {
  return sealDEK(dek, pub.data());
}

// Unseal
std::array<uint8_t,32> unsealDEK(const std::vector<uint8_t>& sealed, const uint8_t priv[32]) {
  if (sealed.size()!=64) throw IntegrityException("sealed DEK size invalid");
  const uint8_t* ephPub = sealed.data();
  const uint8_t* encDEK = sealed.data()+32;
  auto shared = x25519Shared(priv, ephPub);
  auto k = sha256_bytes(shared.data(), shared.size());
  OPENSSL_cleanse(shared.data(), 32);
  std::array<uint8_t,32> dek{};
  for (int i=0;i<32;i++) dek[i] = encDEK[i] ^ k[i];
  OPENSSL_cleanse(k.data(), 32);
  return dek;
}

// AES-256-GCM encrypt: returns cipher = ciphertext || tag16
std::vector<uint8_t> aesGcmEncrypt(const std::vector<uint8_t>& plain, const uint8_t dek[32], const uint8_t nonce[12]) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("EncryptInit failed"); }
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("SET_IVLEN failed"); }
  if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, dek, nonce) != 1) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("EncryptInit key/nonce failed"); }
  std::vector<uint8_t> ct(plain.size());
  int outlen = 0;
  if (!plain.empty()) {
    if (EVP_EncryptUpdate(ctx, ct.data(), &outlen, plain.data(), (int)plain.size()) != 1) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("EncryptUpdate failed"); }
  }
  int finlen = 0;
  if (EVP_EncryptFinal_ex(ctx, ct.data()+outlen, &finlen) != 1) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("EncryptFinal failed"); }
  // tag
  unsigned char tag[16];
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("GET_TAG failed"); }
  EVP_CIPHER_CTX_free(ctx);
  std::vector<uint8_t> cipher;
  cipher.reserve(plain.size()+16);
  cipher.insert(cipher.end(), ct.data(), ct.data()+outlen+finlen);
  cipher.insert(cipher.end(), tag, tag+16);
  OPENSSL_cleanse(tag, 16);
  return cipher;
}

std::vector<uint8_t> aesGcmDecrypt(const std::vector<uint8_t>& cipher, const uint8_t dek[32], const uint8_t nonce[12]) {
  if (cipher.size() < 16) throw IntegrityException("cipher too short (tag missing)");
  size_t ctLen = cipher.size() - 16;
  const uint8_t* ct = cipher.data();
  const uint8_t* tag = cipher.data() + ctLen;
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("DecryptInit failed"); }
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("SET_IVLEN failed"); }
  if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, dek, nonce) != 1) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("DecryptInit key failed"); }
  std::vector<uint8_t> plain(ctLen);
  int outlen = 0;
  if (ctLen>0) {
    if (EVP_DecryptUpdate(ctx, plain.data(), &outlen, ct, (int)ctLen) != 1) { EVP_CIPHER_CTX_free(ctx); throw IntegrityException("GCM decrypt failed"); }
  }
  // set tag before final
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("SET_TAG failed"); }
  int finlen = 0;
  int ret = EVP_DecryptFinal_ex(ctx, plain.data()+outlen, &finlen);
  EVP_CIPHER_CTX_free(ctx);
  if (ret <= 0) throw IntegrityException("GCM tag mismatch");
  plain.resize(outlen + finlen);
  return plain;
}

EncryptOut doEncrypt(const std::vector<uint8_t>& plain, const UserId& recipientId, const std::vector<uint8_t>& recipientPubVec) {
  if (recipientPubVec.size()!=32) throw ValidationException("recipient pubkey must be 32 bytes");
  uint8_t dek[32];
  uint8_t nonce[12];
  if (RAND_bytes(dek, 32) != 1) throw std::runtime_error("RAND_bytes dek failed");
  if (RAND_bytes(nonce, 12) != 1) { OPENSSL_cleanse(dek,32); throw std::runtime_error("RAND_bytes nonce failed"); }
  auto cipher = aesGcmEncrypt(plain, dek, nonce);
  auto digest = digestFromPlain(plain);
  auto sealed = sealDEK(dek, recipientPubVec);
  OPENSSL_cleanse(dek,32);
  std::vector<uint8_t> nonceVec(nonce, nonce+12);
  OPENSSL_cleanse(nonce,12);
  WrappedKey w{recipientId, std::move(nonceVec), std::move(sealed), "X25519-AES-GCM-Seal"};
  return EncryptOut{std::move(cipher), std::move(w), digest};
}

} // anon

ClientCryptoProvider::ClientCryptoProvider(const std::vector<uint8_t>& recipientPub)
  : storedPub_(recipientPub), hasStoredPub_(true) {
  if (recipientPub.size()!=32) throw ValidationException("recipient pubkey must be 32");
}
ClientCryptoProvider::ClientCryptoProvider(const std::array<uint8_t,32>& recipientPub)
  : storedPub_(recipientPub.begin(), recipientPub.end()), hasStoredPub_(true) {}

EncryptOut ClientCryptoProvider::encrypt(const std::vector<uint8_t>& plain) {
  if (!hasStoredPub_) throw ValidationException("recipient pub required: use encrypt(plain, recipientPub)");
  return doEncrypt(plain, UserId{"recipient"}, storedPub_);
}
std::vector<uint8_t> ClientCryptoProvider::decryptAndVerify(const std::vector<uint8_t>&,
                                                            const WrappedKey&,
                                                            const Digest&) {
  throw IntegrityException("privkey required: use decryptAndVerify(cipher, wrapped, digest, priv)");
}

EncryptOut ClientCryptoProvider::encrypt(const std::vector<uint8_t>& plain,
                                         const std::vector<uint8_t>& recipientPub) {
  return doEncrypt(plain, UserId{"recipient"}, recipientPub);
}
EncryptOut ClientCryptoProvider::encrypt(const std::vector<uint8_t>& plain,
                                         const std::array<uint8_t,32>& recipientPub) {
  std::vector<uint8_t> v(recipientPub.begin(), recipientPub.end());
  return doEncrypt(plain, UserId{"recipient"}, v);
}
EncryptOut ClientCryptoProvider::encrypt(const std::vector<uint8_t>& plain,
                                         const UserId& recipientId,
                                         const std::vector<uint8_t>& recipientPub) {
  return doEncrypt(plain, recipientId, recipientPub);
}
EncryptOut ClientCryptoProvider::encrypt(const std::vector<uint8_t>& plain,
                                         const UserId& recipientId,
                                         const std::array<uint8_t,32>& recipientPub) {
  std::vector<uint8_t> v(recipientPub.begin(), recipientPub.end());
  return doEncrypt(plain, recipientId, v);
}

std::vector<uint8_t> ClientCryptoProvider::decryptAndVerify(const std::vector<uint8_t>& cipher,
                                                            const WrappedKey& w,
                                                            const Digest& d,
                                                            const std::array<uint8_t,32>& priv) {
  if (w.nonce.size()!=12) throw IntegrityException("nonce must be 12");
  if (w.bytes.empty()) throw IntegrityException("wrapped bytes empty");
  auto dekArr = unsealDEK(w.bytes, priv.data());
  uint8_t dek[32]; std::memcpy(dek, dekArr.data(),32);
  OPENSSL_cleanse(dekArr.data(),32);
  auto plain = aesGcmDecrypt(cipher, dek, w.nonce.data());
  OPENSSL_cleanse(dek,32);
  auto computed = digestFromPlain(plain);
  if (!(computed == d)) {
    OPENSSL_cleanse(plain.data(), plain.size());
    throw IntegrityException("digest mismatch");
  }
  return plain;
}

std::vector<uint8_t> ClientCryptoProvider::decryptAndVerify(const std::vector<uint8_t>& cipher,
                                                            const WrappedKey& w,
                                                            const Digest& d,
                                                            const std::vector<uint8_t>& priv) {
  if (priv.size()!=32) throw ValidationException("privkey must be 32");
  std::array<uint8_t,32> arr{};
  std::copy(priv.begin(), priv.end(), arr.begin());
  return decryptAndVerify(cipher, w, d, arr);
}
