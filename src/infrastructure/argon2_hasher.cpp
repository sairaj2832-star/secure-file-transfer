#include "infrastructure/argon2_hasher.hpp"
#include <argon2.h>
#include <random>
#include <stdexcept>
#include <vector>
// Required params per MASTER §4: m=19456 KiB, t=2, p=1, hashlen=32, saltlen=16
static constexpr uint32_t MEM_COST=19456, TIME_COST=2, PARALLELISM=1, HASH_LEN=32, SALT_LEN=16;
std::string Argon2Hasher::hash(const std::string& pw) {
  unsigned char salt[SALT_LEN];
  std::random_device rd;
  for(size_t i=0;i<SALT_LEN;i++) salt[i] = static_cast<unsigned char>(rd() & 0xFF);
  size_t encLen = argon2_encodedlen(TIME_COST, MEM_COST, PARALLELISM, SALT_LEN, HASH_LEN, Argon2_id);
  std::vector<char> out(encLen);
  int rc = argon2id_hash_encoded(TIME_COST, MEM_COST, PARALLELISM, pw.data(), pw.size(), salt, SALT_LEN, HASH_LEN, out.data(), out.size());
  if (rc!=ARGON2_OK) throw std::runtime_error(argon2_error_message(rc));
  return std::string(out.data());
}
bool Argon2Hasher::verify(const std::string& enc, const std::string& pw) {
  int rc = argon2id_verify(enc.c_str(), pw.data(), pw.size());
  return rc==ARGON2_OK;
}
