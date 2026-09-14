#include "infrastructure/memory_pubkey_directory.hpp"
#include "domain/exceptions.hpp"

void MemoryPubkeyDirectory::savePubkey(const UserId& uid, const std::vector<uint8_t>& pub) {
  if (uid.value.empty()) throw ValidationException("user_id empty");
  if (pub.empty()) throw ValidationException("pubkey empty");
  if (pub.size() != 32) throw ValidationException("pubkey must be 32 bytes");
  auto it = store_.find(uid.value);
  if (it != store_.end()) throw ValidationException("duplicate user_id");
  store_.emplace(uid.value, pub);
}

std::vector<uint8_t> MemoryPubkeyDirectory::getPubkey(const UserId& uid) const {
  if (uid.value.empty()) throw ValidationException("user_id empty");
  auto it = store_.find(uid.value);
  if (it == store_.end()) throw NotFoundException("pubkey not found");
  return it->second;
}

bool MemoryPubkeyDirectory::exists(const UserId& uid) const {
  if (uid.value.empty()) return false;
  return store_.find(uid.value) != store_.end();
}

std::vector<UserId> MemoryPubkeyDirectory::listAll() const {
  std::vector<UserId> out;
  out.reserve(store_.size());
  for (auto& kv : store_) out.push_back(UserId{kv.first});
  return out;
}
