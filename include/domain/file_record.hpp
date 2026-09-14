#pragma once
#include "domain/ids.hpp"
#include "domain/digest.hpp"
#include "domain/wrapped_key.hpp"
#include "domain/exceptions.hpp"
#include <string>
#include <cstdint>

struct FileRecord {
  FileId id;
  UserId owner;
  std::string origName;
  std::string storageId; // uuid.bin
  uint64_t size = 0;
  Digest digest;
  WrappedKey wrapped;
  UserId recipient;
  std::string uploadId; // UUIDv4
  int64_t createdAt = 0;

  bool isOwnedBy(const UserId& u) const { return owner == u; }
};

inline void validateFileRecord(const FileRecord& r) {
  if (r.origName.empty()) throw ValidationException("origName empty");
  if (r.storageId.empty()) throw ValidationException("storageId empty");
  if (r.uploadId.empty()) throw ValidationException("uploadId empty");
}
