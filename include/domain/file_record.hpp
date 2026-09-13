// include/domain/file_record.hpp
#pragma once
#include "domain/ids.hpp"
#include "domain/digest.hpp"
#include "domain/wrapped_key.hpp"
#include <string>
struct FileRecord {
  FileId id; UserId owner; std::string origName, storageId; uint64_t size = 0; Digest digest; WrappedKey wrapped;
  bool isOwnedBy(const UserId& u) const { return owner == u; }
};