#include "infrastructure/memory_file_repo.hpp"
#include "domain/exceptions.hpp"

void MemoryFileRepository::save(const FileRecord& r){
  if(r.id.value.empty()) throw ValidationException("id empty");
  if(r.uploadId.empty()) throw ValidationException("uploadId empty");
  if(r.storageId.empty()) throw ValidationException("storageId empty");
  if(byId_.find(r.id.value)!=byId_.end()) throw ValidationException("duplicate id");
  if(uploadIdToId_.find(r.uploadId)!=uploadIdToId_.end()) throw ValidationException("duplicate upload_id");
  if(storageIdToId_.find(r.storageId)!=storageIdToId_.end()) throw ValidationException("duplicate storage_id");
  byId_.emplace(r.id.value, r);
  uploadIdToId_.emplace(r.uploadId, r.id.value);
  storageIdToId_.emplace(r.storageId, r.id.value);
}

Result<FileRecord> MemoryFileRepository::findById(const FileId& id) const {
  auto it = byId_.find(id.value);
  if(it==byId_.end()) return Result<FileRecord>::failure("not found");
  return Result<FileRecord>::success(it->second);
}

std::vector<FileRecord> MemoryFileRepository::findByOwner(const UserId& owner) const {
  std::vector<FileRecord> out;
  for(auto& kv: byId_){
    if(kv.second.owner==owner) out.push_back(kv.second);
  }
  return out;
}

bool MemoryFileRepository::existsUploadId(const std::string& uploadId) const {
  return uploadIdToId_.find(uploadId)!=uploadIdToId_.end();
}
