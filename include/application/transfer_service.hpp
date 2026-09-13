// include/application/transfer_service.hpp
#pragma once
#include "domain/result.hpp"
#include "domain/transfer.hpp"
#include "domain/ids.hpp"
#include "domain/file_record.hpp"
#include "ports/storage.hpp"
#include "ports/crypto.hpp"
#include "ports/audit.hpp"
#include <map>
#include <set>
class TransferService {
 public:
  TransferService(IStorage* s, IEncryptionProvider* c, IAuditLogger* a) : st_(s), cr_(c), au_(a) {}
  void addUser(const std::string& n) { users_.insert(n); }
  Result<Transfer> upload(const UserId& sender, const std::string& recip, const std::string& orig, const std::vector<uint8_t>& bytes);
  Result<std::vector<uint8_t>> download(const UserId& req, const FileId& fid);
  std::vector<Transfer> listFor(const UserId& u) const;
 private:
  bool validExt(const std::string& n) const;
  IStorage* st_; IEncryptionProvider* cr_; IAuditLogger* au_;
  std::set<std::string> users_; std::map<std::string, FileRecord> files_; std::map<std::string, Transfer> trs_; std::map<std::string, std::set<std::string>> grants_;
  int ctr_ = 0;
};