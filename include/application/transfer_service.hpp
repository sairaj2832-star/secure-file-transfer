// include/application/transfer_service.hpp
#pragma once
#include "domain/result.hpp"
#include "domain/transfer.hpp"
#include "domain/ids.hpp"
#include "domain/file_record.hpp"
#include "domain/digest.hpp"
#include "domain/wrapped_key.hpp"
#include "domain/clock.hpp"
#include "ports/storage.hpp"
#include "ports/audit.hpp"
#include "ports/file_repository.hpp"
#include "ports/transfer_repository.hpp"
#include "ports/key_directory.hpp"
#include "ports/file_validator.hpp"
#include "ports/session_store.hpp"
#include "ports/user_repository.hpp"
#include <vector>
#include <string>

class TransferService {
 public:
  TransferService(IStorage* st, IKeyDirectory* kd, IFileRepository* fr,
                  ITransferRepository* tr, IAuditLogger* au,
                  IFileValidator* fv, IClock* clk, ISessionStore* ss,
                  IUserRepository* ur)
      : st_(st), keys_(kd), files_(fr), transfers_(tr), au_(au),
        validator_(fv), clock_(clk), sessions_(ss), users_(ur) {}

  // Legacy compat not provided — old tests must be updated to new ctor

  Result<Transfer> upload(const SessionId& senderSess,
                          const std::string& recipientUsername,
                          const std::string& origName,
                          const std::vector<uint8_t>& opaque,
                          const std::string& uploadId,
                          uint64_t size,
                          const Digest& digest,
                          const WrappedKey& wrapped);

  Result<std::vector<uint8_t>> download(const SessionId& requestSess,
                                        const FileId& fid);

  std::vector<Transfer> listFor(const UserId& u) const;

 private:
  IStorage* st_;
  IKeyDirectory* keys_;
  IFileRepository* files_;
  ITransferRepository* transfers_;
  IAuditLogger* au_;
  IFileValidator* validator_;
  IClock* clock_;
  ISessionStore* sessions_;
  IUserRepository* users_;
};
