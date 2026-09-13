// src/application/transfer_service.cpp
#include "application/transfer_service.hpp"
#include "domain/exceptions.hpp"
Result<Transfer> TransferService::upload(const UserId& s, const std::string& r, const std::string& o, const std::vector<uint8_t>& b) {
  if (!users_.count(s.value) || !users_.count(r)) return {false, Transfer{}, "unknown user"};
  if (!validExt(o)) return {false, Transfer{}, "bad extension"};
  if (b.size() > 100u * 1024u * 1024u) return {false, Transfer{}, "oversize"};
  auto out = cr_->encrypt(b);
  std::string uuid = "uuid-" + std::to_string(++ctr_);
  st_->write(uuid, out.cipher);
  FileRecord fr{FileId{"f" + std::to_string(ctr_)}, s, o, uuid, b.size(), out.digest, out.wrapped};
  files_.emplace(fr.id.value, fr);
  grants_[fr.id.value].insert(r);
  Transfer t{TransferId{"t" + std::to_string(ctr_)}, fr.id, s, UserId{r}, Transfer::Status::UPLOADED};
  trs_.emplace(t.id.value, t);
  au_->record({0, "now", s.value, "UPLOAD", fr.id.value, "", "", ""});
  return {true, t, ""};
}
Result<std::vector<uint8_t>> TransferService::download(const UserId& q, const FileId& fid) {
  auto it = files_.find(fid.value);
  if (it == files_.end()) return {false, {}, "not found"};
  const FileRecord& fr = it->second;
  bool ok = (fr.owner == q) || grants_[fid.value].count(q.value);
  if (!ok) { au_->record({0, "now", q.value, "DENIED", fid.value, "", "", ""}); return {false, {}, "denied"}; }
  auto cipher = st_->read(fr.storageId);
  try {
    auto plain = cr_->decryptAndVerify(cipher, fr.wrapped, fr.digest);
    au_->record({0, "now", q.value, "DOWNLOAD", fid.value, "", "", ""});
    return {true, plain, ""};
  } catch (const IntegrityException&) {
    au_->record({0, "now", q.value, "INTEGRITY_FAIL", fid.value, "", "", ""});
    throw;
  }
}
bool TransferService::validExt(const std::string& n) const {
  size_t p = n.rfind('.');
  if (p == std::string::npos) return false;
  std::string ext = n.substr(p + 1);
  return ext == "pdf" || ext == "png" || ext == "jpg" || ext == "zip" || ext == "txt";
}
std::vector<Transfer> TransferService::listFor(const UserId& u) const {
  std::vector<Transfer> out;
  for (auto& [k, t] : trs_) {
    if (t.sender == u || t.recipient == u) out.push_back(t);
  }
  return out;
}