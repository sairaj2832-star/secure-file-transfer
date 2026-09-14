#include "infrastructure/sqlite_file_repo.hpp"
#include "domain/exceptions.hpp"
#include <stdexcept>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>

static std::string digestToHex(const Digest& d){
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for(auto b: d.bytes) oss << std::setw(2) << static_cast<int>(b);
  return oss.str();
}
static Digest hexToDigest(const std::string& s){
  Digest d{};
  if(s.size()!=64) return d; // tolerate empty or malformed -> zero digest
  for(size_t i=0;i<32;i++){
    std::string byteStr = s.substr(i*2,2);
    d.bytes[i] = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
  }
  return d;
}

SqliteFileRepository::SqliteFileRepository(const std::string& dbPath) : dbPath_(dbPath), db_(nullptr){
  if(sqlite3_open(dbPath.c_str(), &db_)!=SQLITE_OK) throw std::runtime_error("sqlite open failed");
  exec("PRAGMA journal_mode=WAL;");
  exec("PRAGMA synchronous=FULL;");
  exec("PRAGMA foreign_keys=ON;");
  exec("CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY, owner_id TEXT, recipient_id TEXT, orig_name TEXT, storage_id TEXT UNIQUE, size INTEGER, digest TEXT, wrapped_dek BLOB, nonce BLOB, upload_id TEXT UNIQUE, created_at TEXT);");
}
SqliteFileRepository::~SqliteFileRepository(){
  if(db_) sqlite3_close(db_);
}
void SqliteFileRepository::exec(const std::string& sql) const {
  char* err=nullptr;
  if(sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err)!=SQLITE_OK){
    std::string e = err?err:"exec failed";
    sqlite3_free(err);
    throw std::runtime_error(e);
  }
}

void SqliteFileRepository::save(const FileRecord& r){
  exec("BEGIN IMMEDIATE;");
  const char* sql = "INSERT INTO files(id, owner_id, recipient_id, orig_name, storage_id, size, digest, wrapped_dek, nonce, upload_id, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?);";
  sqlite3_stmt* stmt=nullptr;
  int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
  if(rc!=SQLITE_OK){ exec("ROLLBACK;"); throw std::runtime_error("prepare failed"); }
  // bind
  sqlite3_bind_text(stmt, 1, r.id.value.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, r.owner.value.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, r.recipient.value.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, r.origName.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 5, r.storageId.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(stmt, 6, static_cast<sqlite3_int64>(r.size));
  std::string digestHex = digestToHex(r.digest);
  sqlite3_bind_text(stmt, 7, digestHex.c_str(), -1, SQLITE_TRANSIENT);
  if(!r.wrapped.bytes.empty()){
    sqlite3_bind_blob(stmt, 8, r.wrapped.bytes.data(), static_cast<int>(r.wrapped.bytes.size()), SQLITE_TRANSIENT);
  } else {
    sqlite3_bind_null(stmt, 8);
  }
  if(!r.wrapped.nonce.empty()){
    sqlite3_bind_blob(stmt, 9, r.wrapped.nonce.data(), static_cast<int>(r.wrapped.nonce.size()), SQLITE_TRANSIENT);
  } else {
    sqlite3_bind_null(stmt, 9);
  }
  sqlite3_bind_text(stmt, 10, r.uploadId.c_str(), -1, SQLITE_TRANSIENT);
  std::string createdAt = std::to_string(r.createdAt);
  // if createdAt is 0, store empty or 0 string; keep as is
  if(r.createdAt==0){
    // store as current time? keep 0
  }
  sqlite3_bind_text(stmt, 11, createdAt.c_str(), -1, SQLITE_TRANSIENT);

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if(rc!=SQLITE_DONE){
    exec("ROLLBACK;");
    if(rc==SQLITE_CONSTRAINT) throw ValidationException("duplicate upload_id or storage_id or id");
    throw std::runtime_error("insert failed");
  }
  if(sqlite3_changes(db_)!=1){
    exec("ROLLBACK;");
    throw std::runtime_error("no row inserted");
  }
  exec("COMMIT;");
}

Result<FileRecord> SqliteFileRepository::findById(const FileId& id) const {
  const char* sql = "SELECT id, owner_id, recipient_id, orig_name, storage_id, size, digest, wrapped_dek, nonce, upload_id, created_at FROM files WHERE id=?;";
  sqlite3_stmt* stmt=nullptr;
  if(sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr)!=SQLITE_OK) return Result<FileRecord>::failure("prepare failed");
  sqlite3_bind_text(stmt,1,id.value.c_str(),-1,SQLITE_TRANSIENT);
  Result<FileRecord> res = Result<FileRecord>::failure("not found");
  if(sqlite3_step(stmt)==SQLITE_ROW){
    FileRecord r;
    r.id.value = reinterpret_cast<const char*>(sqlite3_column_text(stmt,0));
    const unsigned char* owner = sqlite3_column_text(stmt,1);
    r.owner.value = owner?reinterpret_cast<const char*>(owner):"";
    const unsigned char* recip = sqlite3_column_text(stmt,2);
    r.recipient.value = recip?reinterpret_cast<const char*>(recip):"";
    const unsigned char* orig = sqlite3_column_text(stmt,3);
    r.origName = orig?reinterpret_cast<const char*>(orig):"";
    const unsigned char* stor = sqlite3_column_text(stmt,4);
    r.storageId = stor?reinterpret_cast<const char*>(stor):"";
    r.size = static_cast<uint64_t>(sqlite3_column_int64(stmt,5));
    const unsigned char* dig = sqlite3_column_text(stmt,6);
    std::string digHex = dig?reinterpret_cast<const char*>(dig):"";
    r.digest = hexToDigest(digHex);
    // wrapped_dek
    const void* wblob = sqlite3_column_blob(stmt,7);
    int wlen = sqlite3_column_bytes(stmt,7);
    std::vector<uint8_t> wbytes;
    if(wblob && wlen>0) wbytes.assign(static_cast<const uint8_t*>(wblob), static_cast<const uint8_t*>(wblob)+wlen);
    const void* nblob = sqlite3_column_blob(stmt,8);
    int nlen = sqlite3_column_bytes(stmt,8);
    std::vector<uint8_t> nbytes;
    if(nblob && nlen>0) nbytes.assign(static_cast<const uint8_t*>(nblob), static_cast<const uint8_t*>(nblob)+nlen);
    const unsigned char* up = sqlite3_column_text(stmt,9);
    r.uploadId = up?reinterpret_cast<const char*>(up):"";
    const unsigned char* ca = sqlite3_column_text(stmt,10);
    std::string caStr = ca?reinterpret_cast<const char*>(ca):"0";
    try{ r.createdAt = std::stoll(caStr); } catch(...){ r.createdAt = 0; }
    // reconstruct wrapped
    if(!nbytes.empty() || !wbytes.empty()){
      // try validated ctor if possible, otherwise direct assign
      if(nbytes.size()==12 && !wbytes.empty()){
        try{ r.wrapped = WrappedKey(r.recipient, nbytes, wbytes); }
        catch(...){
          r.wrapped.recipientId = r.recipient;
          r.wrapped.nonce = nbytes;
          r.wrapped.bytes = wbytes;
          r.wrapped.alg = "X25519-AES-GCM-Seal";
        }
      } else {
        r.wrapped.recipientId = r.recipient;
        r.wrapped.nonce = nbytes;
        r.wrapped.bytes = wbytes;
        r.wrapped.alg = "X25519-AES-GCM-Seal";
      }
    } else {
      r.wrapped = WrappedKey();
      r.wrapped.recipientId = r.recipient;
    }
    res = Result<FileRecord>::success(r);
  }
  sqlite3_finalize(stmt);
  return res;
}

std::vector<FileRecord> SqliteFileRepository::findByOwner(const UserId& owner) const {
  std::vector<FileRecord> out;
  const char* sql = "SELECT id, owner_id, recipient_id, orig_name, storage_id, size, digest, wrapped_dek, nonce, upload_id, created_at FROM files WHERE owner_id=?;";
  sqlite3_stmt* stmt=nullptr;
  if(sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr)!=SQLITE_OK) return out;
  sqlite3_bind_text(stmt,1,owner.value.c_str(),-1,SQLITE_TRANSIENT);
  while(sqlite3_step(stmt)==SQLITE_ROW){
    FileRecord r;
    r.id.value = reinterpret_cast<const char*>(sqlite3_column_text(stmt,0));
    const unsigned char* own = sqlite3_column_text(stmt,1);
    r.owner.value = own?reinterpret_cast<const char*>(own):"";
    const unsigned char* recip = sqlite3_column_text(stmt,2);
    r.recipient.value = recip?reinterpret_cast<const char*>(recip):"";
    const unsigned char* orig = sqlite3_column_text(stmt,3);
    r.origName = orig?reinterpret_cast<const char*>(orig):"";
    const unsigned char* stor = sqlite3_column_text(stmt,4);
    r.storageId = stor?reinterpret_cast<const char*>(stor):"";
    r.size = static_cast<uint64_t>(sqlite3_column_int64(stmt,5));
    const unsigned char* dig = sqlite3_column_text(stmt,6);
    std::string digHex = dig?reinterpret_cast<const char*>(dig):"";
    r.digest = hexToDigest(digHex);
    const void* wblob = sqlite3_column_blob(stmt,7);
    int wlen = sqlite3_column_bytes(stmt,7);
    std::vector<uint8_t> wbytes;
    if(wblob && wlen>0) wbytes.assign(static_cast<const uint8_t*>(wblob), static_cast<const uint8_t*>(wblob)+wlen);
    const void* nblob = sqlite3_column_blob(stmt,8);
    int nlen = sqlite3_column_bytes(stmt,8);
    std::vector<uint8_t> nbytes;
    if(nblob && nlen>0) nbytes.assign(static_cast<const uint8_t*>(nblob), static_cast<const uint8_t*>(nblob)+nlen);
    const unsigned char* up = sqlite3_column_text(stmt,9);
    r.uploadId = up?reinterpret_cast<const char*>(up):"";
    const unsigned char* ca = sqlite3_column_text(stmt,10);
    std::string caStr = ca?reinterpret_cast<const char*>(ca):"0";
    try{ r.createdAt = std::stoll(caStr); } catch(...){ r.createdAt=0; }
    if(!nbytes.empty() || !wbytes.empty()){
      if(nbytes.size()==12 && !wbytes.empty()){
        try{ r.wrapped = WrappedKey(r.recipient, nbytes, wbytes); }
        catch(...){
          r.wrapped.recipientId = r.recipient;
          r.wrapped.nonce = nbytes;
          r.wrapped.bytes = wbytes;
        }
      } else {
        r.wrapped.recipientId = r.recipient;
        r.wrapped.nonce = nbytes;
        r.wrapped.bytes = wbytes;
      }
    } else {
      r.wrapped = WrappedKey();
      r.wrapped.recipientId = r.recipient;
    }
    out.push_back(std::move(r));
  }
  sqlite3_finalize(stmt);
  return out;
}

bool SqliteFileRepository::existsUploadId(const std::string& uploadId) const {
  const char* sql = "SELECT COUNT(*) FROM files WHERE upload_id=?;";
  sqlite3_stmt* stmt=nullptr;
  if(sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr)!=SQLITE_OK) return false;
  sqlite3_bind_text(stmt,1,uploadId.c_str(),-1,SQLITE_TRANSIENT);
  bool exists=false;
  if(sqlite3_step(stmt)==SQLITE_ROW){
    int cnt = sqlite3_column_int(stmt,0);
    exists = cnt>0;
  }
  sqlite3_finalize(stmt);
  return exists;
}
