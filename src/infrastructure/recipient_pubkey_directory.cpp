#include "infrastructure/recipient_pubkey_directory.hpp"
#include "domain/exceptions.hpp"
#include <stdexcept>
#include <chrono>
#include <ctime>

SqlitePubkeyDirectory::SqlitePubkeyDirectory(const std::string& dbPath) : dbPath_(dbPath), db_(nullptr) {
  if (sqlite3_open(dbPath.c_str(), &db_) != SQLITE_OK) {
    throw std::runtime_error("sqlite open failed");
  }
  // WAL, synchronous=FULL, foreign_keys=ON as per spec
  exec("PRAGMA journal_mode=WAL;");
  exec("PRAGMA synchronous=FULL;");
  exec("PRAGMA foreign_keys=ON;");
  exec("CREATE TABLE IF NOT EXISTS recipient_pubkeys(user_id TEXT PRIMARY KEY, pubkey BLOB, alg TEXT, created_at TEXT);");
}

SqlitePubkeyDirectory::~SqlitePubkeyDirectory() {
  if (db_) sqlite3_close(db_);
}

void SqlitePubkeyDirectory::exec(const std::string& sql) const {
  char* err = nullptr;
  if (sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
    std::string e = err ? err : "exec failed";
    sqlite3_free(err);
    throw std::runtime_error(e);
  }
}

void SqlitePubkeyDirectory::savePubkey(const UserId& uid, const std::vector<uint8_t>& pub) {
  if (uid.value.empty()) throw ValidationException("user_id empty");
  if (pub.size() != 32) throw ValidationException("pubkey must be 32 bytes");
  if (pub.empty()) throw ValidationException("pubkey empty");
  // BEGIN IMMEDIATE
  exec("BEGIN IMMEDIATE;");
  const char* sql = "INSERT INTO recipient_pubkeys(user_id, pubkey, alg, created_at) VALUES(?,?,?,?);";
  sqlite3_stmt* stmt = nullptr;
  int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) {
    exec("ROLLBACK;");
    throw std::runtime_error("prepare failed");
  }
  // current time as RFC3339-ish simple epoch string
  auto now = std::chrono::system_clock::now();
  std::time_t t = std::chrono::system_clock::to_time_t(now);
  std::tm tm{};
#ifdef _WIN32
  gmtime_s(&tm, &t);
#else
  gmtime_r(&t, &tm);
#endif
  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
  std::string nowStr(buf);
  std::string alg = "X25519-AES-GCM-Seal";

  sqlite3_bind_text(stmt, 1, uid.value.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_blob(stmt, 2, pub.data(), static_cast<int>(pub.size()), SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, alg.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, nowStr.c_str(), -1, SQLITE_TRANSIENT);

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if (rc != SQLITE_DONE) {
    exec("ROLLBACK;");
    if (rc == SQLITE_CONSTRAINT) throw ValidationException("duplicate user_id");
    throw std::runtime_error("insert failed");
  }
  if (sqlite3_changes(db_) != 1) {
    exec("ROLLBACK;");
    throw std::runtime_error("no row inserted");
  }
  exec("COMMIT;");
}

std::vector<uint8_t> SqlitePubkeyDirectory::getPubkey(const UserId& uid) const {
  if (uid.value.empty()) throw ValidationException("user_id empty");
  const char* sql = "SELECT pubkey FROM recipient_pubkeys WHERE user_id=?;";
  sqlite3_stmt* stmt = nullptr;
  if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    throw std::runtime_error("prepare failed");
  }
  sqlite3_bind_text(stmt, 1, uid.value.c_str(), -1, SQLITE_TRANSIENT);
  std::vector<uint8_t> out;
  int rc = sqlite3_step(stmt);
  if (rc == SQLITE_ROW) {
    const void* blob = sqlite3_column_blob(stmt, 0);
    int n = sqlite3_column_bytes(stmt, 0);
    if (blob && n > 0) {
      const uint8_t* p = static_cast<const uint8_t*>(blob);
      out.assign(p, p + n);
    }
  } else {
    sqlite3_finalize(stmt);
    throw NotFoundException("pubkey not found");
  }
  sqlite3_finalize(stmt);
  return out;
}

bool SqlitePubkeyDirectory::exists(const UserId& uid) const {
  if (uid.value.empty()) return false;
  const char* sql = "SELECT 1 FROM recipient_pubkeys WHERE user_id=? LIMIT 1;";
  sqlite3_stmt* stmt = nullptr;
  if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
  sqlite3_bind_text(stmt, 1, uid.value.c_str(), -1, SQLITE_TRANSIENT);
  bool found = (sqlite3_step(stmt) == SQLITE_ROW);
  sqlite3_finalize(stmt);
  return found;
}

std::vector<UserId> SqlitePubkeyDirectory::listAll() const {
  std::vector<UserId> out;
  const char* sql = "SELECT user_id FROM recipient_pubkeys;";
  sqlite3_stmt* stmt = nullptr;
  if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return out;
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    const unsigned char* txt = sqlite3_column_text(stmt, 0);
    if (txt) out.push_back(UserId{reinterpret_cast<const char*>(txt)});
  }
  sqlite3_finalize(stmt);
  return out;
}
