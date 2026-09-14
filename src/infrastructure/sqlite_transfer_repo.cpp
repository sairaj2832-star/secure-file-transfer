#include "infrastructure/sqlite_transfer_repo.hpp"
#include "domain/exceptions.hpp"
#include <stdexcept>

static std::string statusToString(Transfer::Status s){
  switch(s){
    case Transfer::Status::CREATED: return "CREATED";
    case Transfer::Status::UPLOADED: return "UPLOADED";
    case Transfer::Status::DOWNLOADED: return "DOWNLOADED";
    case Transfer::Status::FAILED: return "FAILED";
    default: return "CREATED";
  }
}
static Transfer::Status stringToStatus(const std::string& s){
  if(s=="UPLOADED") return Transfer::Status::UPLOADED;
  if(s=="DOWNLOADED") return Transfer::Status::DOWNLOADED;
  if(s=="FAILED") return Transfer::Status::FAILED;
  return Transfer::Status::CREATED;
}

SqliteTransferRepository::SqliteTransferRepository(const std::string& dbPath) : dbPath_(dbPath), db_(nullptr){
  if(sqlite3_open(dbPath.c_str(), &db_)!=SQLITE_OK) throw std::runtime_error("sqlite open failed");
  exec("PRAGMA journal_mode=WAL;");
  exec("PRAGMA synchronous=FULL;");
  exec("PRAGMA foreign_keys=ON;");
  exec("CREATE TABLE IF NOT EXISTS transfers(id TEXT PRIMARY KEY, file_id TEXT, sender TEXT, recipient TEXT, status TEXT, created_at TEXT, updated_at TEXT);");
}
SqliteTransferRepository::~SqliteTransferRepository(){
  if(db_) sqlite3_close(db_);
}
void SqliteTransferRepository::exec(const std::string& sql) const {
  char* err=nullptr;
  if(sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err)!=SQLITE_OK){
    std::string e = err?err:"exec failed";
    sqlite3_free(err);
    throw std::runtime_error(e);
  }
}

void SqliteTransferRepository::save(const Transfer& t){
  exec("BEGIN IMMEDIATE;");
  const char* sql = "INSERT INTO transfers(id, file_id, sender, recipient, status, created_at, updated_at) VALUES(?,?,?,?,?,?,?);";
  sqlite3_stmt* stmt=nullptr;
  int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
  if(rc!=SQLITE_OK){ exec("ROLLBACK;"); throw std::runtime_error("prepare failed"); }
  sqlite3_bind_text(stmt,1,t.id.value.c_str(),-1,SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt,2,t.file.value.c_str(),-1,SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt,3,t.sender.value.c_str(),-1,SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt,4,t.recipient.value.c_str(),-1,SQLITE_TRANSIENT);
  std::string st = statusToString(t.status);
  sqlite3_bind_text(stmt,5,st.c_str(),-1,SQLITE_TRANSIENT);
  // timestamps empty for now
  sqlite3_bind_text(stmt,6,"",-1,SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt,7,"",-1,SQLITE_TRANSIENT);
  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if(rc!=SQLITE_DONE){
    exec("ROLLBACK;");
    if(rc==SQLITE_CONSTRAINT) throw ValidationException("duplicate transfer id");
    throw std::runtime_error("insert failed");
  }
  if(sqlite3_changes(db_)!=1){
    exec("ROLLBACK;");
    throw std::runtime_error("no row inserted");
  }
  exec("COMMIT;");
}

Result<Transfer> SqliteTransferRepository::findById(const TransferId& id) const {
  const char* sql = "SELECT id, file_id, sender, recipient, status, created_at, updated_at FROM transfers WHERE id=?;";
  sqlite3_stmt* stmt=nullptr;
  if(sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr)!=SQLITE_OK) return Result<Transfer>::failure("prepare failed");
  sqlite3_bind_text(stmt,1,id.value.c_str(),-1,SQLITE_TRANSIENT);
  Result<Transfer> res = Result<Transfer>::failure("not found");
  if(sqlite3_step(stmt)==SQLITE_ROW){
    Transfer t;
    t.id.value = reinterpret_cast<const char*>(sqlite3_column_text(stmt,0));
    t.file.value = reinterpret_cast<const char*>(sqlite3_column_text(stmt,1));
    t.sender.value = reinterpret_cast<const char*>(sqlite3_column_text(stmt,2));
    t.recipient.value = reinterpret_cast<const char*>(sqlite3_column_text(stmt,3));
    const unsigned char* st = sqlite3_column_text(stmt,4);
    std::string s = st?reinterpret_cast<const char*>(st):"CREATED";
    t.status = stringToStatus(s);
    res = Result<Transfer>::success(t);
  }
  sqlite3_finalize(stmt);
  return res;
}

std::vector<Transfer> SqliteTransferRepository::listFor(const UserId& user) const {
  std::vector<Transfer> out;
  const char* sql = "SELECT id, file_id, sender, recipient, status FROM transfers WHERE sender=? OR recipient=?;";
  sqlite3_stmt* stmt=nullptr;
  if(sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr)!=SQLITE_OK) return out;
  sqlite3_bind_text(stmt,1,user.value.c_str(),-1,SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt,2,user.value.c_str(),-1,SQLITE_TRANSIENT);
  while(sqlite3_step(stmt)==SQLITE_ROW){
    Transfer t;
    t.id.value = reinterpret_cast<const char*>(sqlite3_column_text(stmt,0));
    t.file.value = reinterpret_cast<const char*>(sqlite3_column_text(stmt,1));
    t.sender.value = reinterpret_cast<const char*>(sqlite3_column_text(stmt,2));
    t.recipient.value = reinterpret_cast<const char*>(sqlite3_column_text(stmt,3));
    const unsigned char* st = sqlite3_column_text(stmt,4);
    std::string s = st?reinterpret_cast<const char*>(st):"CREATED";
    t.status = stringToStatus(s);
    out.push_back(std::move(t));
  }
  sqlite3_finalize(stmt);
  return out;
}
