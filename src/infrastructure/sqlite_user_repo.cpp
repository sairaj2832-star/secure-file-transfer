#include "infrastructure/sqlite_user_repo.hpp"
#include "domain/exceptions.hpp"
#include <stdexcept>
SqliteUserRepository::SqliteUserRepository(const std::string& dbPath){
  if(sqlite3_open(dbPath.c_str(), &db_)!=SQLITE_OK) throw std::runtime_error("sqlite open failed");
  exec("PRAGMA journal_mode=WAL;");
  exec("PRAGMA synchronous=FULL;");
  exec("PRAGMA foreign_keys=ON;");
  exec("CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL, pass_hash TEXT NOT NULL, role TEXT NOT NULL, status TEXT NOT NULL, failed_attempts INT NOT NULL, lockout_until INTEGER NOT NULL);");
}
SqliteUserRepository::~SqliteUserRepository(){ if(db_) sqlite3_close(db_); }
void SqliteUserRepository::exec(const std::string& sql) const {
  char* err=nullptr;
  if(sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err)!=SQLITE_OK){
    std::string e = err?err:"exec failed";
    sqlite3_free(err);
    throw std::runtime_error(e);
  }
}
Result<User> SqliteUserRepository::findByColumn(const std::string& col, const std::string& val) const {
  std::string sql = "SELECT id, username, email, role, status, failed_attempts, lockout_until FROM users WHERE "+col+"=?;";
  sqlite3_stmt* stmt=nullptr;
  if(sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr)!=SQLITE_OK) return Result<User>::failure("prepare failed");
  sqlite3_bind_text(stmt,1,val.c_str(),-1,SQLITE_TRANSIENT);
  Result<User> res = Result<User>::failure("not found");
  if(sqlite3_step(stmt)==SQLITE_ROW){
    UserId id{reinterpret_cast<const char*>(sqlite3_column_text(stmt,0))};
    std::string username = reinterpret_cast<const char*>(sqlite3_column_text(stmt,1));
    std::string email = reinterpret_cast<const char*>(sqlite3_column_text(stmt,2));
    std::string role = reinterpret_cast<const char*>(sqlite3_column_text(stmt,3));
    std::string status = reinterpret_cast<const char*>(sqlite3_column_text(stmt,4));
    int fails = sqlite3_column_int(stmt,5);
    int64_t lockout = sqlite3_column_int64(stmt,6);
    User u(id, username, email, role, status, fails, lockout);
    res = Result<User>::success(u);
  }
  sqlite3_finalize(stmt);
  return res;
}
Result<User> SqliteUserRepository::findByUsername(const std::string& n) const { return findByColumn("username", n); }
Result<User> SqliteUserRepository::findByEmail(const std::string& e) const { return findByColumn("email", e); }
Result<User> SqliteUserRepository::findById(const UserId& id) const { return findByColumn("id", id.value); }
void SqliteUserRepository::save(const User& u, const std::string& encodedHash){
  exec("BEGIN IMMEDIATE;");
  const char* sql="INSERT INTO users(id, username, email, pass_hash, role, status, failed_attempts, lockout_until) VALUES(?,?,?,?,?,?,?,?);";
  sqlite3_stmt* stmt=nullptr;
  int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
  if(rc!=SQLITE_OK){ exec("ROLLBACK;"); throw std::runtime_error("prepare failed"); }
  sqlite3_bind_text(stmt,1,u.id().value.c_str(),-1,SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt,2,u.username().c_str(),-1,SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt,3,u.email().c_str(),-1,SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt,4,encodedHash.c_str(),-1,SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt,5,u.role().c_str(),-1,SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt,6,u.status().c_str(),-1,SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt,7,u.failedAttempts());
  sqlite3_bind_int64(stmt,8,u.lockoutUntil());
  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if(rc!=SQLITE_DONE){
    exec("ROLLBACK;");
    if(rc==SQLITE_CONSTRAINT) throw ValidationException("username or email exists");
    throw std::runtime_error("insert failed");
  }
  exec("COMMIT;");
}
void SqliteUserRepository::update(const User& u){
  // check immutable username/email
  auto existing = findById(u.id());
  if(!existing.ok || !existing.value.has_value()) throw NotFoundException("not found");
  if(existing.value->username()!=u.username() || existing.value->email()!=u.email())
    throw ValidationException("username/email immutable");
  exec("BEGIN IMMEDIATE;");
  const char* sql="UPDATE users SET role=?, status=?, failed_attempts=?, lockout_until=? WHERE id=?;";
  sqlite3_stmt* stmt=nullptr;
  if(sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr)!=SQLITE_OK){ exec("ROLLBACK;"); throw std::runtime_error("prepare failed"); }
  sqlite3_bind_text(stmt,1,u.role().c_str(),-1,SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt,2,u.status().c_str(),-1,SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt,3,u.failedAttempts());
  sqlite3_bind_int64(stmt,4,u.lockoutUntil());
  sqlite3_bind_text(stmt,5,u.id().value.c_str(),-1,SQLITE_TRANSIENT);
  int rc=sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if(rc!=SQLITE_DONE){ exec("ROLLBACK;"); throw std::runtime_error("update failed"); }
  exec("COMMIT;");
}
void SqliteUserRepository::updateHash(const UserId& id, const std::string& h){
  exec("BEGIN IMMEDIATE;");
  const char* sql="UPDATE users SET pass_hash=? WHERE id=?;";
  sqlite3_stmt* stmt=nullptr;
  sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
  sqlite3_bind_text(stmt,1,h.c_str(),-1,SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt,2,id.value.c_str(),-1,SQLITE_TRANSIENT);
  sqlite3_step(stmt); sqlite3_finalize(stmt); exec("COMMIT;");
}
void SqliteUserRepository::recordLoginFailure(const UserId& id, int64_t now){
  exec("BEGIN IMMEDIATE;");
  const char* sel="SELECT failed_attempts, lockout_until FROM users WHERE id=?;";
  sqlite3_stmt* stmt=nullptr;
  if(sqlite3_prepare_v2(db_, sel, -1, &stmt, nullptr)!=SQLITE_OK){ exec("ROLLBACK;"); throw std::runtime_error("prepare failed"); }
  sqlite3_bind_text(stmt,1,id.value.c_str(),-1,SQLITE_TRANSIENT);
  int fails=0; int64_t lockout=0;
  if(sqlite3_step(stmt)==SQLITE_ROW){
    fails = sqlite3_column_int(stmt,0);
    lockout = sqlite3_column_int64(stmt,1);
  } else { sqlite3_finalize(stmt); exec("ROLLBACK;"); throw NotFoundException("not found"); }
  sqlite3_finalize(stmt);
  fails++;
  int64_t newLockout = fails>=5 ? now + 15*60*1000 : lockout;
  const char* upd="UPDATE users SET failed_attempts=?, lockout_until=? WHERE id=?;";
  if(sqlite3_prepare_v2(db_, upd, -1, &stmt, nullptr)!=SQLITE_OK){ exec("ROLLBACK;"); throw std::runtime_error("prepare failed"); }
  sqlite3_bind_int(stmt,1,fails);
  sqlite3_bind_int64(stmt,2,newLockout);
  sqlite3_bind_text(stmt,3,id.value.c_str(),-1,SQLITE_TRANSIENT);
  int rc=sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if(rc!=SQLITE_DONE){ exec("ROLLBACK;"); throw std::runtime_error("update failed"); }
  if(sqlite3_changes(db_)!=1){ exec("ROLLBACK;"); throw std::runtime_error("no row updated"); }
  exec("COMMIT;");
}
void SqliteUserRepository::recordLoginFailure(const UserId& id, int f, int64_t until){
  exec("BEGIN IMMEDIATE;");
  const char* sql="UPDATE users SET failed_attempts=?, lockout_until=? WHERE id=?;";
  sqlite3_stmt* stmt=nullptr;
  if(sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr)!=SQLITE_OK){ exec("ROLLBACK;"); throw std::runtime_error("prepare failed"); }
  sqlite3_bind_int(stmt,1,f);
  sqlite3_bind_int64(stmt,2,until);
  sqlite3_bind_text(stmt,3,id.value.c_str(),-1,SQLITE_TRANSIENT);
  int rc=sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if(rc!=SQLITE_DONE){ exec("ROLLBACK;"); throw std::runtime_error("update failed"); }
  if(sqlite3_changes(db_)!=1){ exec("ROLLBACK;"); throw std::runtime_error("no row updated"); }
  exec("COMMIT;");
}
void SqliteUserRepository::resetLoginFailures(const UserId& id){
  exec("BEGIN IMMEDIATE;");
  const char* sql="UPDATE users SET failed_attempts=0, lockout_until=0 WHERE id=?;";
  sqlite3_stmt* stmt=nullptr;
  if(sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr)!=SQLITE_OK){ exec("ROLLBACK;"); throw std::runtime_error("prepare failed"); }
  sqlite3_bind_text(stmt,1,id.value.c_str(),-1,SQLITE_TRANSIENT);
  int rc=sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if(rc!=SQLITE_DONE){ exec("ROLLBACK;"); throw std::runtime_error("reset failed"); }
  exec("COMMIT;");
}
std::string SqliteUserRepository::getEncodedHash(const UserId& id) const {
  const char* sql="SELECT pass_hash FROM users WHERE id=?;";
  sqlite3_stmt* stmt=nullptr;
  sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
  sqlite3_bind_text(stmt,1,id.value.c_str(),-1,SQLITE_TRANSIENT);
  std::string out;
  if(sqlite3_step(stmt)==SQLITE_ROW){
    out = reinterpret_cast<const char*>(sqlite3_column_text(stmt,0));
  } else { sqlite3_finalize(stmt); throw NotFoundException("hash not found"); }
  sqlite3_finalize(stmt);
  return out;
}
std::vector<User> SqliteUserRepository::listAll() const {
  std::vector<User> out;
  const char* sql="SELECT id, username, email, role, status, failed_attempts, lockout_until FROM users;";
  sqlite3_stmt* stmt=nullptr;
  sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
  while(sqlite3_step(stmt)==SQLITE_ROW){
    UserId id{reinterpret_cast<const char*>(sqlite3_column_text(stmt,0))};
    std::string username = reinterpret_cast<const char*>(sqlite3_column_text(stmt,1));
    std::string email = reinterpret_cast<const char*>(sqlite3_column_text(stmt,2));
    std::string role = reinterpret_cast<const char*>(sqlite3_column_text(stmt,3));
    std::string status = reinterpret_cast<const char*>(sqlite3_column_text(stmt,4));
    int fails = sqlite3_column_int(stmt,5);
    int64_t lockout = sqlite3_column_int64(stmt,6);
    out.emplace_back(id, username, email, role, status, fails, lockout);
  }
  sqlite3_finalize(stmt);
  return out;
}
