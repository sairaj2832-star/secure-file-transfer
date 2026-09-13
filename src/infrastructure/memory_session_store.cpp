#include "infrastructure/memory_session_store.hpp"
#include "domain/ids.hpp"
#include "infrastructure/sha256.hpp"
#include <random>
#include <sstream>
#include <iomanip>
std::string MemorySessionStore::hashToken(const std::string& t) const {
  return real_sha256::hex(t);
}
SessionId MemorySessionStore::createForUser(const UserId& uid, int64_t now){
  // CSPRNG: std::random_device on Windows uses BCryptGenRandom (CSPRNG)
  std::random_device rd;
  unsigned char buf[32];
  for(int i=0;i<32;i++) buf[i]= static_cast<unsigned char>(rd() & 0xFF);
  std::string raw;
  raw.reserve(64);
  for(int i=0;i<32;i++){
    char tmp[3]; snprintf(tmp,sizeof(tmp),"%02x", buf[i]);
    raw+=tmp;
  }
  std::string token = "sess_" + raw;
  std::string h = hashToken(token);
  Session s{SessionId{token}, uid, now, now+3600*1000, false};
  byHash_[h]=s;
  userByHash_[h]=uid.value;
  return SessionId{token};
}
Result<Session> MemorySessionStore::findByToken(const SessionId& token) const {
  std::string h = hashToken(token.value);
  auto it = byHash_.find(h);
  if(it==byHash_.end()) return Result<Session>::failure("not found");
  return Result<Session>::success(it->second);
}
bool MemorySessionStore::invalidate(const SessionId& token){
  std::string h = hashToken(token.value);
  auto it = byHash_.find(h);
  if(it==byHash_.end()) return false;
  it->second.revoked=true;
  return true;
}
int MemorySessionStore::invalidateAllForUser(const UserId& u){
  int n=0;
  for(auto& [h,s] : byHash_){
    if(s.userId==u && !s.revoked){ s.revoked=true; n++; }
  }
  return n;
}
bool MemorySessionStore::isValid(const SessionId& token, int64_t now) const {
  auto r = findByToken(token);
  if(!r.ok || !r.value.has_value()) return false;
  return r.value->isValid(now);
}
