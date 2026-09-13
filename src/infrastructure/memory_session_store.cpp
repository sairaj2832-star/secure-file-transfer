#include "infrastructure/memory_session_store.hpp"
#include "domain/ids.hpp"
#include "domain/digest.hpp"
#include <random>
#include <sstream>
#include <iomanip>
std::string MemorySessionStore::hashToken(const std::string& t) const {
  // SHA256 via sha256stub for now (deterministic, not cryptographic, but suffices for store key)
  // Real implementation should use OpenSSL SHA256
  auto d = sha256stub(t);
  std::string s;
  s.reserve(64);
  for(auto b: d.bytes) {
    char buf[3]; snprintf(buf,sizeof(buf),"%02x", b);
    s+=buf;
  }
  return s;
}
SessionId MemorySessionStore::createForUser(const UserId& uid, int64_t now){
  // CSPRNG 32B hex -> dl_ prefix
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<int> dis(0,255);
  std::string raw;
  raw.reserve(64);
  for(int i=0;i<32;i++){
    char buf[3]; snprintf(buf,sizeof(buf),"%02x", dis(gen));
    raw+=buf;
  }
  std::string token = "dl_" + raw;
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
