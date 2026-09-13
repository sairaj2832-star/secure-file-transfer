#include "presentation/protocol.hpp"
#include "ports/transport.hpp"
#include "domain/exceptions.hpp"
std::vector<uint8_t> encodeRegister(const std::string& u, const std::string& e, const std::string& p){
  std::vector<uint8_t> out;
  put32be(out, (uint32_t)u.size()); out.insert(out.end(), u.begin(), u.end());
  put32be(out, (uint32_t)e.size()); out.insert(out.end(), e.begin(), e.end());
  put32be(out, (uint32_t)p.size()); out.insert(out.end(), p.begin(), p.end());
  return out;
}
RegisterPayload decodeRegister(const std::vector<uint8_t>& b){
  size_t off=0;
  auto read=[&]()->std::string{
    if(off+4>b.size()) throw ValidationException("short");
    uint32_t len=get32be(b.data()+off); off+=4;
    if(off+len>b.size()) throw ValidationException("short body");
    std::string s(b.begin()+off, b.begin()+off+len); off+=len; return s;
  };
  RegisterPayload r; r.username=read(); r.email=read(); r.password=read(); return r;
}
std::vector<uint8_t> encodeLogin(const std::string& u, const std::string& p){
  std::vector<uint8_t> out;
  put32be(out, (uint32_t)u.size()); out.insert(out.end(), u.begin(), u.end());
  put32be(out, (uint32_t)p.size()); out.insert(out.end(), p.begin(), p.end());
  return out;
}
LoginPayload decodeLogin(const std::vector<uint8_t>& b){
  size_t off=0;
  auto read=[&]()->std::string{
    if(off+4>b.size()) throw ValidationException("short");
    uint32_t len=get32be(b.data()+off); off+=4;
    if(off+len>b.size()) throw ValidationException("short body");
    std::string s(b.begin()+off, b.begin()+off+len); off+=len; return s;
  };
  LoginPayload r; r.username=read(); r.password=read(); return r;
}
std::vector<uint8_t> encodeAdmin(const std::string& token, const std::string& target){
  std::vector<uint8_t> out;
  put32be(out, (uint32_t)token.size()); out.insert(out.end(), token.begin(), token.end());
  put32be(out, (uint32_t)target.size()); out.insert(out.end(), target.begin(), target.end());
  return out;
}
AdminPayload decodeAdmin(const std::vector<uint8_t>& b){
  size_t off=0;
  auto read=[&]()->std::string{
    if(off+4>b.size()) throw ValidationException("short");
    uint32_t len=get32be(b.data()+off); off+=4;
    if(off+len>b.size()) throw ValidationException("short body");
    std::string s(b.begin()+off, b.begin()+off+len); off+=len; return s;
  };
  AdminPayload r; r.token=read(); r.targetId=read(); return r;
}
