// include/infrastructure/fake_hasher.hpp — tests only, never prod
#pragma once
#include "ports/password_hasher.hpp"
#include "domain/digest.hpp"
#include <unordered_map>
#include <string>
#include <cstdio>
class FakeHasher : public IPasswordHasher {
  std::unordered_map<std::string,std::string> m_;
  int ctr_=0;
 public:
  std::string hash(const std::string& pw) override {
    // do not embed pw — use sha256stub so hash does not contain plaintext
    auto d = sha256stub(pw + std::to_string(ctr_++));
    std::string hex;
    for(auto b: d.bytes){ char buf[3]; snprintf(buf,sizeof(buf),"%02x", b); hex+=buf; }
    std::string h="$fake$"+hex;
    m_[h]=pw;
    return h;
  }
  bool verify(const std::string& h, const std::string& pw) override { auto it=m_.find(h); return it!=m_.end() && it->second==pw; }
};
