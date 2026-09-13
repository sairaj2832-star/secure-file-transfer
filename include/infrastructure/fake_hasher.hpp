// include/infrastructure/fake_hasher.hpp — tests only, never prod
#pragma once
#include "ports/password_hasher.hpp"
#include <unordered_map>
#include <string>
class FakeHasher : public IPasswordHasher {
  std::unordered_map<std::string,std::string> m_;
  int ctr_=0;
 public:
  std::string hash(const std::string& pw) override { auto h="$fake$"+std::to_string(ctr_++)+"$"+pw; m_[h]=pw; return h; }
  bool verify(const std::string& h, const std::string& pw) override { auto it=m_.find(h); return it!=m_.end() && it->second==pw; }
};
