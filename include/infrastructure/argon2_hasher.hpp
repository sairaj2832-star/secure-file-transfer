// include/infrastructure/argon2_hasher.hpp
#pragma once
#include "ports/password_hasher.hpp"
class Argon2Hasher : public IPasswordHasher {
 public:
  std::string hash(const std::string& pw) override;
  bool verify(const std::string& encoded, const std::string& pw) override;
};
