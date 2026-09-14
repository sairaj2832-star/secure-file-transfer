#pragma once
#include <cstdint>
#include <string>
#include <vector>

class IFileValidator {
 public:
  virtual ~IFileValidator() = default;
  virtual void validate(const std::string& origName, uint64_t size,
                        const std::vector<uint8_t>& headerBytes) = 0;
};
