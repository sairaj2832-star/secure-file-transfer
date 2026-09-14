#pragma once
#include "ports/file_validator.hpp"
#include <cstdint>
#include <string>
#include <vector>

class PdfFileValidator : public IFileValidator {
public:
  void validate(const std::string& origName, uint64_t size,
                const std::vector<uint8_t>& headerBytes) override;
};
