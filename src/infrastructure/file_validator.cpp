#include "infrastructure/file_validator.hpp"
#include "domain/exceptions.hpp"
#include <filesystem>

namespace fs = std::filesystem;

static bool ends_with(const std::string& s, const std::string& suffix) {
  if (suffix.size() > s.size()) return false;
  return s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

void PdfFileValidator::validate(const std::string& origName, uint64_t size,
                                const std::vector<uint8_t>& headerBytes) {
  if (origName.empty() || origName.find('\0') != std::string::npos) {
    throw ValidationException("name empty or NUL");
  }
  auto norm = fs::path(origName).lexically_normal().string();
  if (norm.find("..") != std::string::npos) {
    throw ValidationException("traversal");
  }
  if (!ends_with(norm, ".pdf")) {
    throw ValidationException("PDF-only core");
  }
  if (norm.find(".pdf.") != std::string::npos) {
    throw ValidationException("double ext");
  }
  if (size > 100ULL * 1024 * 1024) {
    throw ValidationException("oversize");
  }
  if (headerBytes.size() < 4 || headerBytes[0] != '%' || headerBytes[1] != 'P' ||
      headerBytes[2] != 'D' || headerBytes[3] != 'F') {
    throw ValidationException("PDF magic");
  }
}
