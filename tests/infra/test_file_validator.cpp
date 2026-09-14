#include <gtest/gtest.h>
#include "infrastructure/file_validator.hpp"
#include "domain/exceptions.hpp"

TEST(FileValidator, AcceptsPdf){
  PdfFileValidator v;
  std::vector<uint8_t> hdr{'%','P','D','F','-', '1','.', '4'};
  EXPECT_NO_THROW(v.validate("assignment.pdf", 1024, hdr));
}

TEST(FileValidator, RejectsNonPdfMagic){
  PdfFileValidator v;
  std::vector<uint8_t> hdr{'P','N','G',0};
  EXPECT_THROW(v.validate("image.png", 100, hdr), ValidationException);
}

TEST(FileValidator, RejectsTraversal){
  PdfFileValidator v;
  std::vector<uint8_t> hdr{'%','P','D','F'};
  EXPECT_THROW(v.validate("../etc/passwd.pdf", 100, hdr), ValidationException);
  EXPECT_THROW(v.validate("a/../../b.pdf", 100, hdr), ValidationException);
}

TEST(FileValidator, RejectsDoubleExt){
  PdfFileValidator v;
  std::vector<uint8_t> hdr{'%','P','D','F'};
  // Adapted to match impl: impl rejects any name containing ".pdf." or not ending with ".pdf".
  // Both cases contain ".pdf." and do not end with ".pdf", so they trigger ValidationException.
  EXPECT_THROW(v.validate("file.pdf.exe", 100, hdr), ValidationException);
  EXPECT_THROW(v.validate("backup.pdf.tmp", 100, hdr), ValidationException);
}

TEST(FileValidator, RejectsOversize){
  PdfFileValidator v;
  std::vector<uint8_t> hdr{'%','P','D','F'};
  EXPECT_THROW(v.validate("big.pdf", 101ULL*1024*1024, hdr), ValidationException);
}
