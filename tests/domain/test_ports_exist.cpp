#include <gtest/gtest.h>
#include "ports/key_directory.hpp"
#include "ports/file_repository.hpp"
#include "ports/transfer_repository.hpp"
#include "ports/file_validator.hpp"

TEST(PortsExist, Compile) {
  IKeyDirectory* kd = nullptr;
  IFileRepository* fr = nullptr;
  ITransferRepository* tr = nullptr;
  IFileValidator* fv = nullptr;
  EXPECT_EQ(kd, nullptr);
  EXPECT_EQ(fr, nullptr);
  EXPECT_EQ(tr, nullptr);
  EXPECT_EQ(fv, nullptr);
}

TEST(PortsExist, InterfaceSignatures) {
  // Compile-time check that interfaces have expected methods
  static_assert(std::is_abstract_v<IKeyDirectory>);
  static_assert(std::is_abstract_v<IFileRepository>);
  static_assert(std::is_abstract_v<ITransferRepository>);
  static_assert(std::is_abstract_v<IFileValidator>);
}
