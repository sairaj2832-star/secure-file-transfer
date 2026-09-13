// include/presentation/cli.hpp
#pragma once
#include <iostream>
#include <string>
#include "presentation/ansi.hpp"
inline bool askYesNo(const std::string& prompt, std::istream& in = std::cin) {
  std::cout << prompt << " [y/N] ";
  std::string a; std::getline(in, a);
  return !a.empty() && (a[0] == 'y' || a[0] == 'Y');
}
inline void printSuccess(const std::string& m) { std::cout << ansi::green() << m << ansi::reset() << "\n"; }
inline void printError(const std::string& m) { std::cout << ansi::red() << m << ansi::reset() << "\n"; }