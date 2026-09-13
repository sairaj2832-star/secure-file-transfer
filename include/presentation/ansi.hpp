// include/presentation/ansi.hpp
#pragma once
#include <string>
namespace ansi {
inline std::string green() { return "\x1b[32m"; }
inline std::string red() { return "\x1b[31m"; }
inline std::string yellow() { return "\x1b[33m"; }
inline std::string reset() { return "\x1b[0m"; }
inline std::string progressBar(int pct) {
  int bars = pct / 10; std::string s = "[";
  for (int i = 0; i < 10; ++i) s += (i < bars ? "#" : "-");
  return s + "] " + std::to_string(pct) + "%";
}
}