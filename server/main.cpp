// server/main.cpp
#include <iostream>
int main(int argc, char** argv) {
  for (int i = 1; i < argc; ++i)
    if (std::string(argv[i]) == "--help") { std::cout << "sft_server --port 5000\n"; return 0; }
  std::cout << "sft_server stub: use --help\n";
  return 0;
}