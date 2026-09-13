// client/main.cpp
#include <iostream>
int main(int argc, char** argv) {
  for (int i = 1; i < argc; ++i)
    if (std::string(argv[i]) == "--help") { std::cout << "sft_client --server <ip> --port 5000\n"; return 0; }
  std::cout << "sft_client stub: use --help\n";
  return 0;
}