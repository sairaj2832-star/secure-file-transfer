// server/main.cpp
#include <iostream>
#include <string>
#include "presentation/server_app.hpp"
int main(int argc, char** argv) {
  uint16_t port = 5000;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--help") { std::cout << "sft_server --port 5000\n"; return 0; }
    if (a == "--port" && i+1 < argc) port = static_cast<uint16_t>(std::stoi(argv[++i]));
  }
  ServerApp app;
  return app.run(port);
}