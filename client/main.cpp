// client/main.cpp
#include <iostream>
#include <string>
#include "presentation/client_app.hpp"
int main(int argc, char** argv) {
  std::string ip = "127.0.0.1";
  uint16_t port = 5000;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--help") { std::cout << "sft_client --server <ip> --port 5000\n"; return 0; }
    if (a == "--server" && i+1 < argc) ip = argv[++i];
    if (a == "--port" && i+1 < argc) port = static_cast<uint16_t>(std::stoi(argv[++i]));
  }
  ClientApp app;
  return app.run(ip, port);
}