// src/presentation/server_app.cpp
#include "presentation/server_app.hpp"
#include "presentation/cli.hpp"
#include "presentation/ansi.hpp"
#include <cstdint>
#include <iostream>
int ServerApp::run(uint16_t port) {
  std::cout << ansi::green() << "SERVER IPv4=127.0.0.1 PORT=" << port << " FINGERPRINT=FAKE-SHA256-STAGE0-DEMO" << ansi::reset() << "\n";
  std::cout << "Server running (Stage-0 stub). Press Enter to exit...\n";
  std::string dummy; std::getline(std::cin, dummy);
  return 0;
}