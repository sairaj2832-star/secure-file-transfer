// include/presentation/client_app.hpp
#pragma once
#include <cstdint>
#include <string>
class ClientApp {
 public:
  int run(const std::string& ip, uint16_t port);
};