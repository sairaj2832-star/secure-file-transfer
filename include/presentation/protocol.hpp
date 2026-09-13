// include/presentation/protocol.hpp
#pragma once
#include <string>
#include <vector>
#include <cstdint>
struct RegisterPayload { std::string username, email, password; };
struct LoginPayload { std::string username, password; };
struct AdminPayload { std::string token; std::string targetId; };
std::vector<uint8_t> encodeRegister(const std::string& u, const std::string& e, const std::string& p);
RegisterPayload decodeRegister(const std::vector<uint8_t>& body);
std::vector<uint8_t> encodeLogin(const std::string& u, const std::string& p);
LoginPayload decodeLogin(const std::vector<uint8_t>& body);
std::vector<uint8_t> encodeAdmin(const std::string& token, const std::string& target);
AdminPayload decodeAdmin(const std::vector<uint8_t>& body);
