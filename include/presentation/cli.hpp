// include/presentation/cli.hpp
#pragma once
#include <iostream>
#include <string>
#include "presentation/ansi.hpp"
#include "domain/audit_event.hpp"
inline bool askYesNo(const std::string& prompt, std::istream& in = std::cin) {
  std::cout << prompt << " [y/N] ";
  std::string a; std::getline(in, a);
  return !a.empty() && (a[0] == 'y' || a[0] == 'Y');
}
inline void printSuccess(const std::string& m) { std::cout << ansi::green() << m << ansi::reset() << "\n"; }
inline void printError(const std::string& m) { std::cout << ansi::red() << m << ansi::reset() << "\n"; }
inline std::string formatSafeAuthMessage(const char* action, const std::string& actor){
  if(std::string(action)==AuditAction::REGISTER_OK) return "Registration succeeded for " + actor;
  if(std::string(action)==AuditAction::REGISTER_FAIL) return "Registration failed";
  if(std::string(action)==AuditAction::LOGIN_OK) return "Login succeeded";
  if(std::string(action)==AuditAction::LOGIN_FAIL) return "Login failed";
  if(std::string(action)==AuditAction::LOGOUT) return "Logged out";
  if(std::string(action)==AuditAction::ACTIVATE) return "Account activated: " + actor;
  if(std::string(action)==AuditAction::DEACTIVATE) return "Account deactivated: " + actor;
  if(std::string(action)==AuditAction::ADMIN_DENIED) return "Admin action denied";
  if(std::string(action)==AuditAction::TLS_FAIL) return "TLS authentication failed";
  return std::string("Auth event: ")+action;
}
inline void printSafe(const std::string& msg){ std::cout << ansi::green() << msg << ansi::reset() << "\n"; }