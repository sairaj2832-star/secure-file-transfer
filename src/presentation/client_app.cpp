// src/presentation/client_app.cpp
#include "presentation/client_app.hpp"
#include "presentation/cli.hpp"
#include "presentation/ansi.hpp"
#include "application/auth_service.hpp"
#include "application/transfer_service.hpp"
#include "infrastructure/fake_crypto.hpp"
#include "infrastructure/memory_storage.hpp"
#include "infrastructure/vector_audit.hpp"
#include "infrastructure/fake_transport.hpp"
#include "ports/transport.hpp"
#include <iostream>
int ClientApp::run(const std::string& ip, uint16_t port) {
  (void)ip; (void)port;
  // Stage-0: use FakeTransport loopback for demo
  FakeTransport::queue_.clear();
  FakeTransport transport;
  MemoryStorage st; FakeCrypto cr; VectorAudit au;
  TransferService svc(&st, &cr, &au);
  // seed users
  svc.addUser("alice"); svc.addUser("bob"); svc.addUser("carol");
  AuthService auth;
  std::string user, pw;
  std::cout << "Login: "; std::getline(std::cin, user);
  std::cout << "Password: "; std::getline(std::cin, pw);
  auto lr = auth.login(user, pw);
  if (!lr.ok) { printError("Login failed"); return 1; }
  std::cout << ansi::green() << "Logged in as " << user << ansi::reset() << "\n";
  // simple menu
  while (true) {
    std::cout << "1) Upload\n2) List\n3) Download\n4) Quit\n> ";
    std::string c; std::getline(std::cin, c);
    if (c == "1") {
      std::string fn, recip; std::cout << "File: "; std::getline(std::cin, fn);
      std::cout << "Recipient: "; std::getline(std::cin, recip);
      if (!askYesNo("Upload " + fn + " for " + recip + "?")) continue;
      std::vector<uint8_t> data(1024, 'x'); // dummy
      auto up = svc.upload(UserId{user}, recip, fn, data);
      if (up.ok) printSuccess("Uploaded, transferId: " + up.value.id.value);
      else printError(up.error);
    } else if (c == "2") {
      auto lst = svc.listFor(UserId{user});
      for (auto& t : lst) std::cout << "  " << t.id.value << " -> " << t.recipient.value << "\n";
    } else if (c == "3") {
      std::string tid; std::cout << "TransferId: "; std::getline(std::cin, tid);
      auto dl = svc.download(UserId{user}, FileId{tid});
      if (dl.ok) printSuccess("Downloaded " + std::to_string(dl.value.size()) + " bytes");
      else printError(dl.error);
    } else if (c == "4") break;
  }
  return 0;
}