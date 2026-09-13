// src/presentation/client_app.cpp — real TLS client (no local auth, no FakeHasher)
#include "presentation/client_app.hpp"
#include "presentation/cli.hpp"
#include "presentation/ansi.hpp"
#include "presentation/protocol.hpp"
#include "infrastructure/asio_tls_transport.hpp"
#include "ports/transport.hpp"
#include <iostream>
int ClientApp::run(const std::string& ip, uint16_t port) {
  TrustConfig trust;
  trust.certPath = "./certs/server.crt";
  trust.caPath = "./certs/server.crt";
  std::string fp = computeSha256Fingerprint(trust.certPath);
  if(!fp.empty()) trust.fingerprint = fp;
  AsioTlsTransport transport(trust);
  try{
    transport.connect(ip, port);
    std::cout << ansi::green() << "Connected to " << ip << ":" << port << " with TLS verify_peer" << ansi::reset() << "\n";
  } catch(const std::exception& e){
    printError(std::string("TLS authentication failed: ") + e.what());
    std::cout << formatSafeAuthMessage(AuditAction::TLS_FAIL, "") << "\n";
    return 1;
  }
  std::string sessionToken; // sess_ token, never logged
  while (true) {
    std::cout << "1) Register  2) Login  3) Logout  4) Quit\n> ";
    std::string c; std::getline(std::cin, c);
    if (c == "1") {
      std::string user, email, pw;
      std::cout << "Username: "; std::getline(std::cin, user);
      std::cout << "Email: "; std::getline(std::cin, email);
      std::cout << "Password: "; std::getline(std::cin, pw);
      if (!askYesNo("Register " + user + "?")) continue;
      auto payload = encodeRegister(user, email, pw);
      Frame req{MsgType::REGISTER, 1, payload};
      transport.sendFrame(req);
      Frame resp; if(transport.recvFrame(resp, 5000)){
        std::string msg(resp.body.begin(), resp.body.end());
        if(resp.type==MsgType::REGISTER) printSafe(msg);
        else printError(msg);
      }
    } else if (c == "2") {
      std::string user, pw;
      std::cout << "Username: "; std::getline(std::cin, user);
      std::cout << "Password: "; std::getline(std::cin, pw);
      auto payload = encodeLogin(user, pw);
      Frame req{MsgType::AUTH, 2, payload};
      transport.sendFrame(req);
      Frame resp; if(transport.recvFrame(resp, 5000)){
        if(resp.type==MsgType::AUTH){
          sessionToken.assign(resp.body.begin(), resp.body.end());
          printSafe(formatSafeAuthMessage(AuditAction::LOGIN_OK, user));
          std::cout << "Session established (token not displayed)\n";
        } else {
          std::string msg(resp.body.begin(), resp.body.end());
          printError(msg.empty()? "Login failed" : msg);
        }
      }
    } else if (c == "3") {
      if(sessionToken.empty()){ printError("Not logged in"); continue; }
      Frame req{MsgType::LOGOUT, 3, std::vector<uint8_t>(sessionToken.begin(), sessionToken.end())};
      transport.sendFrame(req);
      Frame resp; if(transport.recvFrame(resp, 5000)){
        std::string msg(resp.body.begin(), resp.body.end());
        printSafe(msg);
        sessionToken.clear();
      }
    } else if (c == "4") break;
  }
  transport.close();
  return 0;
}
