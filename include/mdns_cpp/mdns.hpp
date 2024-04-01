#pragma once

#include <string>
#include <map>
#include <thread>
#ifdef _WIN32
#include <Winsock2.h>
#include <Ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

struct sockaddr;

namespace mdns_cpp {

class mDNS {
 public:
  ~mDNS();

  void startService();
  void stopService();
  bool isServiceRunning();

  void setServiceHostname(const std::string &hostname);
  void setServicePort(std::uint16_t port);
  void setServiceName(const std::string &name);
  void setServiceTxtRecords(const std::map<std::string, std::string> &text_records);

  void executeQuery(const std::string &service);
  void executeDiscovery();

 private:
  void runMainLoop();
  int openClientSockets(int *sockets, int max_sockets, int port);
  int openServiceSockets(int *sockets, int max_sockets);

  std::string hostname_{"dummy-host"};
  std::string name_{"_http._tcp.local."};
  std::uint16_t port_{42424};
  std::map<std::string, std::string> txt_records_{};

  bool running_{false};

  bool has_ipv4_{false};
  bool has_ipv6_{false};

  struct sockaddr_in service_address_ipv4_{};
  struct sockaddr_in6 service_address_ipv6_{};

  std::thread worker_thread_;
};

}  // namespace mdns_cpp
