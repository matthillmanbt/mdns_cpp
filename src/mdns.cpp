#include "mdns_cpp/mdns.hpp"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <thread>
#include <vector>

#include "mdns.h"
#include "mdns_cpp/logger.hpp"
#include "mdns_cpp/macros.hpp"
#include "mdns_cpp/utils.hpp"

#ifdef _WIN32
#include <iphlpapi.h>
#else
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#endif
#include <string.h>

namespace mdns_cpp {

static mdns_record_txt_t txtbuffer[128];

int mDNS::openServiceSockets(int *sockets, int max_sockets) {
  // When receiving, each socket can receive data from all network interfaces
  // Thus we only need to open one socket for each address family
  int num_sockets = 0;

  // Call the client socket function to enumerate and get local addresses,
  // but not open the actual sockets
  openClientSockets(0, 0, 0);

  if (num_sockets < max_sockets) {
    sockaddr_in sock_addr{};
    sock_addr.sin_family = AF_INET;
#ifdef _WIN32
    sock_addr.sin_addr = in4addr_any;
#else
    sock_addr.sin_addr.s_addr = INADDR_ANY;
#endif
    sock_addr.sin_port = htons(MDNS_PORT);
#ifdef __APPLE__
    sock_addr.sin_len = sizeof(struct sockaddr_in);
#endif
    const int sock = mdns_socket_open_ipv4(&sock_addr);
    if (sock >= 0) {
      sockets[num_sockets++] = sock;
    }
  }

  if (num_sockets < max_sockets) {
    sockaddr_in6 sock_addr{};
    sock_addr.sin6_family = AF_INET6;
    sock_addr.sin6_addr = in6addr_any;
    sock_addr.sin6_port = htons(MDNS_PORT);
#ifdef __APPLE__
    sock_addr.sin6_len = sizeof(struct sockaddr_in6);
#endif
    int sock = mdns_socket_open_ipv6(&sock_addr);
    if (sock >= 0) sockets[num_sockets++] = sock;
  }

  return num_sockets;
}

int mDNS::openClientSockets(int *sockets, int max_sockets, int port) {
  // When sending, each socket can only send to one network interface
  // Thus we need to open one socket for each interface and address family
  int num_sockets = 0;

#ifdef _WIN32

  IP_ADAPTER_ADDRESSES *adapter_address = nullptr;
  ULONG address_size = 8000;
  unsigned int ret{};
  unsigned int num_retries = 4;
  do {
    adapter_address = (IP_ADAPTER_ADDRESSES *)malloc(address_size);
    ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, 0, adapter_address,
                               &address_size);
    if (ret == ERROR_BUFFER_OVERFLOW) {
      free(adapter_address);
      adapter_address = 0;
    } else {
      break;
    }
  } while (num_retries-- > 0);

  if (!adapter_address || (ret != NO_ERROR)) {
    free(adapter_address);
    LogMessage() << "Failed to get network adapter addresses\n";
    return num_sockets;
  }

  int first_ipv4 = 1;
  int first_ipv6 = 1;
  for (PIP_ADAPTER_ADDRESSES adapter = adapter_address; adapter; adapter = adapter->Next) {
    if (adapter->TunnelType == TUNNEL_TYPE_TEREDO) {
      continue;
    }
    if (adapter->OperStatus != IfOperStatusUp) {
      continue;
    }

    for (IP_ADAPTER_UNICAST_ADDRESS *unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
      if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
        struct sockaddr_in *saddr = (struct sockaddr_in *)unicast->Address.lpSockaddr;
        if ((saddr->sin_addr.S_un.S_un_b.s_b1 != 127) || (saddr->sin_addr.S_un.S_un_b.s_b2 != 0) ||
            (saddr->sin_addr.S_un.S_un_b.s_b3 != 0) || (saddr->sin_addr.S_un.S_un_b.s_b4 != 1)) {
          int log_addr = 0;
          if (first_ipv4) {
            service_address_ipv4_ = *saddr;
            first_ipv4 = 0;
            log_addr = 1;
          }
          has_ipv4_ = 1;
          if (num_sockets < max_sockets) {
            saddr->sin_port = htons((unsigned short)port);
            int sock = mdns_socket_open_ipv4(saddr);
            if (sock >= 0) {
              sockets[num_sockets++] = sock;
              log_addr = 1;
            } else {
              log_addr = 0;
            }
          }
          if (log_addr) {
            char buffer[128];
            const auto addr = ipv4AddressToString(buffer, sizeof(buffer), saddr, sizeof(struct sockaddr_in));
            MDNS_LOG << "Local IPv4 address: " << addr;
          }
        }
      } else if (unicast->Address.lpSockaddr->sa_family == AF_INET6) {
        struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)unicast->Address.lpSockaddr;
        static constexpr unsigned char localhost[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        static constexpr unsigned char localhost_mapped[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1};
        if ((unicast->DadState == NldsPreferred) && memcmp(saddr->sin6_addr.s6_addr, localhost, 16) &&
            memcmp(saddr->sin6_addr.s6_addr, localhost_mapped, 16)) {
          int log_addr = 0;
          if (first_ipv6) {
            service_address_ipv6_ = *saddr;
            first_ipv6 = 0;
            log_addr = 1;
          }
          has_ipv6_ = 1;
          if (num_sockets < max_sockets) {
            saddr->sin6_port = htons((unsigned short)port);
            int sock = mdns_socket_open_ipv6(saddr);
            if (sock >= 0) {
              sockets[num_sockets++] = sock;
              log_addr = 1;
            } else {
              log_addr = 0;
            }
          }
          if (log_addr) {
            char buffer[128];
            const auto addr = ipv6AddressToString(buffer, sizeof(buffer), saddr, sizeof(struct sockaddr_in6));
            MDNS_LOG << "Local IPv6 address: " << addr;
          }
        }
      }
    }
  }

  free(adapter_address);

#else

  struct ifaddrs *ifaddr = nullptr;
  struct ifaddrs *ifa = nullptr;

  if (getifaddrs(&ifaddr) < 0) {
    MDNS_LOG << "Unable to get interface addresses";
  }

  int first_ipv4 = 1;
  int first_ipv6 = 1;
  for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
    if (!ifa->ifa_addr) {
      continue;
    }

    if (ifa->ifa_addr->sa_family == AF_INET) {
      struct sockaddr_in *saddr = (struct sockaddr_in *)ifa->ifa_addr;
      if (saddr->sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
        int log_addr = 0;
        if (first_ipv4) {
          service_address_ipv4_ = *saddr;
          first_ipv4 = 0;
          log_addr = 1;
        }
        has_ipv4_ = 1;
        if (num_sockets < max_sockets) {
          saddr->sin_port = htons(port);
          int sock = mdns_socket_open_ipv4(saddr);
          if (sock >= 0) {
            sockets[num_sockets++] = sock;
            log_addr = 1;
          } else {
            log_addr = 0;
          }
        }
        if (log_addr) {
          char buffer[128];
          const auto addr = ipv4AddressToString(buffer, sizeof(buffer), saddr, sizeof(struct sockaddr_in));
          MDNS_LOG << "Local IPv4 address: " << addr;
        }
      }
    } else if (ifa->ifa_addr->sa_family == AF_INET6) {
      struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)ifa->ifa_addr;
      static constexpr unsigned char localhost[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
      static constexpr unsigned char localhost_mapped[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1};
      if (memcmp(saddr->sin6_addr.s6_addr, localhost, 16) && memcmp(saddr->sin6_addr.s6_addr, localhost_mapped, 16)) {
        int log_addr = 0;
        if (first_ipv6) {
          service_address_ipv6_ = *saddr;
          first_ipv6 = 0;
          log_addr = 1;
        }
        has_ipv6_ = 1;
        if (num_sockets < max_sockets) {
          saddr->sin6_port = htons(port);
          int sock = mdns_socket_open_ipv6(saddr);
          if (sock >= 0) {
            sockets[num_sockets++] = sock;
            log_addr = 1;
          } else {
            log_addr = 0;
          }
        }
        if (log_addr) {
          char buffer[128] = {};
          const auto addr = ipv6AddressToString(buffer, sizeof(buffer), saddr, sizeof(struct sockaddr_in6));
          MDNS_LOG << "Local IPv6 address: " << addr;
        }
      }
    }
  }

  freeifaddrs(ifaddr);

#endif

  return num_sockets;
}

static int query_callback(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry,
                          uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data,
                          size_t size, size_t name_offset, size_t name_length, size_t record_offset,
                          size_t record_length, void *user_data) {
  (void)sizeof(sock);
  (void)sizeof(query_id);
  (void)sizeof(name_length);
  (void)sizeof(user_data);

  QueryResult *res = static_cast<QueryResult*>(user_data);

  static char addrbuffer[64]{};
  static char namebuffer[256]{};
  static char entrybuffer[256]{};

  const auto fromaddrstr = ipAddressToString(addrbuffer, sizeof(addrbuffer), from, addrlen);
  const char *entrytype = (entry == MDNS_ENTRYTYPE_ANSWER) ? "answer" : ((entry == MDNS_ENTRYTYPE_AUTHORITY) ? "authority" : "additional");
  mdns_string_t entrystr = mdns_string_extract(data, size, &name_offset, entrybuffer, sizeof(entrybuffer));

  const int str_capacity = 1000;
  char str_buffer[str_capacity]={};

  if (rtype == MDNS_RECORDTYPE_PTR) {
    mdns_string_t namestr = mdns_record_parse_ptr(data, size, record_offset, record_length, namebuffer, sizeof(namebuffer));

    res->host = namestr.str;
    snprintf(str_buffer, str_capacity, "%s : %s %.*s PTR %.*s rclass 0x%x ttl %u length %d", fromaddrstr.data(),
             entrytype, MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(namestr), rclass, ttl, (int)record_length);
  } else if (rtype == MDNS_RECORDTYPE_SRV) {
    mdns_record_srv_t srv = mdns_record_parse_srv(data, size, record_offset, record_length, namebuffer, sizeof(namebuffer));
    res->srv = srv;
    snprintf(str_buffer, str_capacity,"%s : %s %.*s SRV %.*s priority %d weight %d port %d", fromaddrstr.data(), entrytype,
           MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(srv.name), srv.priority, srv.weight, srv.port);
  } else if (rtype == MDNS_RECORDTYPE_A) {
    struct sockaddr_in addr;
    mdns_record_parse_a(data, size, record_offset, record_length, &addr);
    const auto addrstr = ipv4AddressToString(namebuffer, sizeof(namebuffer), &addr, sizeof(addr));
    snprintf(str_buffer, str_capacity,"%s : %s %.*s A %s", fromaddrstr.data(), entrytype, MDNS_STRING_FORMAT(entrystr), addrstr.data());
    res->ipv4 = namebuffer;
  } else if (rtype == MDNS_RECORDTYPE_AAAA) {
    struct sockaddr_in6 addr;
    mdns_record_parse_aaaa(data, size, record_offset, record_length, &addr);
    const auto addrstr = ipv6AddressToString(namebuffer, sizeof(namebuffer), &addr, sizeof(addr));
    snprintf(str_buffer, str_capacity,"%s : %s %.*s AAAA %s", fromaddrstr.data(), entrytype, MDNS_STRING_FORMAT(entrystr), addrstr.data());
    res->ipv6 = namebuffer;
  } else if (rtype == MDNS_RECORDTYPE_TXT) {
    size_t parsed = mdns_record_parse_txt(data, size, record_offset, record_length, txtbuffer,
                                          sizeof(txtbuffer) / sizeof(mdns_record_txt_t));
    for (size_t itxt = 0; itxt < parsed; ++itxt) {
      res->txt.emplace_back(txtbuffer[itxt]);
      if (txtbuffer[itxt].value.length) {
        snprintf(str_buffer, str_capacity,"%s : %s %.*s TXT %.*s = %.*s", fromaddrstr.data(), entrytype, MDNS_STRING_FORMAT(entrystr),
               MDNS_STRING_FORMAT(txtbuffer[itxt].key), MDNS_STRING_FORMAT(txtbuffer[itxt].value));
      } else {
        snprintf(str_buffer, str_capacity,"%s : %s %.*s TXT %.*s", fromaddrstr.data(), entrytype, MDNS_STRING_FORMAT(entrystr),
               MDNS_STRING_FORMAT(txtbuffer[itxt].key));
      }
    }
  } else {
    snprintf(str_buffer, str_capacity,"%s : %s %.*s type %u rclass 0x%x ttl %u length %d\n", fromaddrstr.data(), entrytype,
           MDNS_STRING_FORMAT(entrystr), rtype, rclass, ttl, (int)record_length);
  }
  MDNS_LOG << std::string(str_buffer);

  return 0;
}

int service_callback(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type entry, uint16_t query_id,
                     uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data, size_t size, size_t name_offset,
                     size_t name_length, size_t record_offset, size_t record_length, void *user_data) {
  (void)sizeof(name_offset);
  (void)sizeof(name_length);
  (void)sizeof(ttl);

  if (static_cast<int>(entry) != MDNS_ENTRYTYPE_QUESTION) {
    return 0;
  }

  char addrbuffer[64] = {0};
  char namebuffer[256] = {0};
  const char dns_sd[] = "_services._dns-sd._udp.local.";
  mDNS *inst = (mDNS *)user_data;
  const ServiceRecord *service_record = inst->serviceRecord();
  char sendbuffer[256] = {0};

  const auto fromaddrstr = ipAddressToString(addrbuffer, sizeof(addrbuffer), from, addrlen);
  const auto enType = static_cast<mdns_record_type>(rtype);
  auto offset = name_offset;
  const mdns_string_t name = mdns_string_extract(data, size, &offset, namebuffer, sizeof(namebuffer));

  if ((name.length == (sizeof(dns_sd) - 1)) && (strncmp(name.str, dns_sd, sizeof(dns_sd) - 1) == 0)) {
    if (enType == mdns_record_type::MDNS_RECORDTYPE_PTR || enType == mdns_record_type::MDNS_RECORDTYPE_ANY) {
      MDNS_LOG << fromaddrstr << " : question PTR 1 " << std::string(name.str, name.length);
      // The PTR query was for the DNS-SD domain, send answer with a PTR record for the
			// service name we advertise, typically on the "<_service-name>._tcp.local." format

			// Answer PTR record reverse mapping "<_service-name>._tcp.local." to
			// "<hostname>.<_service-name>._tcp.local."
      mdns_record_t answer = {.name = name, .type = MDNS_RECORDTYPE_PTR, .data = { .ptr = {.name = service_record->service}}};
      uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
      MDNS_LOG << "  --> answer " << service_record->service << " (" << (unicast ? "unicast" : "multicast") << ")";
      if (unicast) {
        mdns_query_answer_unicast(sock, from, addrlen, sendbuffer, sizeof(sendbuffer), query_id, enType, name.str, name.length, answer, 0, 0, 0, 0);
      } else {
        mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0, 0, 0);
      }
    }
  } else if ((name.length == service_record->service.length) && (strncmp(name.str, service_record->service.str, name.length) == 0)) {
    if (enType == mdns_record_type::MDNS_RECORDTYPE_PTR || enType == mdns_record_type::MDNS_RECORDTYPE_ANY) {
      MDNS_LOG << fromaddrstr << " : question PTR 2 " << std::string(name.str, name.length);
      // The PTR query was for our service (usually "<_service-name._tcp.local"), answer a PTR
			// record reverse mapping the queried service name to our service instance name
			// (typically on the "<hostname>.<_service-name>._tcp.local." format), and add
			// additional records containing the SRV record mapping the service instance name to our
			// qualified hostname (typically "<hostname>.local.") and port, as well as any IPv4/IPv6
			// address for the hostname as A/AAAA records, and two test TXT records

			// Answer PTR record reverse mapping "<_service-name>._tcp.local." to
			// "<hostname>.<_service-name>._tcp.local."
      mdns_record_t answer = service_record->record_ptr;

      std::vector<mdns_record_t> additional;

      additional.emplace_back(inst->currentSRV());

      if (service_record->address_ipv4.sin_family == AF_INET) {
        additional.emplace_back(service_record->record_a);
      } else if (service_record->address_ipv6.sin6_family == AF_INET6) {
        additional.emplace_back(service_record->record_aaaa);
      }

      for (auto txt : service_record->txt_records) {
        additional.emplace_back(txt);
      }

      uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
      MDNS_LOG << "  --> answer " << service_record->hostname << "." << service_record->service << " port "
               << service_record->port << " (" << (unicast ? "unicast" : "multicast") << ")";
      if (unicast) {
        mdns_query_answer_unicast(sock, from, addrlen, sendbuffer, sizeof(sendbuffer), query_id, enType, name.str, name.length, answer, 0, 0, &additional[0], additional.size());
      } else {
        mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0, &additional[0], additional.size());
      }
    }
  } else if (name.length == service_record->service_instance.length && strncmp(name.str, service_record->service_instance.str, name.length) == 0) {
    if (enType == mdns_record_type::MDNS_RECORDTYPE_SRV || enType == mdns_record_type::MDNS_RECORDTYPE_ANY) {
      auto service = mdns_record_parse_srv(data, size, record_offset, record_length, namebuffer, sizeof(namebuffer));
      MDNS_LOG << fromaddrstr << " : question SRV  " << std::string(service.name.str, service.name.length);
      // The SRV query was for our service instance (usually
			// "<hostname>.<_service-name._tcp.local"), answer a SRV record mapping the service
			// instance name to our qualified hostname (typically "<hostname>.local.") and port, as
			// well as any IPv4/IPv6 address for the hostname as A/AAAA records, and two test TXT
			// records

			// Answer PTR record reverse mapping "<_service-name>._tcp.local." to
			// "<hostname>.<_service-name>._tcp.local."
			mdns_record_t answer = inst->currentSRV();
      std::vector<mdns_record_t> additional;

      if (service_record->address_ipv4.sin_family == AF_INET) {
        additional.emplace_back(service_record->record_a);
      } else if (service_record->address_ipv6.sin6_family == AF_INET6) {
        additional.emplace_back(service_record->record_aaaa);
      }

      for (auto txt : service_record->txt_records) {
        additional.emplace_back(txt);
      }

      uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
      MDNS_LOG << "  --> answer " << service_record->hostname << "." << service_record->service << " port "
               << service_record->port << " (" << (unicast ? "unicast" : "multicast") << ")";
      if (unicast) {
        mdns_query_answer_unicast(sock, from, addrlen, sendbuffer, sizeof(sendbuffer), query_id, enType, name.str, name.length, answer, 0, 0, &additional[0], additional.size());
      } else {
        mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0, &additional[0], additional.size());
      }
    }
  } else if (name.length == service_record->hostname_qualified.length && strncmp(name.str, service_record->hostname_qualified.str, name.length) == 0) {
    if (
      (enType == mdns_record_type::MDNS_RECORDTYPE_A || enType == mdns_record_type::MDNS_RECORDTYPE_ANY)
      && service_record->address_ipv4.sin_family == AF_INET
    ) {
      // The A query was for our qualified hostname (typically "<hostname>.local.") and we
			// have an IPv4 address, answer with an A record mapping the hostname to an IPv4
			// address, as well as any IPv6 address for the hostname, and two test TXT records

			// Answer A records mapping "<hostname>.local." to IPv4 address
      auto answer = service_record->record_a;

      std::vector<mdns_record_t> additional;

      additional.emplace_back(inst->currentSRV());

      if (service_record->address_ipv6.sin6_family == AF_INET6) {
        additional.emplace_back(service_record->record_aaaa);
      }

      for (auto txt : service_record->txt_records) {
        additional.emplace_back(txt);
      }

      uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
      MDNS_LOG << "  --> answer " << service_record->hostname << "." << service_record->service << " port "
               << service_record->port << " (" << (unicast ? "unicast" : "multicast") << ")";
      if (unicast) {
        mdns_query_answer_unicast(sock, from, addrlen, sendbuffer, sizeof(sendbuffer), query_id, enType, name.str, name.length, answer, 0, 0, &additional[0], additional.size());
      } else {
        mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0, &additional[0], additional.size());
      }
    } else if (
      (enType == mdns_record_type::MDNS_RECORDTYPE_AAAA || enType == mdns_record_type::MDNS_RECORDTYPE_ANY)
      && service_record->address_ipv6.sin6_family == AF_INET6
    ) {
      // The AAAA query was for our qualified hostname (typically "<hostname>.local.") and we
			// have an IPv6 address, answer with an AAAA record mapping the hostname to an IPv6
			// address, as well as any IPv4 address for the hostname, and two test TXT records

			// Answer AAAA records mapping "<hostname>.local." to IPv6 address
      auto answer = service_record->record_aaaa;

      std::vector<mdns_record_t> additional;

      additional.emplace_back(inst->currentSRV());

      if (service_record->address_ipv4.sin_family == AF_INET) {
        additional.emplace_back(service_record->record_a);
      }

      for (auto txt : service_record->txt_records) {
        additional.emplace_back(txt);
      }

      uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
      MDNS_LOG << "  --> answer " << service_record->hostname << "." << service_record->service << " port "
               << service_record->port << " (" << (unicast ? "unicast" : "multicast") << ")";
      if (unicast) {
        mdns_query_answer_unicast(sock, from, addrlen, sendbuffer, sizeof(sendbuffer), query_id, enType, name.str, name.length, answer, 0, 0, &additional[0], additional.size());
      } else {
        mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0, &additional[0], additional.size());
      }
    }
  }

  return 0;
}

mDNS::~mDNS() { stopService(); }

void mDNS::startService() {
  if (running_) {
    stopService();
  }

  running_ = true;
  worker_thread_ = std::thread([this]() { this->runMainLoop(); });
}

void mDNS::stopService() {
  running_ = false;
  if (worker_thread_.joinable()) {
    worker_thread_.join();
  }
}

bool mDNS::isServiceRunning() { return running_; }

void mDNS::setServiceHostname(const std::string &hostname) { hostname_ = hostname; }

void mDNS::setServicePort(std::uint16_t port) { port_ = port; }

void mDNS::setServiceName(const std::string &name) { name_ = name; }

void mDNS::setServiceTxtRecords(const std::map<std::string, std::string> &txt_records) { txt_records_ = txt_records; }

void mDNS::runMainLoop() {
  constexpr size_t number_of_sockets = 32;
  int sockets[number_of_sockets];
  const int num_sockets = openServiceSockets(sockets, sizeof(sockets) / sizeof(sockets[0]));
  if (num_sockets <= 0) {
    const auto msg = "Error: Failed to open any client sockets";
    MDNS_LOG << msg;
    throw std::runtime_error(msg);
  }

  MDNS_LOG << "Opened " << std::to_string(num_sockets) << " socket" << (num_sockets ? "s" : "")
           << " for mDNS service";
  MDNS_LOG << "Service mDNS: " << name_ << ":" << port_;
  MDNS_LOG << "Hostname: " << hostname_.data();


  constexpr size_t capacity = 2048u;
  std::shared_ptr<void> buffer(malloc(capacity), free);
  service_record_ = std::make_unique<ServiceRecord>();
  service_record_->service = { .str = name_.data(), .length = name_.length() };
  service_record_->hostname = { .str = hostname_.data(), .length = hostname_.length() };

	// Build the service instance "<hostname>.<_service-name>._tcp.local." string
	char service_instance_buffer[256] = {0};
	snprintf(service_instance_buffer, sizeof(service_instance_buffer) - 1, "%.*s.%.*s",
	         MDNS_STRING_FORMAT(service_record_->hostname), MDNS_STRING_FORMAT(service_record_->service));
	service_record_->service_instance = { .str = service_instance_buffer, .length = strlen(service_instance_buffer)};

	// Build the "<hostname>.local." string
	char qualified_hostname_buffer[256] = {0};
	snprintf(qualified_hostname_buffer, sizeof(qualified_hostname_buffer) - 1, "%.*s.local.",
	         MDNS_STRING_FORMAT(service_record_->hostname));
	service_record_->hostname_qualified = { .str = qualified_hostname_buffer, .length = strlen(qualified_hostname_buffer)};

  service_record_->address_ipv4 = service_address_ipv4_;
  service_record_->address_ipv6 = service_address_ipv6_;
  service_record_->port = port_;

  // Setup our mDNS records

	// PTR record reverse mapping "<_service-name>._tcp.local." to
	// "<hostname>.<_service-name>._tcp.local."
	service_record_->record_ptr = {.name = service_record_->service,
    .type = MDNS_RECORDTYPE_PTR,
    .data = {.ptr = {.name = service_record_->service_instance}}
  };

	// SRV record mapping "<hostname>.<_service-name>._tcp.local." to
	// "<hostname>.local." with port. Set weight & priority to 0.
	service_record_->record_srv = {
    .name = service_record_->service_instance,
    .type = MDNS_RECORDTYPE_SRV,
    .data = {
      .srv = {
        .priority = 0,
        .weight = 0,
        .port = service_record_->port,
        .name = service_record_->hostname_qualified
      }
    }
  };

	// A/AAAA records mapping "<hostname>.local." to IPv4/IPv6 addresses
	service_record_->record_a = {
    .name = service_record_->hostname_qualified,
    .type = MDNS_RECORDTYPE_A,
    .data = {.a = {.addr = service_record_->address_ipv4}}
  };

	service_record_->record_aaaa = {
    .name = service_record_->hostname_qualified,
    .type = MDNS_RECORDTYPE_AAAA,
    .data = {.aaaa = {.addr = service_record_->address_ipv6}}
  };

  for (const auto &[key, val] : txt_records_) {
    mdns_record_t txt = {
      .name = service_record_->service_instance,
      .type = mdns_record_type::MDNS_RECORDTYPE_TXT,
      .data = { .txt = {
        .key = {.str = key.data(), .length = key.length()},
        .value = {.str = val.data(), .length = val.length()} } }};
    service_record_->txt_records.emplace_back(txt);
  }

  // This is a crude implementation that checks for incoming queries
  while (running_) {
    int nfds = 0;
    fd_set readfs{};
    FD_ZERO(&readfs);
    for (int isock = 0; isock < num_sockets; ++isock) {
      if (sockets[isock] >= nfds) nfds = sockets[isock] + 1;
      FD_SET(sockets[isock], &readfs);
    }

    if (select(nfds, &readfs, 0, 0, 0) >= 0) {
      for (int isock = 0; isock < num_sockets; ++isock) {
        if (FD_ISSET(sockets[isock], &readfs)) {
          mdns_socket_listen(sockets[isock], buffer.get(), capacity, service_callback, this);
        }
        FD_SET(sockets[isock], &readfs);
      }
    } else {
      break;
    }
  }

  for (int isock = 0; isock < num_sockets; ++isock) {
    mdns_socket_close(sockets[isock]);
  }
  MDNS_LOG << "Closed socket " << (num_sockets ? "s" : "");
}

std::list<std::shared_ptr<QueryResult>> mDNS::executeQuery(const std::string &service, mdns_record_type_t type, ProcessResultFn handle_result) {
  int sockets[32];
  int query_id[32];
  int num_sockets = openClientSockets(sockets, sizeof(sockets) / sizeof(sockets[0]), 0);

  if (num_sockets <= 0) {
    const auto msg = "Failed to open any client sockets";
    MDNS_LOG << msg;
    throw std::runtime_error(msg);
  }
  MDNS_LOG << "Opened " << num_sockets << " socket" << (num_sockets ? "s" : "") << " for mDNS query";

  size_t capacity = 2048;
  void *buffer = malloc(capacity);
  size_t records;

  MDNS_LOG << "Sending mDNS query: " << service << " [" << type << "]";
  for (int isock = 0; isock < num_sockets; ++isock) {
    query_id[isock] = mdns_query_send(sockets[isock], type, service.data(), strlen(service.data()), buffer, capacity, 0);
    if (query_id[isock] < 0) {
      MDNS_LOG << "Failed to send mDNS query: " << strerror(errno);
    }
  }

  // This is a simple implementation that loops for 5 seconds or as long as we
  // get replies
  std::list<std::shared_ptr<QueryResult>> results;
  int res{};
  MDNS_LOG << "Reading mDNS query replies";
  do {
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    int nfds = 0;
    fd_set readfs;
    FD_ZERO(&readfs);
    for (int isock = 0; isock < num_sockets; ++isock) {
      if (sockets[isock] >= nfds) nfds = sockets[isock] + 1;
      FD_SET(sockets[isock], &readfs);
    }

    records = 0;
    res = select(nfds, &readfs, 0, 0, &timeout);
    if (res > 0) {
      for (int isock = 0; isock < num_sockets; ++isock) {
        if (FD_ISSET(sockets[isock], &readfs)) {
          std::shared_ptr<QueryResult> query_result = std::make_shared<QueryResult>();
          records += mdns_query_recv(sockets[isock], buffer, capacity, query_callback, query_result.get(), query_id[isock]);
          results.push_back(query_result);
          handle_result(query_result);
        }
        FD_SET(sockets[isock], &readfs);
      }
    }
  } while (res > 0);

  MDNS_LOG << "Read [" << records << "] records";

  free(buffer);

  for (int isock = 0; isock < num_sockets; ++isock) {
    mdns_socket_close(sockets[isock]);
  }
  MDNS_LOG << "Closed socket" << (num_sockets ? "s" : "");

  return results;
}

void mDNS::executeDiscovery(ProcessResultFn handle_result) {
  int sockets[32];
  int num_sockets = openClientSockets(sockets, sizeof(sockets) / sizeof(sockets[0]), 0);
  if (num_sockets <= 0) {
    const auto msg = "Failed to open any client sockets";
    MDNS_LOG << msg;
    throw std::runtime_error(msg);
  }

  MDNS_LOG << "Opened " << num_sockets << " socket" << (num_sockets ? "s" : "") << " for DNS-SD";
  MDNS_LOG << "Sending DNS-SD discovery";
  for (int isock = 0; isock < num_sockets; ++isock) {
    if (mdns_discovery_send(sockets[isock])) {
      MDNS_LOG << "Failed to send DNS-DS discovery: " << strerror(errno);
    }
  }

  size_t capacity = 2048;
  void *buffer = malloc(capacity);
  size_t records;

  // This is a simple implementation that loops for 5 seconds or as long as we
  // get replies
  int res;
  MDNS_LOG << "Reading DNS-SD replies";
  do {
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    int nfds = 0;
    fd_set readfs;
    FD_ZERO(&readfs);
    for (int isock = 0; isock < num_sockets; ++isock) {
      if (sockets[isock] >= nfds) nfds = sockets[isock] + 1;
      FD_SET(sockets[isock], &readfs);
    }

    records = 0;
    res = select(nfds, &readfs, 0, 0, &timeout);
    if (res > 0) {
      for (int isock = 0; isock < num_sockets; ++isock) {
        if (FD_ISSET(sockets[isock], &readfs)) {
          std::shared_ptr<QueryResult> query_result = std::make_shared<QueryResult>();
          records += mdns_discovery_recv(sockets[isock], buffer, capacity, query_callback, query_result.get());
          handle_result(query_result);
        }
      }
    }
  } while (res > 0);

  MDNS_LOG << "Read [" << records << "] records";

  free(buffer);

  for (int isock = 0; isock < num_sockets; ++isock) {
    mdns_socket_close(sockets[isock]);
  }
  MDNS_LOG << "Closed socket" << (num_sockets ? "s" : "");
}

mdns_record_t mDNS::currentSRV() {
  auto base = service_record_->record_srv;

  std::srand(std::time(nullptr));
  base.data.srv.priority = getSRVPriority_();
  base.data.srv.weight = getSRVWeight_();

  MDNS_LOG << "🌈 Sending SRV " << base.data.srv.priority << " " << base.data.srv.weight;

  return base;
}

}  // namespace mdns_cpp
