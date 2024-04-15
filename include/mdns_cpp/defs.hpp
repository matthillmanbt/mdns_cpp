#ifndef MDNS_CPP_DEFS_H__
#define MDNS_CPP_DEFS_H__
#pragma once

#include <cstdint>
#include <functional>
#include <vector>
#include <string>
#ifdef _WIN32
#include <Winsock2.h>
#include <Ws2tcpip.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include "../../src/mdns.h"

namespace mdns_cpp {

class ServiceRecord {
public:
    mdns_string_t service;
    mdns_string_t hostname;
    std::string service_instance;
    std::string hostname_qualified;

    struct sockaddr_in address_ipv4;
    struct sockaddr_in6 address_ipv6;
    uint16_t port;

    mdns_record_t record_ptr;
    mdns_record_t record_srv;
    mdns_record_t record_a;
    mdns_record_t record_aaaa;
    std::vector<mdns_record_t> txt_records;
};

struct QueryResult {
    std::string host;
    std::string ipv4;
    std::string ipv6;

    mdns_record_srv_t srv;
    std::vector<mdns_record_txt_t> txt;
};

typedef std::function<void(QueryResult &)> ProcessResultFn;

} // namespace mdns_cpp

#endif // MDNS_CPP_DEFS_H__