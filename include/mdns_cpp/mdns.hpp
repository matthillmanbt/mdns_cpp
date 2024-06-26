#ifndef MDNS_CPP_MDNS_H__
#define MDNS_CPP_MDNS_H__
#pragma once

#include <functional>
#include <list>
#include <map>
#include <string>
#include <thread>
#ifdef _WIN32
#include <Winsock2.h>
#include <Ws2tcpip.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include "defs.hpp"

struct sockaddr;

namespace mdns_cpp {

class mDNS {
public:
    mDNS(const std::string &serviceName, std::uint16_t port);
    mDNS() = default;
    ~mDNS();

    void startService();
    void stopService();
    bool isServiceRunning() const;

    void setServiceHostname(const std::string &hostname);
    void setServicePort(std::uint16_t port);
    void setServiceName(const std::string &name);
    void setServiceTxtRecords(const std::map<std::string, std::string> &text_records);

    void setSRVPriorityCallback(std::function<std::uint16_t()> cb);
    void setSRVWeightCallback(std::function<std::uint16_t()> cb);

    const ServiceRecord *serviceRecord() const;
    mdns_record_t currentSRV();

    std::list<QueryResult> executeQuery(const std::string &service, mdns_record_type_t type, ProcessResultFn handle_result, long timeout_seconds = 5);
    void executeDiscovery(ProcessResultFn handle_result);

private:
    void runMainServiceLoop();
    int openClientSockets(int *sockets, int max_sockets, int port);
    int openServiceSockets(int *sockets, int max_sockets);
    void initServiceRecord();

    std::unique_ptr<ServiceRecord> service_record_ {};

    std::function<std::uint16_t()> getSRVPriority_ = [] { return 0; };
    std::function<std::uint16_t()> getSRVWeight_ = [] { return 0; };

    std::string hostname_ { "dummy-host" };
    std::string name_ { "_http._tcp.local." };
    std::uint16_t port_ { 42424 };
    std::map<std::string, std::string> txt_records_ {};

    bool running_ { false };

    bool has_ipv4_ { false };
    bool has_ipv6_ { false };

    struct sockaddr_in service_address_ipv4_ { };
    struct sockaddr_in6 service_address_ipv6_ { };

    std::thread worker_thread_;
};

} // namespace mdns_cpp

#endif // MDNS_CPP_MDNS_H__