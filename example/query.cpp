#include "mdns_cpp/defs.hpp"
#include <iostream>
#include <signal.h>
#include <stdlib.h>

#ifdef _WIN32
#include <winsock2.h>
#endif

#include "consts.h"
#include "mdns_cpp/mdns_cpp.h"

void onInterruptHandler(int s)
{
    std::cout << "Caught signal: " << s << std::endl;
    exit(0);
}

int main()
{
    signal(SIGINT, onInterruptHandler);

#ifdef _WIN32
    WSADATA wsaData;
    // Initialize Winsock
    const int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);

    if (iResult != 0) {
        std::cout << "WSAStartup failed: " << iResult << "\n";
        return 1;
    }
#endif

    mdns_cpp::Logger::setLoggerSink([](const std::string &log_msg) {
        std::cout << "❓ MDNS_QUERY: " << log_msg << std::endl;
        std::flush(std::cout);
    });

    mdns_cpp::mDNS mdns;

    auto results = mdns.executeQuery(SERVICE_NAME, mdns_record_type::MDNS_RECORDTYPE_PTR,
        [](mdns_cpp::QueryResult result) {
            std::cout << "❓ MDNS_QUERY: result callback " << result << std::endl;
            std::cout << "❓ MDNS_QUERY: SRV callback priority: " << result.srv.priority << std::endl;
        });

    for (const auto &result : results) {
        std::cout << "❓ MDNS_QUERY: got result from list " << result << std::endl;
    }

    return 0;
}
