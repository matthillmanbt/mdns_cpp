#include <signal.h>
#include <stdlib.h>

#include "mdns_cpp/defs.hpp"
#include <iostream>

#ifdef _WIN32
#include <winsock2.h>
#endif

#include "mdns_cpp/logger.hpp"
#include "mdns_cpp/mdns.hpp"

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

    mdns_cpp::Logger::setLoggerSink([](const std::string& log_msg) {
        std::cout << "❓ MDNS_QUERY: " << log_msg << std::endl;
        std::flush(std::cout);
    });

    mdns_cpp::mDNS mdns;
    // const std::string serviceHost = "jzp-mpam";
    const std::string service = "_jzp._mpam.local.";

    auto results = mdns.executeQuery(
        service, mdns_record_type::MDNS_RECORDTYPE_PTR, [](std::shared_ptr<mdns_cpp::QueryResult> result) {
            std::cout << "❓ MDNS_QUERY: result callback " << result.get() << std::endl;
            std::cout << "❓ MDNS_QUERY: SRV callback priority: " << result->srv.priority << std::endl;
        });

    for (const auto& result : results) {
        std::cout << "❓ MDNS_QUERY: got result from list " << result.get() << std::endl;
    }

    return 0;
}
