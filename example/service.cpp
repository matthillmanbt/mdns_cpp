#include <signal.h>
#include <stdlib.h>

#include <iostream>
#include <thread>

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
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);

    if (iResult != 0) {
        std::cout << "WSAStartup failed: " << iResult << "\n";
        return 1;
    }
#endif

    mdns_cpp::Logger::setLoggerSink([](const std::string &log_msg) {
        std::cout << "🧑‍✈️ MDNS_SERVICE: " << log_msg << std::endl;
        std::flush(std::cout);
    });

    mdns_cpp::mDNS mdns(SERVICE_HOST, SERVICE_NAME, 443);

    mdns.setServiceTxtRecords({
        { "TXT_KEY", "TXT_VALUE" },
    });

    std::srand(std::time(nullptr));
    auto randCB = [] { return static_cast<uint16_t>(std::rand()); };
    mdns.setSRVPriorityCallback(randCB);
    mdns.setSRVWeightCallback(randCB);

    mdns.startService();

    while (mdns.isServiceRunning()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}
