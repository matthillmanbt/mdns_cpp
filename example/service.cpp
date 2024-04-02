#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include <iostream>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#endif

#include "mdns_cpp/logger.hpp"
#include "mdns_cpp/mdns.hpp"

void onInterruptHandler(int s) {
  std::cout << "Caught signal: " << s << std::endl;
  exit(0);
}

int main() {
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

  mdns_cpp::Logger::setLoggerSink([](const std::string& log_msg) {
    std::cout << "🧑‍✈️ MDNS_SERVICE: " << log_msg << std::endl;
    std::flush(std::cout);
  });

  mdns_cpp::mDNS mdns;

  mdns.setServiceName("_jzp._mpam.local.");
  mdns.setServiceHostname("jzp-mpam");
  mdns.setServiceTxtRecords({
    {"TXT_KEY", "TXT_VALUE"},
  });

  std::srand(std::time(nullptr));
  mdns.setSRVPriorityCallback([]() {
    return static_cast<uint16_t>(std::rand());
  });
  mdns.setSRVWeightCallback([]() {
    return static_cast<uint16_t>(std::rand());
  });

  mdns.startService();

  while (mdns.isServiceRunning()) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }

  return 0;
}
