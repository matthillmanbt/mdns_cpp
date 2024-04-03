#ifndef MDNS_CPP_LOGGER_H__
#define MDNS_CPP_LOGGER_H__
#pragma once

#include <functional>
#include <iostream>
#include <sstream>
#include <string>

#include "../../src/mdns.h"

#define MDNS_LOG_LN (LogMessage(__FILE__, __LINE__))
#define MDNS_LOG (LogMessage())

namespace mdns_cpp {
struct QueryResult;

class Logger {
public:
    static void LogIt(const std::string &s);
    static void setLoggerSink(std::function<void(const std::string &)> callback);
    static void useDefaultSink();

private:
    static bool logger_registered;
    static std::function<void(const std::string &)> logging_callback_function;
};

class LogMessage {
public:
    LogMessage(const char *file, int line);
    LogMessage();

    ~LogMessage();

    template <typename T>
    LogMessage &operator<<(const T &t)
    {
        os << t;
        return *this;
    }

private:
    std::ostringstream os;
};

} // namespace mdns_cpp

std::ostream &operator<<(std::ostream &out, const mdns_string_t &s);
std::ostream &operator<<(std::ostream &out, const mdns_record_srv_t &srv);
std::ostream &operator<<(std::ostream &out, const mdns_record_txt_t &txt);
std::ostream &operator<<(std::ostream &out, mdns_cpp::QueryResult r);

#endif // MDNS_CPP_LOGGER_H__