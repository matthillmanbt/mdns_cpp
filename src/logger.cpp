#include "mdns_cpp/logger.hpp"
#include "mdns_cpp/defs.hpp"

namespace mdns_cpp {

bool Logger::logger_registered = false;

std::function<void(const std::string &)> Logger::logging_callback_function;

void Logger::LogIt(const std::string &s)
{
    if (logger_registered) {
        logging_callback_function(s);
    } else {
        std::cout << s << std::endl;
    }
}

void Logger::setLoggerSink(std::function<void(const std::string &)> callback)
{
    logger_registered = true;
    logging_callback_function = callback;
}

void Logger::useDefaultSink() { logger_registered = false; }

LogMessage::LogMessage(const char *file, int line) { os << "[" << file << ":" << line << "] "; }

LogMessage::LogMessage() { os << ""; }

LogMessage::~LogMessage() { Logger::LogIt(os.str()); }

} // namespace mdns_cpp

std::ostream &operator<<(std::ostream &out, const mdns_string_t &s)
{
    out << std::string(s.str, s.length);

    return out;
}

std::ostream &operator<<(std::ostream &out, const mdns_record_srv_t &srv)
{
    out << "[SRV " << srv.name.str << " "
        << "priority " << srv.priority << " "
        << "weight " << srv.weight << " "
        << "port " << srv.port
        << "]";

    return out;
}

std::ostream &operator<<(std::ostream &out, const mdns_record_txt_t &txt)
{
    if (txt.value.length) {
        out << "[TXT kv: " << txt.key << " = " << txt.value << "]";
    } else {
        out << "[TXT " << txt.key << "]";
    }

    return out;
}

std::ostream &operator<<(std::ostream &out, mdns_cpp::QueryResult r)
{
    out << "[host: " << r.host << "]"
        << "[v4: " << r.ipv4 << "]"
        << "[v6: " << r.ipv6 << "]"
        << "[srv: " << r.srv << "]";

    for (auto &txt : r.txt) {
        out << "[txt: " << txt << "]";
    }

    return out;
}