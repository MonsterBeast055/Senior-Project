#include "sp/core/Log.h"

#include <iostream>

namespace sp::core {
namespace {

LogLevel g_min_level = LogLevel::Info;

LogSink& sink()
{
    static LogSink s = [](LogLevel level, const std::string& message) {
        std::cerr << "[" << to_string(level) << "] " << message << "\n";
    };
    return s;
}

} // namespace

const char* to_string(LogLevel l)
{
    switch (l) {
    case LogLevel::Trace: return "trace";
    case LogLevel::Debug: return "debug";
    case LogLevel::Info:  return "info";
    case LogLevel::Warn:  return "warn";
    case LogLevel::Error: return "error";
    default:              return "?";
    }
}

void set_log_sink(LogSink s)
{
    sink() = std::move(s);
}

void set_log_level(LogLevel min_level)
{
    g_min_level = min_level;
}

void log(LogLevel level, const std::string& message)
{
    if (level < g_min_level) {
        return;
    }
    if (sink()) {
        sink()(level, message);
    }
}

} // namespace sp::core
