#pragma once
//
// Log.h - Minimal severity-based logging.
//
// Analysis passes report progress and anomalies here instead of writing to
// stdout, so that a GUI or JSON-emitting frontend can capture or silence them.
//
#include <functional>
#include <string>

namespace sp::core {

enum class LogLevel { Trace, Debug, Info, Warn, Error };

const char* to_string(LogLevel l);

using LogSink = std::function<void(LogLevel, const std::string&)>;

// Replace the global sink. Default sink writes to stderr.
void set_log_sink(LogSink sink);
void set_log_level(LogLevel min_level);

void log(LogLevel level, const std::string& message);

inline void log_debug(const std::string& m) { log(LogLevel::Debug, m); }
inline void log_info(const std::string& m)  { log(LogLevel::Info,  m); }
inline void log_warn(const std::string& m)  { log(LogLevel::Warn,  m); }
inline void log_error(const std::string& m) { log(LogLevel::Error, m); }

} // namespace sp::core
