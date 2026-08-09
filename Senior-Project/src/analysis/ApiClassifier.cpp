#include "sp/analysis/ApiClassifier.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <unordered_map>

namespace sp::analysis {
namespace {

std::string lowercase(const std::string& text)
{
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

// Trailing A/W variants are the same API for our purposes.
std::string strip_charset_suffix(const std::string& name)
{
    if (name.size() > 1) {
        const char last = name.back();
        if (last == 'A' || last == 'W') {
            return name.substr(0, name.size() - 1);
        }
    }
    return name;
}

// --- Input sources -------------------------------------------------------
const std::unordered_map<std::string, InputSource>& source_table()
{
    static const std::unordered_map<std::string, InputSource> table = {
        // Network
        { "recv", InputSource::Network },
        { "recvfrom", InputSource::Network },
        { "WSARecv", InputSource::Network },
        { "InternetReadFile", InputSource::Network },
        { "WinHttpReadData", InputSource::Network },
        { "HttpQueryInfo", InputSource::Network },
        { "URLDownloadToFile", InputSource::Network },

        // File
        { "ReadFile", InputSource::File },
        { "ReadFileEx", InputSource::File },
        { "fread", InputSource::File },
        { "fgets", InputSource::File },
        { "MapViewOfFile", InputSource::File },
        { "GetPrivateProfileString", InputSource::File },

        // Command line and environment
        { "GetCommandLine", InputSource::CommandLine },
        { "CommandLineToArgv", InputSource::CommandLine },
        { "GetEnvironmentVariable", InputSource::Environment },
        { "GetEnvironmentStrings", InputSource::Environment },
        { "getenv", InputSource::Environment },

        // Registry
        { "RegQueryValueEx", InputSource::Registry },
        { "RegGetValue", InputSource::Registry },
        { "RegEnumValue", InputSource::Registry },

        // IPC
        { "ConnectNamedPipe", InputSource::Ipc },
        { "ReadFileScatter", InputSource::Ipc },
        { "CallNamedPipe", InputSource::Ipc },

        // Another process's memory
        { "ReadProcessMemory", InputSource::ProcessMemory },

        // Direct user input
        { "GetWindowText", InputSource::UserInput },
        { "GetDlgItemText", InputSource::UserInput },
        { "GetClipboardData", InputSource::UserInput },
        { "DragQueryFile", InputSource::UserInput },
    };
    return table;
}

// --- Risky sinks ---------------------------------------------------------
const std::unordered_map<std::string, SinkKind>& sink_table()
{
    static const std::unordered_map<std::string, SinkKind> table = {
        // No length argument exists, so there is no safe way to call these.
        { "strcpy", SinkKind::UnboundedCopy },
        { "strcat", SinkKind::UnboundedCopy },
        { "wcscpy", SinkKind::UnboundedCopy },
        { "wcscat", SinkKind::UnboundedCopy },
        { "lstrcpy", SinkKind::UnboundedCopy },
        { "lstrcat", SinkKind::UnboundedCopy },
        { "gets", SinkKind::UnboundedCopy },
        { "StrCpy", SinkKind::UnboundedCopy },

        // Safe only if the caller computed the length correctly.
        { "memcpy", SinkKind::BoundedCopy },
        { "memmove", SinkKind::BoundedCopy },
        { "strncpy", SinkKind::BoundedCopy },
        { "wcsncpy", SinkKind::BoundedCopy },
        { "CopyMemory", SinkKind::BoundedCopy },
        { "RtlCopyMemory", SinkKind::BoundedCopy },

        { "sprintf", SinkKind::FormatString },
        { "vsprintf", SinkKind::FormatString },
        { "swprintf", SinkKind::FormatString },
        { "wsprintf", SinkKind::FormatString },
        { "_snprintf", SinkKind::FormatString },
        { "__stdio_common_vswprintf", SinkKind::FormatString },
        { "FormatMessage", SinkKind::FormatString },

        { "CreateProcess", SinkKind::ProcessLaunch },
        { "ShellExecute", SinkKind::ProcessLaunch },
        { "ShellExecuteEx", SinkKind::ProcessLaunch },
        { "WinExec", SinkKind::ProcessLaunch },
        { "system", SinkKind::ProcessLaunch },
        { "_wsystem", SinkKind::ProcessLaunch },

        { "LoadLibrary", SinkKind::LibraryLoad },
        { "LoadLibraryEx", SinkKind::LibraryLoad },
        { "GetProcAddress", SinkKind::LibraryLoad },
        { "LdrLoadDll", SinkKind::LibraryLoad },

        { "VirtualProtect", SinkKind::MemoryProtect },
        { "VirtualProtectEx", SinkKind::MemoryProtect },
        { "VirtualAllocEx", SinkKind::MemoryProtect },
        { "NtProtectVirtualMemory", SinkKind::MemoryProtect },

        { "WriteProcessMemory", SinkKind::RemoteWrite },
        { "CreateRemoteThread", SinkKind::RemoteWrite },
        { "NtCreateThreadEx", SinkKind::RemoteWrite },
        { "QueueUserAPC", SinkKind::RemoteWrite },
        { "SetThreadContext", SinkKind::RemoteWrite },

        { "RegSetValueEx", SinkKind::RegistryWrite },
        { "RegSetKeyValue", SinkKind::RegistryWrite },
        { "RegCreateKeyEx", SinkKind::RegistryWrite },

        { "WriteFile", SinkKind::FileWrite },
        { "DeleteFile", SinkKind::FileWrite },
        { "MoveFileEx", SinkKind::FileWrite },
        { "CopyFile", SinkKind::FileWrite },

        { "MD5Init", SinkKind::WeakCrypto },
        { "MD4Init", SinkKind::WeakCrypto },
        { "A_SHAInit", SinkKind::WeakCrypto },
        { "CryptCreateHash", SinkKind::WeakCrypto },
    };
    return table;
}

// APIs interesting on their own, independent of reachability. These are the
// behaviour patterns a malware report cares about.
const std::unordered_map<std::string, bool>& notable_table()
{
    static const std::unordered_map<std::string, bool> table = {
        // Process injection
        { "VirtualAllocEx", true },
        { "WriteProcessMemory", true },
        { "CreateRemoteThread", true },
        { "NtCreateThreadEx", true },
        { "QueueUserAPC", true },
        { "SetWindowsHookEx", true },
        { "NtUnmapViewOfSection", true },

        // Anti-debug and anti-analysis
        { "IsDebuggerPresent", true },
        { "CheckRemoteDebuggerPresent", true },
        { "NtQueryInformationProcess", true },
        { "OutputDebugString", true },

        // Privilege and token manipulation
        { "AdjustTokenPrivileges", true },
        { "OpenProcessToken", true },
        { "ImpersonateLoggedOnUser", true },
        { "LogonUser", true },

        // Discovery
        { "CreateToolhelp32Snapshot", true },
        { "Process32First", true },
        { "EnumProcesses", true },
        { "GetAdaptersInfo", true },

        // Persistence
        { "RegSetValueEx", true },
        { "CreateService", true },
        { "SetServiceStatus", true },

        // Credential access
        { "CryptUnprotectData", true },
    };
    return table;
}

// Category from the API-set name, which encodes the functional area directly.
ApiCategory category_from_api_set(const std::string& library_lower)
{
    struct Entry { const char* fragment; ApiCategory category; };
    static const Entry entries[] = {
        { "-registry-",  ApiCategory::Registry },
        { "-file-",      ApiCategory::File },
        { "-memory-",    ApiCategory::Memory },
        { "-heap-",      ApiCategory::Memory },
        { "-synch-",     ApiCategory::Synchronization },
        { "-interlocked-", ApiCategory::Synchronization },
        { "-processthreads-", ApiCategory::Process },
        { "-processenvironment-", ApiCategory::Environment },
        { "-threadpool-", ApiCategory::Thread },
        { "-com-",       ApiCategory::Com },
        { "-winrt-",     ApiCategory::Com },
        { "-crypt",      ApiCategory::Crypto },
        { "-debug-",     ApiCategory::Debug },
        { "-string-",    ApiCategory::String },
        { "-datetime-",  ApiCategory::Time },
        { "-sysinfo-",   ApiCategory::Time },
        { "-winsock",    ApiCategory::Network },
        { "-http",       ApiCategory::Network },
    };

    for (const Entry& entry : entries) {
        if (library_lower.find(entry.fragment) != std::string::npos) {
            return entry.category;
        }
    }
    return ApiCategory::Unknown;
}

// Classic DLLs carry no functional hint in their name, so they need a table.
ApiCategory category_from_dll(const std::string& library_lower)
{
    static const std::unordered_map<std::string, ApiCategory> table = {
        { "user32.dll",   ApiCategory::Ui },
        { "gdi32.dll",    ApiCategory::Ui },
        { "comctl32.dll", ApiCategory::Ui },
        { "comdlg32.dll", ApiCategory::Ui },
        { "shell32.dll",  ApiCategory::File },
        { "shlwapi.dll",  ApiCategory::File },
        { "advapi32.dll", ApiCategory::Registry },
        { "ws2_32.dll",   ApiCategory::Network },
        { "wininet.dll",  ApiCategory::Network },
        { "winhttp.dll",  ApiCategory::Network },
        { "urlmon.dll",   ApiCategory::Network },
        { "crypt32.dll",  ApiCategory::Crypto },
        { "bcrypt.dll",   ApiCategory::Crypto },
        { "ole32.dll",    ApiCategory::Com },
        { "oleaut32.dll", ApiCategory::Com },
        { "ntdll.dll",    ApiCategory::Process },
        { "psapi.dll",    ApiCategory::Process },
    };
    auto it = table.find(library_lower);
    return it == table.end() ? ApiCategory::Unknown : it->second;
}

} // namespace

const char* to_string(ApiCategory c)
{
    switch (c) {
    case ApiCategory::File:            return "file";
    case ApiCategory::Registry:        return "registry";
    case ApiCategory::Network:         return "network";
    case ApiCategory::Process:         return "process";
    case ApiCategory::Thread:          return "thread";
    case ApiCategory::Memory:          return "memory";
    case ApiCategory::Crypto:          return "crypto";
    case ApiCategory::Com:             return "com";
    case ApiCategory::Ui:              return "ui";
    case ApiCategory::Debug:           return "debug";
    case ApiCategory::Synchronization: return "synchronization";
    case ApiCategory::Environment:     return "environment";
    case ApiCategory::String:          return "string";
    case ApiCategory::Time:            return "time";
    case ApiCategory::Unknown:
    default:                           return "unknown";
    }
}

const char* to_string(InputSource s)
{
    switch (s) {
    case InputSource::Network:       return "network";
    case InputSource::File:          return "file";
    case InputSource::CommandLine:   return "command-line";
    case InputSource::Registry:      return "registry";
    case InputSource::Environment:   return "environment";
    case InputSource::Ipc:           return "ipc";
    case InputSource::ProcessMemory: return "process-memory";
    case InputSource::UserInput:     return "user-input";
    case InputSource::None:
    default:                         return "none";
    }
}

const char* to_string(SinkKind k)
{
    switch (k) {
    case SinkKind::UnboundedCopy: return "unbounded-copy";
    case SinkKind::BoundedCopy:   return "bounded-copy";
    case SinkKind::FormatString:  return "format-string";
    case SinkKind::ProcessLaunch: return "process-launch";
    case SinkKind::LibraryLoad:   return "library-load";
    case SinkKind::MemoryProtect: return "memory-protect";
    case SinkKind::RemoteWrite:   return "remote-write";
    case SinkKind::RegistryWrite: return "registry-write";
    case SinkKind::FileWrite:     return "file-write";
    case SinkKind::WeakCrypto:    return "weak-crypto";
    case SinkKind::None:
    default:                      return "none";
    }
}

const char* to_string(SinkSeverity s)
{
    switch (s) {
    case SinkSeverity::High:   return "high";
    case SinkSeverity::Medium: return "medium";
    case SinkSeverity::Low:    return "low";
    case SinkSeverity::Informational:
    default:                   return "informational";
    }
}

SinkSeverity base_severity(SinkKind kind)
{
    switch (kind) {
    // No safe way to call these at all.
    case SinkKind::UnboundedCopy:
        return SinkSeverity::High;

    // Dangerous, but only in combination with attacker-controlled data.
    case SinkKind::FormatString:
    case SinkKind::RemoteWrite:
    case SinkKind::ProcessLaunch:
        return SinkSeverity::Medium;

    case SinkKind::BoundedCopy:
    case SinkKind::LibraryLoad:
    case SinkKind::MemoryProtect:
    case SinkKind::WeakCrypto:
        return SinkSeverity::Low;

    // Normal application behaviour on its own.
    case SinkKind::RegistryWrite:
    case SinkKind::FileWrite:
    case SinkKind::None:
    default:
        return SinkSeverity::Informational;
    }
}

std::string ApiClassifier::bare_name(const std::string& qualified)
{
    const std::size_t bang = qualified.rfind('!');
    if (bang == std::string::npos) {
        return qualified;
    }
    return qualified.substr(bang + 1);
}

std::string ApiClassifier::library_of(const std::string& qualified)
{
    const std::size_t bang = qualified.rfind('!');
    if (bang == std::string::npos) {
        return {};
    }
    return qualified.substr(0, bang);
}

ApiCategory ApiClassifier::categorize(const std::string& qualified)
{
    const std::string library = lowercase(library_of(qualified));
    if (library.empty()) {
        return ApiCategory::Unknown;
    }

    // API sets name their own category; classic DLLs need the table.
    if (library.rfind("api-ms-win", 0) == 0) {
        return category_from_api_set(library);
    }
    return category_from_dll(library);
}

InputSource ApiClassifier::input_source_of(const std::string& qualified)
{
    const std::string name = bare_name(qualified);
    const auto& table = source_table();

    auto it = table.find(name);
    if (it != table.end()) {
        return it->second;
    }
    // Try without the A/W charset suffix.
    it = table.find(strip_charset_suffix(name));
    if (it != table.end()) {
        return it->second;
    }
    return InputSource::None;
}

SinkKind ApiClassifier::sink_of(const std::string& qualified)
{
    const std::string name = bare_name(qualified);
    const auto& table = sink_table();

    auto it = table.find(name);
    if (it != table.end()) {
        return it->second;
    }
    it = table.find(strip_charset_suffix(name));
    if (it != table.end()) {
        return it->second;
    }

    // CRT names often carry decoration: _o_strcpy, __imp_strcpy, strcpy_s.
    // The _s variants are the *safe* versions, so they must not match.
    std::string trimmed = name;
    while (!trimmed.empty() && trimmed.front() == '_') {
        trimmed.erase(trimmed.begin());
    }
    if (trimmed.size() > 2 && trimmed.rfind("_s") == trimmed.size() - 2) {
        return SinkKind::None;
    }
    if (trimmed.rfind("o_", 0) == 0) {
        trimmed = trimmed.substr(2);
    }

    it = table.find(trimmed);
    if (it != table.end()) {
        return it->second;
    }
    it = table.find(strip_charset_suffix(trimmed));
    return it == table.end() ? SinkKind::None : it->second;
}

bool ApiClassifier::is_notable_behavior(const std::string& qualified)
{
    const std::string name = bare_name(qualified);
    const auto& table = notable_table();

    if (table.find(name) != table.end()) {
        return true;
    }
    return table.find(strip_charset_suffix(name)) != table.end();
}

} // namespace sp::analysis
