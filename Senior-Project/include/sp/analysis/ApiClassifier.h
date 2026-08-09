#pragma once
//
// ApiClassifier.h - Naming and meaning for imported APIs.
//
// Two jobs, both small but load-bearing.
//
// 1. Normalisation. Imports arrive as "api-ms-win-core-registry-l1-1-0.dll!
//    RegCreateKeyExW". The library half is noise in a prompt and makes name
//    matching impossible, so we strip it.
//
// 2. Classification. Which APIs read untrusted input, which are risky
//    operations, and what functional area each belongs to. This is what turns a
//    list of names into an argument about whether a finding matters.
//
// A useful accident of Windows API sets: the set name literally encodes the
// functional area (-registry-, -file-, -synch-, -com-), so a category comes free
// for a large fraction of imports.
//
#include <cstdint>
#include <string>
#include <vector>

namespace sp::analysis {

// Functional area of an API. Mostly derived from the API-set name, with a
// lookup table for classic DLLs that carry no such hint.
enum class ApiCategory : std::uint8_t {
    Unknown = 0,
    File,
    Registry,
    Network,
    Process,
    Thread,
    Memory,
    Crypto,
    Com,
    Ui,
    Debug,
    Synchronization,
    Environment,
    String,
    Time,
};

const char* to_string(ApiCategory c);

// Where untrusted data can enter the program.
//
// This is the half of reachability analysis that decides whether a risky
// operation is actually exposed. A `strcpy` nothing untrusted reaches is noise;
// the same `strcpy` downstream of `recv` is a finding.
enum class InputSource : std::uint8_t {
    None = 0,
    Network,        // recv, WinHttpReadData, InternetReadFile
    File,           // ReadFile, fread, MapViewOfFile
    CommandLine,    // GetCommandLineW
    Registry,       // RegQueryValueExW
    Environment,    // GetEnvironmentVariableW
    Ipc,            // named pipes, mailslots
    ProcessMemory,  // ReadProcessMemory
    UserInput,      // GetWindowTextW, clipboard
};

const char* to_string(InputSource s);

// Operations where untrusted input causes real trouble.
enum class SinkKind : std::uint8_t {
    None = 0,
    UnboundedCopy,   // strcpy, strcat, gets - no length argument at all
    BoundedCopy,     // memcpy, strncpy - safe only if the length is right
    FormatString,    // sprintf, printf family
    ProcessLaunch,   // CreateProcessW, WinExec, system
    LibraryLoad,     // LoadLibraryW, GetProcAddress
    MemoryProtect,   // VirtualProtect, VirtualAllocEx - shellcode staging
    RemoteWrite,     // WriteProcessMemory, CreateRemoteThread
    RegistryWrite,   // RegSetValueExW
    FileWrite,       // WriteFile, DeleteFileW
    WeakCrypto,      // MD5, SHA1, DES, RC4
};

const char* to_string(SinkKind k);

// Severity a sink carries before reachability is considered.
enum class SinkSeverity : std::uint8_t {
    Informational = 0,
    Low,
    Medium,
    High,
};

const char* to_string(SinkSeverity s);

SinkSeverity base_severity(SinkKind kind);

class ApiClassifier {
public:
    // "api-ms-win-core-registry-l1-1-0.dll!RegCreateKeyExW" -> "RegCreateKeyExW"
    // "KERNEL32.dll!CreateFileW" -> "CreateFileW"
    // "CreateFileW" -> "CreateFileW"
    static std::string bare_name(const std::string& qualified);

    // Library half of a qualified name, or empty.
    static std::string library_of(const std::string& qualified);

    // Functional area, from the API-set name where available and a table of
    // classic DLL names otherwise.
    static ApiCategory categorize(const std::string& qualified);

    // Does this API read data the program did not produce itself?
    static InputSource input_source_of(const std::string& qualified);

    // Is this a risky operation, and of what kind?
    static SinkKind sink_of(const std::string& qualified);

    // True for APIs that are interesting on their own regardless of
    // reachability - process injection, persistence, anti-debug.
    static bool is_notable_behavior(const std::string& qualified);
};

} // namespace sp::analysis
