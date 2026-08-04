#pragma once
//
// PeFormat.h - LIEF-free PE structure helpers.
//
// Deliberately independent of LIEF. Two reasons:
//
//   1. LIEF's exception/unwind API has changed shape across releases, and the
//      .pdata table is a fixed, well-documented on-disk layout. Reading it
//      directly is version-proof.
//   2. Anything that takes raw bytes instead of a LIEF object can be unit
//      tested without a real executable on disk, which matters because .pdata
//      is our single most trusted source of function boundaries.
//
#include "sp/core/Types.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace sp::loader {

// One RUNTIME_FUNCTION entry from the x64 exception directory. Twelve bytes on
// disk: three little-endian uint32 RVAs.
struct RuntimeFunction {
    core::RVA begin_rva = 0;
    core::RVA end_rva = 0;
    core::RVA unwind_info_rva = 0;

    bool plausible() const
    {
        return begin_rva != 0 && end_rva > begin_rva;
    }
};

inline constexpr std::size_t kRuntimeFunctionSize = 12;

// Parse a RUNTIME_FUNCTION array. `data` points at the start of the exception
// directory contents, `size` is its byte length.
//
// Entries that fail `plausible()` are skipped rather than trusted: a malformed
// or deliberately corrupted .pdata should degrade our function list, not poison
// it with garbage boundaries carrying Certain confidence.
std::vector<RuntimeFunction> parse_unwind_table(const std::uint8_t* data, std::size_t size);

// True if `bytes` starts with a DOS header whose e_lfanew points at a valid
// "PE\0\0" signature. Cheap structural check, no full parse.
bool has_pe_signature(const std::uint8_t* bytes, std::size_t size);

// Read a whole file into memory. Returns false if it cannot be opened.
bool read_file(const std::string& path, std::vector<std::uint8_t>& out);

// --- Little-endian readers -------------------------------------------------
// Explicit rather than reinterpret_cast so the code is correct regardless of
// host endianness and alignment.

std::uint16_t read_u16le(const std::uint8_t* p);
std::uint32_t read_u32le(const std::uint8_t* p);
std::uint64_t read_u64le(const std::uint8_t* p);

} // namespace sp::loader
