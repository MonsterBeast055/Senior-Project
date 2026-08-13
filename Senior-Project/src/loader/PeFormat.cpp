#include "sp/loader/PeFormat.h"

#include <fstream>

namespace sp::loader {
namespace {

// Offset of e_lfanew within the DOS header.
constexpr std::size_t kELfanewOffset = 0x3C;

// Smallest file that could possibly carry a PE signature.
constexpr std::size_t kMinPeSize = kELfanewOffset + 4 + 4;

} // namespace

std::uint16_t read_u16le(const std::uint8_t* p)
{
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(p[0])
                                      | (static_cast<std::uint16_t>(p[1]) << 8));
}

std::uint32_t read_u32le(const std::uint8_t* p)
{
    return static_cast<std::uint32_t>(p[0])
         | (static_cast<std::uint32_t>(p[1]) << 8)
         | (static_cast<std::uint32_t>(p[2]) << 16)
         | (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint64_t read_u64le(const std::uint8_t* p)
{
    return static_cast<std::uint64_t>(read_u32le(p))
         | (static_cast<std::uint64_t>(read_u32le(p + 4)) << 32);
}

void write_u16le(std::uint8_t* p, std::uint16_t value)
{
    p[0] = static_cast<std::uint8_t>(value & 0xFF);
    p[1] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
}

void write_u32le(std::uint8_t* p, std::uint32_t value)
{
    p[0] = static_cast<std::uint8_t>(value & 0xFF);
    p[1] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
    p[2] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
    p[3] = static_cast<std::uint8_t>((value >> 24) & 0xFF);
}

std::vector<RuntimeFunction> parse_unwind_table(const std::uint8_t* data, std::size_t size)
{
    std::vector<RuntimeFunction> functions;
    if (data == nullptr || size < kRuntimeFunctionSize) {
        return functions;
    }

    const std::size_t count = size / kRuntimeFunctionSize;
    functions.reserve(count);

    for (std::size_t i = 0; i < count; ++i) {
        const std::uint8_t* entry = data + (i * kRuntimeFunctionSize);

        RuntimeFunction function;
        function.begin_rva = read_u32le(entry);
        function.end_rva = read_u32le(entry + 4);
        function.unwind_info_rva = read_u32le(entry + 8);

        // A run of zeroes is the normal terminator for a padded directory.
        if (function.begin_rva == 0 && function.end_rva == 0) {
            break;
        }

        // Skip rather than trust. These entries are handed downstream with
        // Certain confidence, so a corrupt one does real damage.
        if (!function.plausible()) {
            continue;
        }

        functions.push_back(function);
    }
    return functions;
}

bool has_pe_signature(const std::uint8_t* bytes, std::size_t size)
{
    if (bytes == nullptr || size < kMinPeSize) {
        return false;
    }
    if (bytes[0] != 'M' || bytes[1] != 'Z') {
        return false;
    }

    const std::uint32_t e_lfanew = read_u32le(bytes + kELfanewOffset);

    // Guard against a header pointing outside the file, which is both a
    // corruption signal and an out-of-bounds read waiting to happen.
    if (e_lfanew > size || size - e_lfanew < 4) {
        return false;
    }

    const std::uint8_t* pe = bytes + e_lfanew;
    return pe[0] == 'P' && pe[1] == 'E' && pe[2] == 0 && pe[3] == 0;
}

bool read_file(const std::string& path, std::vector<std::uint8_t>& out)
{
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) {
        return false;
    }

    const std::streamoff size = stream.tellg();
    if (size < 0) {
        return false;
    }
    stream.seekg(0, std::ios::beg);

    out.resize(static_cast<std::size_t>(size));
    if (size > 0) {
        stream.read(reinterpret_cast<char*>(out.data()), size);
        if (!stream) {
            return false;
        }
    }
    return true;
}

} // namespace sp::loader
