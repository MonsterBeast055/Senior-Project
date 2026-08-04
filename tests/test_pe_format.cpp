#include "test_harness.h"

#include "sp/loader/PeFormat.h"

#include <cstdint>
#include <vector>

using namespace sp::loader;

namespace {

// Minimal DOS header whose e_lfanew points at a "PE\0\0" signature.
std::vector<std::uint8_t> make_pe_header(std::uint32_t e_lfanew = 0x80)
{
    std::vector<std::uint8_t> bytes(e_lfanew + 4, 0);
    bytes[0] = 'M';
    bytes[1] = 'Z';
    bytes[0x3C] = static_cast<std::uint8_t>(e_lfanew & 0xFF);
    bytes[0x3D] = static_cast<std::uint8_t>((e_lfanew >> 8) & 0xFF);
    bytes[0x3E] = static_cast<std::uint8_t>((e_lfanew >> 16) & 0xFF);
    bytes[0x3F] = static_cast<std::uint8_t>((e_lfanew >> 24) & 0xFF);
    bytes[e_lfanew + 0] = 'P';
    bytes[e_lfanew + 1] = 'E';
    bytes[e_lfanew + 2] = 0;
    bytes[e_lfanew + 3] = 0;
    return bytes;
}

void push_u32(std::vector<std::uint8_t>& out, std::uint32_t value)
{
    out.push_back(static_cast<std::uint8_t>(value & 0xFF));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFF));
}

void push_runtime_function(std::vector<std::uint8_t>& out,
                           std::uint32_t begin,
                           std::uint32_t end,
                           std::uint32_t unwind)
{
    push_u32(out, begin);
    push_u32(out, end);
    push_u32(out, unwind);
}

} // namespace

void test_pe_format()
{
    SP_TEST("pe format: little-endian readers");
    {
        const std::uint8_t bytes[8] = { 0x78, 0x56, 0x34, 0x12, 0xEF, 0xCD, 0xAB, 0x89 };
        SP_CHECK_EQ(read_u16le(bytes), std::uint16_t{ 0x5678 });
        SP_CHECK_EQ(read_u32le(bytes), std::uint32_t{ 0x12345678 });
        SP_CHECK_EQ(read_u64le(bytes), std::uint64_t{ 0x89ABCDEF12345678ull });
    }

    SP_TEST("pe format: signature detection accepts a valid header");
    {
        const auto bytes = make_pe_header();
        SP_CHECK(has_pe_signature(bytes.data(), bytes.size()));
    }

    SP_TEST("pe format: signature detection rejects malformed input");
    {
        SP_CHECK(!has_pe_signature(nullptr, 0));

        // Too short to hold e_lfanew.
        const std::uint8_t stub[4] = { 'M', 'Z', 0, 0 };
        SP_CHECK(!has_pe_signature(stub, sizeof(stub)));

        // Missing MZ.
        auto no_mz = make_pe_header();
        no_mz[0] = 'X';
        SP_CHECK(!has_pe_signature(no_mz.data(), no_mz.size()));

        // Wrong signature at e_lfanew.
        auto bad_sig = make_pe_header();
        bad_sig[0x80] = 'N';
        SP_CHECK(!has_pe_signature(bad_sig.data(), bad_sig.size()));

        // e_lfanew pointing past the end of the file must not read out of
        // bounds - a corrupt header should be rejected, not crash.
        auto out_of_range = make_pe_header();
        out_of_range[0x3C] = 0xFF;
        out_of_range[0x3D] = 0xFF;
        SP_CHECK(!has_pe_signature(out_of_range.data(), out_of_range.size()));
    }

    SP_TEST("pe format: unwind table yields function starts");
    {
        std::vector<std::uint8_t> table;
        push_runtime_function(table, 0x1000, 0x1050, 0x5000);
        push_runtime_function(table, 0x1050, 0x10C0, 0x5010);
        push_runtime_function(table, 0x10C0, 0x1120, 0x5020);

        const auto functions = parse_unwind_table(table.data(), table.size());
        SP_CHECK_EQ(functions.size(), std::size_t{ 3 });
        if (functions.size() == 3) {
            SP_CHECK_EQ(functions[0].begin_rva, sp::core::RVA{ 0x1000 });
            SP_CHECK_EQ(functions[0].end_rva, sp::core::RVA{ 0x1050 });
            SP_CHECK_EQ(functions[2].begin_rva, sp::core::RVA{ 0x10C0 });
        }
    }

    SP_TEST("pe format: unwind table stops at the zero terminator");
    {
        std::vector<std::uint8_t> table;
        push_runtime_function(table, 0x1000, 0x1050, 0x5000);
        push_runtime_function(table, 0, 0, 0);
        push_runtime_function(table, 0x2000, 0x2100, 0x6000);

        // Padding after the terminator must not be read as real entries.
        const auto functions = parse_unwind_table(table.data(), table.size());
        SP_CHECK_EQ(functions.size(), std::size_t{ 1 });
    }

    SP_TEST("pe format: unwind table skips implausible entries");
    {
        std::vector<std::uint8_t> table;
        push_runtime_function(table, 0x1000, 0x1050, 0x5000);
        // end <= begin is impossible for a real function.
        push_runtime_function(table, 0x2000, 0x1FF0, 0x6000);
        push_runtime_function(table, 0x3000, 0x3080, 0x7000);

        // These carry Certain confidence downstream, so a corrupt entry must be
        // dropped rather than trusted.
        const auto functions = parse_unwind_table(table.data(), table.size());
        SP_CHECK_EQ(functions.size(), std::size_t{ 2 });
        if (functions.size() == 2) {
            SP_CHECK_EQ(functions[1].begin_rva, sp::core::RVA{ 0x3000 });
        }
    }

    SP_TEST("pe format: unwind table tolerates truncation");
    {
        std::vector<std::uint8_t> table;
        push_runtime_function(table, 0x1000, 0x1050, 0x5000);
        // A trailing partial entry must be ignored, not read past the buffer.
        push_u32(table, 0x2000);
        push_u32(table, 0x2100);

        const auto functions = parse_unwind_table(table.data(), table.size());
        SP_CHECK_EQ(functions.size(), std::size_t{ 1 });

        SP_CHECK(parse_unwind_table(nullptr, 0).empty());
        SP_CHECK(parse_unwind_table(table.data(), 4).empty());
    }
}
