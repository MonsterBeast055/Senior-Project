#include "test_harness.h"

#include "sp/harden/PeHardener.h"
#include "sp/loader/PeFormat.h"

#include <cstdint>
#include <vector>

using namespace sp;
using namespace sp::harden;
using loader::read_u16le;
using loader::read_u32le;
using loader::write_u16le;
using loader::write_u32le;

namespace {

/* A synthetic PE, built byte by byte.
 *
 * The whole reason PeHardener takes a byte buffer instead of a file path is so
 * this is possible: every precondition it refuses on - stripped relocations, a
 * missing reloc directory, a certificate, a 32-bit image - can be constructed
 * exactly, without needing four real executables checked into the repository
 * that happen to have those properties. */
struct PeSpec {
    bool pe32_plus = true;
    std::uint16_t dll_characteristics = 0;
    std::uint16_t coff_characteristics = 0;
    bool reloc_directory = false;
    bool certificate = false;
};

constexpr std::size_t kFileSize = 0x200;
constexpr std::size_t kPeAt = 0x80;
constexpr std::size_t kCoffAt = kPeAt + 4;      // 0x84
constexpr std::size_t kOptAt = kCoffAt + 20;    // 0x98

std::vector<std::uint8_t> build(const PeSpec& spec)
{
    std::vector<std::uint8_t> bytes(kFileSize, 0);

    bytes[0] = 'M';
    bytes[1] = 'Z';
    write_u32le(&bytes[0x3C], static_cast<std::uint32_t>(kPeAt));

    bytes[kPeAt + 0] = 'P';
    bytes[kPeAt + 1] = 'E';

    write_u16le(&bytes[kCoffAt + 0], spec.pe32_plus ? 0x8664 : 0x014C);
    write_u16le(&bytes[kCoffAt + 2], 1);
    // 0x70 or 0x60 of fixed fields, plus 16 directory entries of 8 bytes.
    const std::uint16_t optional_size = spec.pe32_plus ? 0x00F0 : 0x00E0;
    write_u16le(&bytes[kCoffAt + 16], optional_size);
    write_u16le(&bytes[kCoffAt + 18], spec.coff_characteristics);

    write_u16le(&bytes[kOptAt], spec.pe32_plus ? 0x020B : 0x010B);
    write_u16le(&bytes[kOptAt + 0x46], spec.dll_characteristics);

    const std::size_t count_offset = spec.pe32_plus ? 0x6C : 0x5C;
    const std::size_t dir_offset = spec.pe32_plus ? 0x70 : 0x60;
    write_u32le(&bytes[kOptAt + count_offset], 16);

    if (spec.reloc_directory) {
        write_u32le(&bytes[kOptAt + dir_offset + (5 * 8)], 0x5000);
        write_u32le(&bytes[kOptAt + dir_offset + (5 * 8) + 4], 0x100);
    }
    if (spec.certificate) {
        write_u32le(&bytes[kOptAt + dir_offset + (4 * 8)], 0x1800);
        write_u32le(&bytes[kOptAt + dir_offset + (4 * 8) + 4], 0x200);
    }

    return bytes;
}

std::uint16_t dll_flags(const std::vector<std::uint8_t>& bytes)
{
    return read_u16le(&bytes[kOptAt + 0x46]);
}

} // namespace

void test_pe_hardener()
{
    SP_TEST("inspect rejects a file with no MZ signature");
    {
        std::vector<std::uint8_t> bytes(kFileSize, 0);
        const MitigationReport report = inspect(bytes);
        SP_CHECK(!report.parsed);
        SP_CHECK(!report.problem.empty());
    }

    SP_TEST("inspect rejects e_lfanew pointing outside the file");
    {
        std::vector<std::uint8_t> bytes = build({});
        write_u32le(&bytes[0x3C], 0x00FF0000);
        const MitigationReport report = inspect(bytes);
        SP_CHECK(!report.parsed);
    }

    SP_TEST("inspect reads the mitigation bits it is given");
    {
        PeSpec spec;
        spec.dll_characteristics = kDynamicBase | kNxCompat | kGuardCf;
        spec.reloc_directory = true;
        const MitigationReport report = inspect(build(spec));

        SP_CHECK(report.parsed);
        SP_CHECK(report.pe32_plus);
        SP_CHECK(report.aslr);
        SP_CHECK(report.dep);
        SP_CHECK(report.cfg);
        SP_CHECK(!report.high_entropy_va);
        SP_CHECK(report.has_relocations);
        SP_CHECK(!report.relocations_stripped);
        SP_CHECK(!report.signed_image);
    }

    SP_TEST("harden enables DEP, ASLR and high-entropy on a relocatable image");
    {
        PeSpec spec;
        spec.reloc_directory = true;
        std::vector<std::uint8_t> bytes = build(spec);

        const HardenResult result = apply_mitigations(bytes, HardenOptions{});
        SP_CHECK(result.ok);
        SP_CHECK(result.changed());
        SP_CHECK_EQ(result.applied.size(), static_cast<std::size_t>(3));

        SP_CHECK((dll_flags(bytes) & kNxCompat) != 0);
        SP_CHECK((dll_flags(bytes) & kDynamicBase) != 0);
        SP_CHECK((dll_flags(bytes) & kHighEntropyVa) != 0);
        SP_CHECK(result.after.fully_hardened());
    }

    SP_TEST("harden refuses ASLR when there is no relocation directory");
    {
        std::vector<std::uint8_t> bytes = build({});  // no reloc directory

        const HardenResult result = apply_mitigations(bytes, HardenOptions{});
        SP_CHECK(result.ok);
        // DEP still applies; it has no precondition.
        SP_CHECK((dll_flags(bytes) & kNxCompat) != 0);
        SP_CHECK((dll_flags(bytes) & kDynamicBase) == 0);
        // And high-entropy must follow ASLR down rather than being set alone.
        SP_CHECK((dll_flags(bytes) & kHighEntropyVa) == 0);
        SP_CHECK(!result.refused.empty());
    }

    SP_TEST("harden refuses ASLR when the COFF header says relocations were stripped");
    {
        PeSpec spec;
        spec.reloc_directory = true;   // present, but...
        spec.coff_characteristics = kRelocsStripped;   // ...declared stripped
        std::vector<std::uint8_t> bytes = build(spec);

        const HardenResult result = apply_mitigations(bytes, HardenOptions{});
        SP_CHECK(result.ok);
        SP_CHECK(result.before.relocations_stripped);
        SP_CHECK((dll_flags(bytes) & kDynamicBase) == 0);
    }

    SP_TEST("harden refuses high-entropy ASLR on a 32-bit image");
    {
        PeSpec spec;
        spec.pe32_plus = false;
        spec.reloc_directory = true;
        std::vector<std::uint8_t> bytes = build(spec);

        const HardenResult result = apply_mitigations(bytes, HardenOptions{});
        SP_CHECK(result.ok);
        SP_CHECK((dll_flags(bytes) & kDynamicBase) != 0);
        SP_CHECK((dll_flags(bytes) & kHighEntropyVa) == 0);
        // fully_hardened must not demand a 64-bit-only bit from a 32-bit image.
        SP_CHECK(result.after.fully_hardened());
    }

    SP_TEST("harden refuses a signed image unless told otherwise");
    {
        PeSpec spec;
        spec.reloc_directory = true;
        spec.certificate = true;
        std::vector<std::uint8_t> bytes = build(spec);
        const std::vector<std::uint8_t> original = bytes;

        const HardenResult refused = apply_mitigations(bytes, HardenOptions{});
        SP_CHECK(!refused.ok);
        SP_CHECK(refused.before.signed_image);
        // Refusal must not have touched the buffer.
        SP_CHECK(bytes == original);

        HardenOptions permitted;
        permitted.allow_signed = true;
        const HardenResult allowed = apply_mitigations(bytes, permitted);
        SP_CHECK(allowed.ok);
        SP_CHECK((dll_flags(bytes) & kDynamicBase) != 0);
    }

    SP_TEST("harden recomputes the checksum so it validates afterwards");
    {
        PeSpec spec;
        spec.reloc_directory = true;
        std::vector<std::uint8_t> bytes = build(spec);

        const HardenResult result = apply_mitigations(bytes, HardenOptions{});
        SP_CHECK(result.ok);
        SP_CHECK(result.after.checksum_valid);
        SP_CHECK(result.after.stored_checksum == result.after.computed_checksum);
    }

    SP_TEST("harden leaves the checksum alone when asked not to fix it");
    {
        PeSpec spec;
        spec.reloc_directory = true;
        std::vector<std::uint8_t> bytes = build(spec);

        HardenOptions options;
        options.fix_checksum = false;
        const HardenResult result = apply_mitigations(bytes, options);
        SP_CHECK(result.ok);
        SP_CHECK_EQ(result.after.stored_checksum, static_cast<std::uint32_t>(0));
    }

    SP_TEST("harden on an already-hardened image changes nothing");
    {
        PeSpec spec;
        spec.reloc_directory = true;
        spec.dll_characteristics = kDynamicBase | kNxCompat | kHighEntropyVa;
        std::vector<std::uint8_t> bytes = build(spec);
        const std::vector<std::uint8_t> original = bytes;

        const HardenResult result = apply_mitigations(bytes, HardenOptions{});
        SP_CHECK(result.ok);
        SP_CHECK(!result.changed());
        // Byte-identical: a caller that saves unconditionally must not produce a
        // file that differs only by a rewritten checksum.
        SP_CHECK(bytes == original);
    }

    SP_TEST("checksum excludes its own field");
    {
        PeSpec spec;
        std::vector<std::uint8_t> bytes = build(spec);
        const std::size_t checksum_at = kOptAt + 0x40;

        const std::uint32_t clean = compute_checksum(bytes, checksum_at);
        // Whatever is sitting in the field must not affect the result, or the
        // value could never be stable across two runs.
        write_u32le(&bytes[checksum_at], 0xDEADBEEF);
        SP_CHECK_EQ(compute_checksum(bytes, checksum_at), clean);
    }
}
