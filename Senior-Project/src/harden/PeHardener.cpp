#include "sp/harden/PeHardener.h"

#include "sp/loader/PeFormat.h"

#include <utility>

namespace sp::harden {
namespace {

using loader::read_u16le;
using loader::read_u32le;
using loader::write_u16le;
using loader::write_u32le;

// Fixed offsets in the PE layout.
constexpr std::size_t kLfanewOffset = 0x3C;
constexpr std::size_t kCoffSize = 20;
constexpr std::size_t kCoffCharacteristicsOffset = 18;

// Within the optional header. These two are at the same offset in PE32 and
// PE32+ despite the 8-byte ImageBase, because PE32 carries a BaseOfData field
// that PE32+ drops - the two differences cancel exactly at 0x20.
constexpr std::size_t kOptChecksumOffset = 0x40;
constexpr std::size_t kOptDllCharacteristicsOffset = 0x46;

constexpr std::uint16_t kMagicPe32 = 0x010B;
constexpr std::uint16_t kMagicPe32Plus = 0x020B;

// Where the data directory array starts, and where its count lives. Here the
// two formats genuinely differ.
constexpr std::size_t kNumRvaAndSizesPe32 = 0x5C;
constexpr std::size_t kNumRvaAndSizesPe32Plus = 0x6C;
constexpr std::size_t kDataDirPe32 = 0x60;
constexpr std::size_t kDataDirPe32Plus = 0x70;

constexpr std::size_t kDirCertificate = 4;
constexpr std::size_t kDirBaseReloc = 5;

/// Everything located during a successful parse, so the two public entry points
/// do not each re-derive it.
struct Layout {
    bool ok = false;
    std::string problem;

    std::size_t opt = 0;            ///< File offset of the optional header.
    std::size_t coff = 0;           ///< File offset of the COFF header.
    bool pe32_plus = false;
    std::size_t data_dir = 0;       ///< File offset of directory entry 0.
    std::uint32_t dir_count = 0;
};

Layout locate(const std::vector<std::uint8_t>& bytes)
{
    Layout out;

    if (bytes.size() < kLfanewOffset + 4) {
        out.problem = "file is too small to contain a DOS header";
        return out;
    }
    if (bytes[0] != 'M' || bytes[1] != 'Z') {
        out.problem = "missing MZ signature";
        return out;
    }

    const std::uint32_t lfanew = read_u32le(bytes.data() + kLfanewOffset);
    // Bounded before use: e_lfanew is attacker-controlled in a hostile sample,
    // and this runs over files we were handed precisely because they might be.
    if (lfanew > bytes.size() || bytes.size() - lfanew < 4 + kCoffSize) {
        out.problem = "e_lfanew points outside the file";
        return out;
    }
    const std::uint8_t* pe = bytes.data() + lfanew;
    if (pe[0] != 'P' || pe[1] != 'E' || pe[2] != 0 || pe[3] != 0) {
        out.problem = "missing PE signature";
        return out;
    }

    out.coff = lfanew + 4;
    out.opt = out.coff + kCoffSize;

    const std::uint16_t size_of_optional =
        read_u16le(bytes.data() + out.coff + 16);
    if (size_of_optional == 0) {
        out.problem = "object file, not an image: no optional header";
        return out;
    }
    if (out.opt + size_of_optional > bytes.size()) {
        out.problem = "optional header runs past the end of the file";
        return out;
    }
    // Everything we touch lives below 0x70 + directories; require at least
    // enough for DllCharacteristics before reading it.
    if (size_of_optional < kOptDllCharacteristicsOffset + 2) {
        out.problem = "optional header is truncated before DllCharacteristics";
        return out;
    }

    const std::uint16_t magic = read_u16le(bytes.data() + out.opt);
    if (magic == kMagicPe32Plus) {
        out.pe32_plus = true;
    } else if (magic != kMagicPe32) {
        out.problem = "unrecognised optional header magic";
        return out;
    }

    const std::size_t count_offset =
        out.pe32_plus ? kNumRvaAndSizesPe32Plus : kNumRvaAndSizesPe32;
    const std::size_t dir_offset =
        out.pe32_plus ? kDataDirPe32Plus : kDataDirPe32;

    if (size_of_optional >= count_offset + 4) {
        out.dir_count = read_u32le(bytes.data() + out.opt + count_offset);
        out.data_dir = out.opt + dir_offset;
        // A count large enough to run off the end is corruption, not a reason
        // to read out of bounds.
        const std::size_t needed = out.data_dir + (std::size_t{ out.dir_count } * 8);
        if (out.dir_count > 16 || needed > bytes.size()) {
            out.dir_count = 0;
        }
    }

    out.ok = true;
    return out;
}

// Section headers follow the optional header, 40 bytes each.
constexpr std::size_t kSectionHeaderSize = 40;
constexpr std::size_t kSectionNameSize = 8;
constexpr std::size_t kSectionCharacteristicsOffset = 36;

/// File offset of the section table, and how many entries it has.
struct SectionTable {
    std::size_t offset = 0;
    std::uint16_t count = 0;
};

SectionTable locate_sections(const std::vector<std::uint8_t>& bytes, const Layout& layout)
{
    SectionTable table;
    const std::uint16_t size_of_optional =
        read_u16le(bytes.data() + layout.coff + 16);
    table.count = read_u16le(bytes.data() + layout.coff + 2);
    table.offset = layout.opt + size_of_optional;

    // A count that would run past the end is corruption, not a reason to read
    // out of bounds.
    const std::size_t needed =
        table.offset + (std::size_t{ table.count } * kSectionHeaderSize);
    if (table.count > 96 || needed > bytes.size()) {
        table.count = 0;
    }
    return table;
}

/// Directory `index`: true when present with a non-zero address and size.
bool directory_present(const std::vector<std::uint8_t>& bytes,
                       const Layout& layout,
                       std::size_t index)
{
    if (index >= layout.dir_count) {
        return false;
    }
    const std::uint8_t* entry = bytes.data() + layout.data_dir + (index * 8);
    return read_u32le(entry) != 0 && read_u32le(entry + 4) != 0;
}

} // namespace

std::uint32_t compute_checksum(const std::vector<std::uint8_t>& bytes,
                               std::size_t checksum_offset)
{
    std::uint64_t sum = 0;

    for (std::size_t i = 0; i + 1 < bytes.size(); i += 2) {
        std::uint16_t word = read_u16le(bytes.data() + i);
        // The CheckSum field reads as zero while its own value is computed.
        // It is 4 bytes and 2-aligned, so it covers exactly two words.
        if (i >= checksum_offset && i < checksum_offset + 4) {
            word = 0;
        }
        sum += word;
        // Fold the carry out of 32 bits back in as it happens, rather than
        // letting it accumulate.
        if (sum > 0xFFFFFFFFull) {
            sum = (sum & 0xFFFFFFFFull) + (sum >> 32);
        }
    }

    // An odd-length file contributes its last byte as the low half of a word.
    if ((bytes.size() % 2) != 0 && !bytes.empty()) {
        sum += bytes.back();
    }

    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = sum + (sum >> 16);
    sum = sum & 0xFFFF;

    return static_cast<std::uint32_t>(sum) + static_cast<std::uint32_t>(bytes.size());
}

MitigationReport inspect(const std::vector<std::uint8_t>& bytes)
{
    MitigationReport report;

    const Layout layout = locate(bytes);
    if (!layout.ok) {
        report.problem = layout.problem;
        return report;
    }

    report.parsed = true;
    report.pe32_plus = layout.pe32_plus;

    report.dll_characteristics =
        read_u16le(bytes.data() + layout.opt + kOptDllCharacteristicsOffset);
    report.coff_characteristics =
        read_u16le(bytes.data() + layout.coff + kCoffCharacteristicsOffset);

    report.aslr = (report.dll_characteristics & kDynamicBase) != 0;
    report.high_entropy_va = (report.dll_characteristics & kHighEntropyVa) != 0;
    report.dep = (report.dll_characteristics & kNxCompat) != 0;
    report.cfg = (report.dll_characteristics & kGuardCf) != 0;
    report.safe_seh_disabled = (report.dll_characteristics & kNoSeh) != 0;

    report.relocations_stripped =
        (report.coff_characteristics & kRelocsStripped) != 0;
    report.has_relocations = directory_present(bytes, layout, kDirBaseReloc);
    // The certificate directory's first field is a file offset, not an RVA -
    // the one entry in the table that breaks that rule. Only presence matters
    // here, so it does not change the check.
    report.signed_image = directory_present(bytes, layout, kDirCertificate);

    const SectionTable table = locate_sections(bytes, layout);
    report.sections.reserve(table.count);
    for (std::uint16_t i = 0; i < table.count; ++i) {
        const std::uint8_t* header =
            bytes.data() + table.offset + (std::size_t{ i } * kSectionHeaderSize);

        SectionFlags section;
        // The name is eight bytes and is NOT required to be terminated when it
        // fills the field, so it is read by length rather than as a C string.
        std::size_t length = 0;
        while (length < kSectionNameSize && header[length] != 0) ++length;
        section.name.assign(reinterpret_cast<const char*>(header), length);

        const std::uint32_t flags =
            read_u32le(header + kSectionCharacteristicsOffset);
        section.executable = (flags & kScnExecute) != 0;
        section.writable = (flags & kScnWrite) != 0;
        section.readable = (flags & kScnRead) != 0;
        section.code = (flags & kScnCode) != 0;
        report.sections.push_back(std::move(section));
    }

    report.stored_checksum = read_u32le(bytes.data() + layout.opt + kOptChecksumOffset);
    report.computed_checksum =
        compute_checksum(bytes, layout.opt + kOptChecksumOffset);
    report.checksum_valid = report.stored_checksum == report.computed_checksum;

    return report;
}

HardenResult apply_mitigations(std::vector<std::uint8_t>& bytes,
                               const HardenOptions& options)
{
    HardenResult result;
    result.before = inspect(bytes);

    if (!result.before.parsed) {
        result.problem = result.before.problem;
        result.after = result.before;
        return result;
    }

    if (result.before.signed_image && !options.allow_signed) {
        result.problem =
            "image is Authenticode signed; any edit invalidates the signature. "
            "Re-run with allow_signed to proceed and strip or re-sign afterwards.";
        result.after = result.before;
        return result;
    }

    const Layout layout = locate(bytes);
    std::uint16_t flags = result.before.dll_characteristics;

    if (options.enable_dep) {
        if (result.before.dep) {
            result.refused.emplace_back("DEP (NX_COMPAT): already enabled");
        } else {
            flags |= kNxCompat;
            result.applied.emplace_back("DEP (NX_COMPAT): stack and heap marked non-executable");
        }
    }

    /* ASLR is the one with a precondition. Without relocation data the loader
     * cannot place the image anywhere but its preferred base, so the bit is at
     * best ignored and at worst produces an image that will not load. Refusing
     * with the reason is the useful answer; setting it anyway would be a lie
     * that this tool had hardened something. */
    const bool relocatable =
        result.before.has_relocations && !result.before.relocations_stripped;

    if (options.enable_aslr) {
        if (result.before.aslr) {
            result.refused.emplace_back("ASLR (DYNAMIC_BASE): already enabled");
        } else if (!relocatable) {
            result.refused.emplace_back(
                result.before.relocations_stripped
                    ? "ASLR (DYNAMIC_BASE): refused, the COFF header says relocations "
                      "were stripped, so the image cannot be rebased"
                    : "ASLR (DYNAMIC_BASE): refused, no base relocation directory, "
                      "so the image cannot be rebased");
        } else {
            flags |= kDynamicBase;
            result.applied.emplace_back("ASLR (DYNAMIC_BASE): image may load at a randomised base");
        }
    }

    // High-entropy ASLR is 64-bit only, and meaningless without DYNAMIC_BASE.
    if (options.enable_high_entropy_va) {
        const bool aslr_on_after = (flags & kDynamicBase) != 0;
        if (!layout.pe32_plus) {
            result.refused.emplace_back(
                "High-entropy ASLR (HIGH_ENTROPY_VA): not applicable to a 32-bit image");
        } else if (!aslr_on_after) {
            result.refused.emplace_back(
                "High-entropy ASLR (HIGH_ENTROPY_VA): refused, it does nothing without ASLR");
        } else if (result.before.high_entropy_va) {
            result.refused.emplace_back("High-entropy ASLR (HIGH_ENTROPY_VA): already enabled");
        } else {
            flags |= kHighEntropyVa;
            result.applied.emplace_back(
                "High-entropy ASLR (HIGH_ENTROPY_VA): full 64-bit randomisation range");
        }
    }

    /* W^X: the only change here that can break the program.
     *
     * A section that is both writable and executable is memory an attacker can
     * fill and then run, which is the shape most exploits need, and no correct
     * program requires both permissions on the same page. But removing a
     * permission removes something the image may genuinely use - a packer
     * decompressing into its own section, or self-modifying code, faults on the
     * first store. So it is reported always and changed only on request.
     *
     * Which bit to clear is decided per section: a code section keeps execute
     * and loses write; a data section keeps write and loses execute. Clearing
     * the wrong one turns a hardening pass into a crash. */
    std::vector<std::size_t> offenders;
    for (std::size_t i = 0; i < result.before.sections.size(); ++i) {
        if (result.before.sections[i].write_execute()) offenders.push_back(i);
    }

    if (!offenders.empty() && options.enforce_write_xor_execute) {
        const SectionTable table = locate_sections(bytes, layout);
        for (const std::size_t index : offenders) {
            if (index >= table.count) continue;
            std::uint8_t* header = bytes.data() + table.offset
                + (index * kSectionHeaderSize) + kSectionCharacteristicsOffset;
            std::uint32_t flags = read_u32le(header);

            const SectionFlags& section = result.before.sections[index];
            if (section.code) {
                flags &= ~kScnWrite;
            } else {
                flags &= ~kScnExecute;
            }
            write_u32le(header, flags);

            result.applied.emplace_back(
                "W^X on section '" + section.name + "': removed "
                + (section.code ? "write" : "execute")
                + " permission, which no correct program needs alongside the other");
        }
    } else if (!offenders.empty()) {
        std::string names;
        for (const std::size_t index : offenders) {
            if (!names.empty()) names += ", ";
            names += "'" + result.before.sections[index].name + "'";
        }
        result.refused.emplace_back(
            "W^X: section(s) " + names + " are writable AND executable, which is "
            "how injected data becomes running code. Not changed automatically: "
            "removing a permission the image genuinely uses - a packer, or "
            "self-modifying code - would break it. Re-run with the option enabled "
            "once you have established it does neither.");
    }

    /* Reported, never set. Each needs something this tool cannot synthesise, and
     * a header bit claiming otherwise would make the image assert a protection
     * it does not have - strictly worse than leaving it off. */
    if (!result.before.cfg) {
        result.refused.emplace_back(
            "Control Flow Guard (GUARD_CF): cannot be added, it needs the guard "
            "tables the compiler emits. Rebuild with /guard:cf.");
    }
    if (!result.before.safe_seh_disabled) {
        result.refused.emplace_back(
            "NO_SEH: reported only. Setting it asserts the image installs no "
            "structured exception handler, and asserting that wrongly disables "
            "exception handling the program depends on. Establishing it needs the "
            "load configuration directory, which this pass does not read.");
    }
    result.refused.emplace_back(
        "Stack cookies (/GS): not representable in the PE header. They are "
        "compiler-emitted code, so their absence cannot be seen here and their "
        "presence cannot be added. Rebuild with /GS.");
    result.refused.emplace_back(
        "CET shadow stack: not visible from the optional header. The flag lives "
        "in an extended-characteristics debug directory entry, which this pass "
        "does not parse. Rebuild with /CETCOMPAT to enable it.");

    if (result.applied.empty()) {
        // Nothing to write. Leaving the buffer untouched means a caller that
        // saves unconditionally still produces a byte-identical file.
        result.ok = true;
        result.after = result.before;
        return result;
    }

    write_u16le(bytes.data() + layout.opt + kOptDllCharacteristicsOffset, flags);

    if (options.fix_checksum) {
        const std::size_t checksum_at = layout.opt + kOptChecksumOffset;
        write_u32le(bytes.data() + checksum_at, compute_checksum(bytes, checksum_at));
    }

    result.ok = true;
    result.after = inspect(bytes);
    return result;
}

} // namespace sp::harden
