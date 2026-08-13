#pragma once
//
// PeHardener.h - Read and raise the exploit mitigations in a PE image.
//
// WHAT THIS IS
//
// The engine finds defects. This turns some of what it finds into a changed
// executable, by enabling the loader-level mitigations the image asks for in its
// own header: ASLR, DEP, and high-entropy address space on 64-bit.
//
// WHAT THIS IS NOT, AND WHY
//
// It does not repair the defective code. Rewriting `lstrcpyW(dst, src)` into a
// bounded copy needs the capacity of `dst`, and this engine has no value-level
// dataflow - every finding says so in its own `limitation` field. A repair
// derived from analysis that cannot know the buffer size cannot be shown
// correct: too small silently truncates, too large changes nothing while
// claiming a fix. Shipping an unverifiable patch would contradict the property
// the rest of this project is built on, which is that a stated confidence means
// something.
//
// Mitigations are a different claim, and an honest one. Enabling DEP does not
// fix the overflow; it removes the conditions that make the overflow run
// attacker code. That is a real, checkable improvement, and it is checkable by
// somebody else's tool - `dumpbin /headers`, or Microsoft's BinSkim - which is
// worth more than this project marking its own homework.
//
// HONESTY CONSTRAINTS BAKED IN
//
//   * ASLR is refused without relocation data. Setting DYNAMIC_BASE on an image
//     whose relocations were stripped produces something the loader cannot
//     rebase; depending on the OS it is ignored or the image fails to load.
//   * /GS is reported as unrepresentable, not as absent. Stack cookies are
//     compiler-emitted code, not a header bit; there is nothing here to set, and
//     saying "off" would imply this tool could turn it on.
//   * CFG is reported, never set. It needs the guard tables the compiler emits.
//   * A signed image is refused by default. Any byte we change invalidates the
//     Authenticode signature, and quietly producing a binary with a broken
//     signature is worse than producing nothing.
//
// Raw bytes in, raw bytes out, no LIEF - same reasoning as PeFormat: this is a
// fixed on-disk layout, and a function over a byte buffer can be unit tested
// without an executable on disk.
//
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace sp::harden {

// IMAGE_DLLCHARACTERISTICS_* values we care about.
inline constexpr std::uint16_t kHighEntropyVa = 0x0020;
inline constexpr std::uint16_t kDynamicBase   = 0x0040;
inline constexpr std::uint16_t kNxCompat      = 0x0100;
inline constexpr std::uint16_t kNoSeh         = 0x0400;
inline constexpr std::uint16_t kGuardCf       = 0x4000;

// IMAGE_FILE_RELOCS_STRIPPED, in the COFF header's Characteristics.
inline constexpr std::uint16_t kRelocsStripped = 0x0001;

// IMAGE_SCN_* section characteristics.
inline constexpr std::uint32_t kScnCode    = 0x00000020;
inline constexpr std::uint32_t kScnExecute = 0x20000000;
inline constexpr std::uint32_t kScnRead    = 0x40000000;
inline constexpr std::uint32_t kScnWrite   = 0x80000000;

/// One section's memory permissions.
struct SectionFlags {
    std::string name;
    bool executable = false;
    bool writable = false;
    bool readable = false;
    /// The section holds code, as opposed to initialised data.
    bool code = false;

    /// Writable AND executable at once: the classic W^X violation. Memory an
    /// attacker can write to and then run is the shape most exploits need, and
    /// no correct program requires both permissions on the same page.
    bool write_execute() const { return writable && executable; }
};

/// What an image currently asks the loader for.
struct MitigationReport {
    bool parsed = false;
    /// Set when `parsed` is false: why the file could not be read as a PE.
    std::string problem;

    bool pe32_plus = false;             ///< PE32+ (64-bit) rather than PE32.
    std::uint16_t dll_characteristics = 0;
    std::uint16_t coff_characteristics = 0;

    bool aslr = false;                  ///< DYNAMIC_BASE
    bool high_entropy_va = false;       ///< HIGH_ENTROPY_VA (64-bit ASLR)
    bool dep = false;                   ///< NX_COMPAT
    bool cfg = false;                   ///< GUARD_CF (reported only)
    bool safe_seh_disabled = false;     ///< NO_SEH

    /// A base relocation directory exists and is non-empty.
    bool has_relocations = false;
    /// The COFF header says relocations were stripped. ASLR cannot work.
    bool relocations_stripped = false;
    /// An Authenticode certificate is present. Editing invalidates it.
    bool signed_image = false;

    std::uint32_t stored_checksum = 0;
    std::uint32_t computed_checksum = 0;
    bool checksum_valid = false;

    /// Every section's permissions, so the W^X claim can be checked rather than
    /// taken on trust.
    std::vector<SectionFlags> sections;

    /// At least one section is both writable and executable.
    bool has_write_execute() const
    {
        for (const SectionFlags& s : sections) {
            if (s.write_execute()) return true;
        }
        return false;
    }

    /// True when every mitigation this tool can set is already set.
    bool fully_hardened() const
    {
        return aslr && dep && (!pe32_plus || high_entropy_va);
    }
};

struct HardenOptions {
    bool enable_aslr = true;
    bool enable_dep = true;
    bool enable_high_entropy_va = true;

    /* Separate a merely writable-and-executable section from the other fixes,
     * and default it OFF, because it is the only one that can break the program.
     *
     * Setting DYNAMIC_BASE or NX_COMPAT asks the loader for stricter treatment
     * of an image that was always meant to run that way. Removing a section's
     * write permission removes something the program may actually use: a packer
     * that decompresses into its own section, or self-modifying code, will fault
     * on the first store. The permission is nearly always a build accident, but
     * "nearly always" is not a basis for changing it without being asked. */
    bool enforce_write_xor_execute = false;
    /// Proceed even though it breaks an Authenticode signature. Off by default;
    /// the caller has to say so deliberately.
    bool allow_signed = false;
    /// Recompute the header checksum after editing. Off means the image keeps a
    /// stale checksum, which some loaders reject.
    bool fix_checksum = true;
};

struct HardenResult {
    bool ok = false;
    /// Set when `ok` is false.
    std::string problem;

    MitigationReport before;
    MitigationReport after;

    /// Human-readable, one per mitigation actually turned on.
    std::vector<std::string> applied;
    /// One per mitigation deliberately not applied, each with its reason. A
    /// refusal is a result, not an error: "ASLR needs relocation data, and this
    /// image has none" is the useful output.
    std::vector<std::string> refused;

    bool changed() const { return !applied.empty(); }
};

/// Read an image's current mitigation state. Never modifies `bytes`.
MitigationReport inspect(const std::vector<std::uint8_t>& bytes);

/// Raise what can be raised, in place. `bytes` is left untouched when the result
/// is not `ok`, and when nothing could be applied.
///
/// Named `apply_mitigations` rather than `harden` because a function cannot
/// share a name with the namespace that contains it: any translation unit doing
/// `using namespace sp;` and `using namespace sp::harden;` then sees both the
/// namespace and the function under one name, and every call is an ambiguous
/// symbol.
HardenResult apply_mitigations(std::vector<std::uint8_t>& bytes,
                               const HardenOptions& options);

/// The PE header checksum over `bytes`, computed as the loader does: 16-bit
/// ones-complement-style accumulation with the CheckSum field itself read as
/// zero, plus the file size.
std::uint32_t compute_checksum(const std::vector<std::uint8_t>& bytes,
                               std::size_t checksum_offset);

} // namespace sp::harden
