#pragma once
//
// StringExtractor.h - Recovering referenced string literals.
//
// The single highest information-per-token input the AI layer can receive. A
// function referencing "SOFTWARE\Microsoft\Windows\CurrentVersion\Run" is
// identifiable at a glance; the same function described only by its 200
// instructions often is not. Strings frequently settle a function's purpose
// more decisively than the entire disassembly.
//
// Strategy: for every instruction with a statically-known memory operand
// pointing into a non-writable section, try to decode a string there. Only
// references that actually appear in code are reported - scanning sections
// blindly would produce thousands of unreferenced strings with no idea which
// function cares about any of them.
//
#include "sp/core/Types.h"
#include "sp/db/FactStore.h"
#include "sp/disasm/InstructionStorage.h"

#include <cstddef>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

namespace sp::analysis {

enum class StringEncoding : std::uint8_t {
    Ascii = 0,   // single-byte, NUL terminated
    Utf16,       // UTF-16LE, NUL terminated - the Windows default
};

const char* to_string(StringEncoding e);

struct ExtractedString {
    core::VA address = core::kInvalidVA;
    StringEncoding encoding = StringEncoding::Ascii;

    // Decoded content, always stored as UTF-8 for output. UTF-16 sources are
    // transcoded so consumers never have to care which they came from.
    std::string text;

    // Length in characters, before truncation.
    std::size_t length = 0;

    // True when `text` was cut short for output. The full length stays in
    // `length` so a consumer can tell it was clipped.
    bool truncated = false;
};

struct StringExtractionOptions {
    // Shorter runs are overwhelmingly coincidence rather than real strings.
    std::size_t min_length = 4;

    // Cap on a single string's decoded length.
    std::size_t max_length = 512;

    bool decode_ascii = true;
    bool decode_utf16 = true;

    // Require every character to be printable. Without this, arbitrary binary
    // data decodes as long strings of control characters.
    bool printable_only = true;

    // --- UTF-16 plausibility ---------------------------------------------
    //
    // `printable_only` alone is far too weak for UTF-16, and this was a real
    // defect rather than a theoretical one. Any two bytes in the range
    // 0x4E00-0x9FFF form a perfectly "printable" CJK ideograph, so pointer
    // tables, relocation data and x86 instruction bytes all decoded as fluent
    // Chinese. The extractor was reporting text that is not there.
    //
    // The tests below cannot be "reject CJK": a Japanese-language application
    // legitimately contains Japanese. They test coherence instead - real text
    // stays inside one script, misread bytes wander across unrelated ones.

    // Require UTF-16 strings to start on an even address. Compilers align wide
    // literals; an odd start is a strong sign of a misread. Cheap, and it
    // removes roughly half of all accidental decodes on its own.
    bool utf16_require_alignment = true;

    // How many distinct non-ASCII script groups a string may span. Real text is
    // one script plus ASCII punctuation. Two or more unrelated groups in one
    // short run is data being misread.
    std::size_t max_script_groups = 1;

    // A string containing no ASCII at all is believed only if it is at least
    // this long. Short all-CJK runs are the single largest source of false
    // positives, and a genuine non-ASCII UI string is rarely three characters.
    std::size_t min_length_non_ascii = 8;
};

class StringExtractor {
public:
    // Scan the instruction stream for references into read-only data and decode
    // whatever strings are found there.
    void extract(const db::FactStore& facts,
                const disasm::InstructionStorage& instructions,
                const StringExtractionOptions& options);

    // Every distinct string found, keyed by address.
    const std::map<core::VA, ExtractedString>& strings() const { return strings_; }

    // Strings referenced from a given instruction address.
    const ExtractedString* string_at(core::VA address) const;

    // Instruction addresses that reference the string at `string_address`.
    const std::vector<core::VA>* referrers_of(core::VA string_address) const;

    // Which instruction addresses reference strings. Lets the caller attach
    // strings to whichever function contains each instruction.
    const std::unordered_map<core::VA, core::VA>& reference_sites() const
    {
        return reference_sites_;
    }

    std::size_t size() const { return strings_.size(); }
    void clear();

    // --- Decoding primitives, exposed for testing ------------------------

    // Decode a NUL-terminated single-byte string. Returns false if the bytes do
    // not form a plausible string under `options`.
    static bool decode_ascii(const std::uint8_t* data, std::size_t available,
                            const StringExtractionOptions& options,
                            ExtractedString& out);

    // Decode a NUL-terminated UTF-16LE string and transcode it to UTF-8.
    static bool decode_utf16(const std::uint8_t* data, std::size_t available,
                            const StringExtractionOptions& options,
                            ExtractedString& out);

    // Printable per our definition: normal ASCII range, plus tab, newline and
    // carriage return, which appear in real message strings.
    static bool is_printable(std::uint32_t code_point);

private:
    std::map<core::VA, ExtractedString> strings_;
    std::unordered_map<core::VA, std::vector<core::VA>> referrers_;

    // instruction address -> string address
    std::unordered_map<core::VA, core::VA> reference_sites_;
};

} // namespace sp::analysis
