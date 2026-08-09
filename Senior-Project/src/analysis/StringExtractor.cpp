#include "sp/analysis/StringExtractor.h"

#include "sp/core/Log.h"

#include <algorithm>

namespace sp::analysis {
namespace {

// Longest byte run we will ever examine for one string.
constexpr std::size_t kMaxProbe = 4096;

// Append a Unicode code point to a UTF-8 string.
void append_utf8(std::string& out, std::uint32_t code_point)
{
    if (code_point < 0x80) {
        out.push_back(static_cast<char>(code_point));
    } else if (code_point < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (code_point >> 6)));
        out.push_back(static_cast<char>(0x80 | (code_point & 0x3F)));
    } else if (code_point < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (code_point >> 12)));
        out.push_back(static_cast<char>(0x80 | ((code_point >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (code_point & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (code_point >> 18)));
        out.push_back(static_cast<char>(0x80 | ((code_point >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((code_point >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (code_point & 0x3F)));
    }
}

} // namespace

const char* to_string(StringEncoding e)
{
    switch (e) {
    case StringEncoding::Ascii: return "ascii";
    case StringEncoding::Utf16: return "utf16";
    default:                    return "?";
    }
}

// --- UTF-16 plausibility -------------------------------------------------
//
// Coarse script grouping. Deliberately coarse: the goal is to notice that a run
// of "characters" wanders across unrelated writing systems, which is what happens
// when binary data is read as UTF-16. Fine-grained Unicode block tables would add
// pages of data and answer a question nobody asked.
enum class ScriptGroup {
    Ascii,          // not counted as a group - real text mixes ASCII with anything
    LatinExtended,  // accented Latin, IPA
    GreekCyrillic,
    Semitic,        // Hebrew, Arabic, Syriac
    Indic,
    SoutheastAsian, // Thai, Lao, Khmer, Myanmar
    CJK,            // Han, Hiragana, Katakana, Hangul, Bopomofo, fullwidth forms
    Symbols,        // punctuation, arrows, maths, box drawing, emoji
    Implausible,    // private use, noncharacters, unassigned-prone ranges
};

ScriptGroup script_group_of(std::uint32_t cp)
{
    if (cp < 0x80)                       return ScriptGroup::Ascii;
    // Private use and noncharacters never appear in a real string literal. They
    // do appear constantly when arbitrary bytes are reinterpreted.
    if (cp >= 0xE000 && cp <= 0xF8FF)    return ScriptGroup::Implausible;
    if (cp >= 0xF0000)                   return ScriptGroup::Implausible;
    if (cp >= 0xFDD0 && cp <= 0xFDEF)    return ScriptGroup::Implausible;
    if ((cp & 0xFFFE) == 0xFFFE)         return ScriptGroup::Implausible;

    if (cp <= 0x24F)                     return ScriptGroup::LatinExtended;
    if (cp >= 0x370 && cp <= 0x52F)      return ScriptGroup::GreekCyrillic;
    if (cp >= 0x590 && cp <= 0x8FF)      return ScriptGroup::Semitic;
    if (cp >= 0x900 && cp <= 0xDFF)      return ScriptGroup::Indic;
    if (cp >= 0xE00 && cp <= 0x109F)     return ScriptGroup::SoutheastAsian;
    if (cp >= 0x1100 && cp <= 0x11FF)    return ScriptGroup::CJK;   // Hangul Jamo
    if (cp >= 0x2E80 && cp <= 0x9FFF)    return ScriptGroup::CJK;
    if (cp >= 0xA960 && cp <= 0xA97F)    return ScriptGroup::CJK;
    if (cp >= 0xAC00 && cp <= 0xD7FF)    return ScriptGroup::CJK;   // Hangul syllables
    if (cp >= 0xF900 && cp <= 0xFAFF)    return ScriptGroup::CJK;   // compat ideographs
    if (cp >= 0xFF00 && cp <= 0xFFEF)    return ScriptGroup::CJK;   // fullwidth forms
    if (cp >= 0x20000 && cp <= 0x3FFFF)  return ScriptGroup::CJK;   // ext B and beyond
    return ScriptGroup::Symbols;
}

bool StringExtractor::is_printable(std::uint32_t code_point)
{
    if (code_point == '\t' || code_point == '\n' || code_point == '\r') {
        return true;
    }
    if (code_point >= 0x20 && code_point < 0x7F) {
        return true;
    }
    // Accept printable non-ASCII (accented characters, CJK, and so on) but
    // reject the C1 control block, which is a reliable sign of binary data
    // being misread as text.
    return code_point >= 0xA0 && code_point <= 0x10FFFF;
}

bool StringExtractor::decode_ascii(const std::uint8_t* data, std::size_t available,
                                  const StringExtractionOptions& options,
                                  ExtractedString& out)
{
    if (data == nullptr || available == 0) {
        return false;
    }

    const std::size_t limit = std::min(available, kMaxProbe);
    std::string text;
    std::size_t index = 0;

    for (; index < limit; ++index) {
        const std::uint8_t byte = data[index];
        if (byte == 0) {
            break;      // terminator
        }
        if (options.printable_only && !is_printable(byte)) {
            return false;
        }
        if (text.size() < options.max_length) {
            text.push_back(static_cast<char>(byte));
        }
    }

    // No terminator inside the probe window means this is probably not a string.
    if (index >= limit) {
        return false;
    }
    if (index < options.min_length) {
        return false;
    }

    out.encoding = StringEncoding::Ascii;
    out.length = index;
    out.truncated = index > options.max_length;
    out.text = std::move(text);
    return true;
}

bool StringExtractor::decode_utf16(const std::uint8_t* data, std::size_t available,
                                  const StringExtractionOptions& options,
                                  ExtractedString& out)
{
    if (data == nullptr || available < 2) {
        return false;
    }

    const std::size_t limit = std::min(available, kMaxProbe) & ~std::size_t{ 1 };
    std::string text;
    std::size_t chars = 0;
    std::size_t index = 0;
    bool terminated = false;

    // Plausibility evidence, accumulated as we decode rather than re-derived
    // afterwards. By the time `text` exists it is UTF-8, and decoding it a second
    // time to ask questions about its code points would be wasteful and would put
    // two decoders in the codebase that have to agree.
    std::size_t ascii_chars = 0;
    unsigned script_groups = 0;   // bitmask over ScriptGroup, ASCII excluded
    bool implausible = false;

    while (index + 1 < limit) {
        const std::uint32_t unit =
            static_cast<std::uint32_t>(data[index])
            | (static_cast<std::uint32_t>(data[index + 1]) << 8);
        index += 2;

        if (unit == 0) {
            terminated = true;
            break;
        }

        std::uint32_t code_point = unit;

        // Surrogate pair.
        if (unit >= 0xD800 && unit <= 0xDBFF && index + 1 < limit) {
            const std::uint32_t low =
                static_cast<std::uint32_t>(data[index])
                | (static_cast<std::uint32_t>(data[index + 1]) << 8);
            if (low >= 0xDC00 && low <= 0xDFFF) {
                code_point = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00);
                index += 2;
            } else {
                // A high surrogate with no low surrogate is not valid UTF-16 at
                // all. Real text never contains one; misread bytes do.
                return false;
            }
        } else if (unit >= 0xDC00 && unit <= 0xDFFF) {
            // Lone low surrogate. Same reasoning.
            return false;
        }

        if (options.printable_only && !is_printable(code_point)) {
            return false;
        }

        const ScriptGroup group = script_group_of(code_point);
        if (group == ScriptGroup::Implausible) {
            implausible = true;
        } else if (group == ScriptGroup::Ascii) {
            ++ascii_chars;
        } else {
            script_groups |= 1u << static_cast<unsigned>(group);
        }

        if (chars < options.max_length) {
            append_utf8(text, code_point);
        }
        ++chars;
    }

    if (!terminated || chars < options.min_length) {
        return false;
    }

    // Private-use or noncharacter code points: not a string, at any length.
    if (implausible) {
        return false;
    }

    // Count how many distinct non-ASCII scripts appeared. Symbols are excluded
    // from the count because a real sentence may legitimately carry a curly quote
    // or an arrow alongside its own script.
    unsigned groups = script_groups & ~(1u << static_cast<unsigned>(ScriptGroup::Symbols));
    std::size_t distinct = 0;
    for (unsigned bit = groups; bit != 0; bit >>= 1) {
        distinct += (bit & 1u);
    }
    if (distinct > options.max_script_groups) {
        return false;
    }

    // Nothing recognisable as ASCII anywhere: believable, but only at length.
    // This is the test that removes the bulk of the phantom CJK.
    if (ascii_chars == 0 && chars < options.min_length_non_ascii) {
        return false;
    }

    out.encoding = StringEncoding::Utf16;
    out.length = chars;
    out.truncated = chars > options.max_length;
    out.text = std::move(text);
    return true;
}

void StringExtractor::extract(const db::FactStore& facts,
                             const disasm::InstructionStorage& instructions,
                             const StringExtractionOptions& options)
{
    clear();

    const core::AddressSpace& space = facts.address_space();
    std::size_t rejected = 0;

    for (const auto& entry : instructions) {
        const core::VA site = entry.first;
        const disasm::InstructionInfo& insn = entry.second;

        if (!insn.memory_reference.has_value()) {
            continue;
        }
        const core::VA target = *insn.memory_reference;

        // Already decoded from another reference site.
        auto known = strings_.find(target);
        if (known != strings_.end()) {
            referrers_[target].push_back(site);
            reference_sites_[site] = target;
            continue;
        }

        // String literals live in read-only data. A writable target is a
        // variable, not a literal, and an executable one is code.
        const core::SectionRange* section = space.section_containing(target);
        if (section == nullptr || section->writable || section->executable) {
            continue;
        }

        // How many bytes remain in this section from the target address.
        const core::VA section_start = space.to_va(section->rva);
        const core::VA section_end = section_start + section->virtual_size;
        if (target >= section_end) {
            continue;
        }
        const std::size_t remaining = static_cast<std::size_t>(section_end - target);
        const std::size_t probe = std::min(remaining, kMaxProbe);

        const std::uint8_t* bytes = facts.bytes_at(target, probe);
        if (bytes == nullptr) {
            continue;
        }

        ExtractedString decoded;
        decoded.address = target;

        // Try UTF-16 first. Windows APIs are predominantly wide-character, and
        // an ASCII decode of UTF-16 text succeeds on the first character then
        // stops at the interleaved NUL - producing a one-character string that
        // silently hides the real one.
        bool ok = false;
        // Alignment is checked here rather than inside decode_utf16, because the
        // decoder is handed a buffer and has no idea what address it came from.
        // Compilers align wide literals, so an odd start is a misread.
        const bool aligned =
            !options.utf16_require_alignment || (target % 2 == 0);
        if (options.decode_utf16 && aligned) {
            ok = decode_utf16(bytes, probe, options, decoded);
        }
        if (!ok && options.decode_ascii) {
            ok = decode_ascii(bytes, probe, options, decoded);
        }

        if (!ok) {
            ++rejected;
            continue;
        }

        strings_.emplace(target, std::move(decoded));
        referrers_[target].push_back(site);
        reference_sites_[site] = target;
    }

    core::log_info("extracted " + std::to_string(strings_.size())
                   + " strings from " + std::to_string(reference_sites_.size())
                   + " reference sites (" + std::to_string(rejected)
                   + " non-string data references)");
}

const ExtractedString* StringExtractor::string_at(core::VA address) const
{
    auto it = strings_.find(address);
    return it == strings_.end() ? nullptr : &it->second;
}

const std::vector<core::VA>* StringExtractor::referrers_of(core::VA string_address) const
{
    auto it = referrers_.find(string_address);
    return it == referrers_.end() ? nullptr : &it->second;
}

void StringExtractor::clear()
{
    strings_.clear();
    referrers_.clear();
    reference_sites_.clear();
}

} // namespace sp::analysis
