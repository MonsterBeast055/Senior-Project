#include "test_harness.h"

#include "sp/analysis/StringExtractor.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using namespace sp;
using namespace sp::analysis;

namespace {

std::vector<std::uint8_t> ascii_bytes(const char* text)
{
    std::vector<std::uint8_t> out(text, text + std::strlen(text));
    out.push_back(0);
    return out;
}

std::vector<std::uint8_t> utf16_bytes(const char* ascii_source)
{
    std::vector<std::uint8_t> out;
    for (const char* p = ascii_source; *p != '\0'; ++p) {
        out.push_back(static_cast<std::uint8_t>(*p));
        out.push_back(0);
    }
    out.push_back(0);
    out.push_back(0);
    return out;
}

} // namespace

// Builds a NUL-terminated UTF-16LE buffer from code points. Surrogate pairs are
// encoded properly so the tests exercise the decoder's real path.
static std::vector<std::uint8_t> utf16_bytes(const std::vector<std::uint32_t>& points)
{
    std::vector<std::uint8_t> out;
    for (std::uint32_t cp : points) {
        if (cp < 0x10000) {
            out.push_back(static_cast<std::uint8_t>(cp & 0xFF));
            out.push_back(static_cast<std::uint8_t>(cp >> 8));
        } else {
            const std::uint32_t v = cp - 0x10000;
            const std::uint32_t hi = 0xD800 + (v >> 10);
            const std::uint32_t lo = 0xDC00 + (v & 0x3FF);
            out.push_back(static_cast<std::uint8_t>(hi & 0xFF));
            out.push_back(static_cast<std::uint8_t>(hi >> 8));
            out.push_back(static_cast<std::uint8_t>(lo & 0xFF));
            out.push_back(static_cast<std::uint8_t>(lo >> 8));
        }
    }
    out.push_back(0);
    out.push_back(0);
    return out;
}

void test_strings()
{
    StringExtractionOptions options;

    SP_TEST("strings: ascii decoding");
    {
        const auto bytes = ascii_bytes("CreateFileW");
        ExtractedString out;
        SP_CHECK(StringExtractor::decode_ascii(bytes.data(), bytes.size(), options, out));
        SP_CHECK(out.text == "CreateFileW");
        SP_CHECK_EQ(out.length, std::size_t{ 11 });
        SP_CHECK_EQ(out.encoding, StringEncoding::Ascii);
    }

    SP_TEST("strings: utf-16 decoding transcodes to utf-8");
    {
        const auto bytes = utf16_bytes("SOFTWARE\\Microsoft");
        ExtractedString out;
        SP_CHECK(StringExtractor::decode_utf16(bytes.data(), bytes.size(), options, out));
        SP_CHECK(out.text == "SOFTWARE\\Microsoft");
        SP_CHECK_EQ(out.encoding, StringEncoding::Utf16);
    }

    SP_TEST("strings: utf-16 is tried before ascii");
    {
        // An ASCII decode of UTF-16 text reads the first character then hits the
        // interleaved NUL, yielding a 1-character string. If ASCII were tried
        // first, every wide string in a Windows binary would come out as a
        // single letter - so ordering matters, and min_length is what makes the
        // wrong answer fail rather than silently win.
        const auto bytes = utf16_bytes("Hello");
        ExtractedString as_ascii;
        SP_CHECK(!StringExtractor::decode_ascii(bytes.data(), bytes.size(),
                                               options, as_ascii));

        ExtractedString as_utf16;
        SP_CHECK(StringExtractor::decode_utf16(bytes.data(), bytes.size(),
                                              options, as_utf16));
        SP_CHECK(as_utf16.text == "Hello");
    }

    SP_TEST("strings: too short is rejected");
    {
        const auto bytes = ascii_bytes("ab");
        ExtractedString out;
        SP_CHECK(!StringExtractor::decode_ascii(bytes.data(), bytes.size(), options, out));
    }

    SP_TEST("strings: unterminated run is rejected");
    {
        // No NUL inside the window: this is data that happens to look textual,
        // not a string literal.
        std::vector<std::uint8_t> bytes(64, 'A');
        ExtractedString out;
        SP_CHECK(!StringExtractor::decode_ascii(bytes.data(), bytes.size(), options, out));
    }

    SP_TEST("strings: non-printable bytes reject the decode");
    {
        std::vector<std::uint8_t> bytes = { 'a', 'b', 0x01, 0x02, 'c', 'd', 0 };
        ExtractedString out;
        SP_CHECK(!StringExtractor::decode_ascii(bytes.data(), bytes.size(), options, out));
    }

    SP_TEST("strings: printable classification");
    {
        SP_CHECK(StringExtractor::is_printable('A'));
        SP_CHECK(StringExtractor::is_printable(' '));
        SP_CHECK(StringExtractor::is_printable('\t'));
        SP_CHECK(StringExtractor::is_printable('\n'));
        SP_CHECK(!StringExtractor::is_printable(0x00));
        SP_CHECK(!StringExtractor::is_printable(0x01));
        SP_CHECK(!StringExtractor::is_printable(0x7F));
        // C1 control block is the tell for binary data read as text.
        SP_CHECK(!StringExtractor::is_printable(0x85));
        // Real non-ASCII text is accepted.
        SP_CHECK(StringExtractor::is_printable(0x00E9));   // e-acute
    }

    SP_TEST("strings: max_length truncates but records true length");
    {
        StringExtractionOptions capped = options;
        capped.max_length = 8;

        const auto bytes = ascii_bytes("abcdefghijklmnop");
        ExtractedString out;
        SP_CHECK(StringExtractor::decode_ascii(bytes.data(), bytes.size(), capped, out));
        SP_CHECK_EQ(out.text.size(), std::size_t{ 8 });
        SP_CHECK_EQ(out.length, std::size_t{ 16 });
        SP_CHECK(out.truncated);
    }

    SP_TEST("strings: empty and null inputs are safe");
    {
        ExtractedString out;
        SP_CHECK(!StringExtractor::decode_ascii(nullptr, 0, options, out));
        SP_CHECK(!StringExtractor::decode_utf16(nullptr, 0, options, out));

        const std::uint8_t single = 0;
        SP_CHECK(!StringExtractor::decode_utf16(&single, 1, options, out));
    }

    SP_TEST("strings: utf-16 surrogate pair");
    {
        // U+1F600, encoded as the surrogate pair D83D DE00.
        std::vector<std::uint8_t> bytes = {
            'a', 0, 'b', 0, 'c', 0, 'd', 0,
            0x3D, 0xD8, 0x00, 0xDE,
            0, 0
        };
        ExtractedString out;
        SP_CHECK(StringExtractor::decode_utf16(bytes.data(), bytes.size(), options, out));
        SP_CHECK_EQ(out.length, std::size_t{ 5 });
        // Four ASCII bytes plus a 4-byte UTF-8 sequence.
        SP_CHECK_EQ(out.text.size(), std::size_t{ 8 });
    }

    // --- UTF-16 plausibility ---------------------------------------------
    //
    // Regression cases for a real defect: `printable_only` accepts every code
    // point from 0xA0 up, so any two bytes in 0x4E00-0x9FFF formed a "printable"
    // CJK ideograph and pointer tables decoded as fluent Chinese. The gate has to
    // reject those without rejecting a Japanese application's real strings, which
    // is why every case below comes in both flavours.
    SP_TEST("utf16 keeps real non-ASCII text");
    {
        StringExtractionOptions options;
        ExtractedString out;

        // Long enough, single script: a genuine Japanese UI string.
        auto japanese = utf16_bytes({ 0x30D5, 0x30A1, 0x30A4, 0x30EB, 0x3092,
                                      0x4FDD, 0x5B58, 0x3067, 0x304D, 0x307E,
                                      0x305B, 0x3093 });
        SP_CHECK(StringExtractor::decode_utf16(japanese.data(), japanese.size(),
                                               options, out));

        // Mixed with ASCII, which is the common real case.
        auto mixed = utf16_bytes({ 0x30D5, 0x30A1, 0x30A4, 0x30EB, ':', ' ', '%', 's' });
        SP_CHECK(StringExtractor::decode_utf16(mixed.data(), mixed.size(),
                                               options, out));

        auto accented = utf16_bytes({ 'C', 0xE9, 'l', 0xE8, 'b', 'r', 'e' });
        SP_CHECK(StringExtractor::decode_utf16(accented.data(), accented.size(),
                                               options, out));
    }

    SP_TEST("utf16 rejects misread binary data");
    {
        StringExtractionOptions options;
        ExtractedString out;

        // Short all-CJK runs: the bulk of the false positives.
        auto phantom = utf16_bytes({ 0x4E2D, 0x6587, 0x5B57, 0x7B26 });
        SP_CHECK(!StringExtractor::decode_utf16(phantom.data(), phantom.size(),
                                                options, out));

        // Scripts wandering across unrelated writing systems.
        auto scattered = utf16_bytes({ 0x4E2D, 0x0440, 0x05D0, 0x4E8C, 0x0441, 0x05D1 });
        SP_CHECK(!StringExtractor::decode_utf16(scattered.data(), scattered.size(),
                                                options, out));

        // Private use area and noncharacters are never real literals.
        auto pua = utf16_bytes({ 0xE000, 0xE001, 0xE002, 0xE003, 0xE004 });
        SP_CHECK(!StringExtractor::decode_utf16(pua.data(), pua.size(), options, out));

        auto noncharacter = utf16_bytes({ 'a', 'b', 'c', 0xFFFF, 'd' });
        SP_CHECK(!StringExtractor::decode_utf16(noncharacter.data(),
                                                noncharacter.size(), options, out));

        // An x86-64 pointer table, which is what was being reported as text.
        const std::vector<std::uint8_t> pointers = {
            0x00, 0x40, 0x04, 0x40, 0x01, 0x00, 0x00, 0x00,
            0x18, 0x50, 0x04, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };
        SP_CHECK(!StringExtractor::decode_utf16(pointers.data(), pointers.size(),
                                                options, out));

        // Unpaired surrogates are not valid UTF-16 at any length.
        const std::vector<std::uint8_t> lone_high = {
            0x00, 0xD8, 'a', 0x00, 'b', 0x00, 'c', 0x00, 0x00, 0x00 };
        SP_CHECK(!StringExtractor::decode_utf16(lone_high.data(), lone_high.size(),
                                                options, out));

        const std::vector<std::uint8_t> lone_low = {
            0x00, 0xDC, 'a', 0x00, 'b', 0x00, 'c', 0x00, 0x00, 0x00 };
        SP_CHECK(!StringExtractor::decode_utf16(lone_low.data(), lone_low.size(),
                                                options, out));
    }
}
