#pragma once
//
// Confidence.h - Graded belief instead of boolean assertion.
//
// Traditional disassemblers commit to a decision (these bytes are code) and
// discard the fact that it was a guess. We keep the grade so that the UI can
// visually distinguish solid ground from speculation, the AI layer can weight
// its reasoning, and later passes can override low-confidence conclusions
// without fighting the earlier ones.
//
#include <cstdint>

namespace sp::core {

enum class Confidence : std::uint8_t {
    None    = 0,  // no opinion
    Low     = 1,  // speculative (e.g. linear sweep over unclaimed bytes)
    Medium  = 2,  // plausible (e.g. heuristic prologue match)
    High    = 3,  // strong structural evidence (e.g. direct call target)
    Certain = 4,  // ground truth (e.g. PE entry point, user assertion)
};

const char* to_string(Confidence c);

// Confidence is a lattice: combining two independent sources of evidence
// yields at least the stronger of the two.
inline Confidence combine(Confidence a, Confidence b)
{
    return (a > b) ? a : b;
}

// How a byte range is classified. Deliberately not a bool: the ambiguous
// middle is where real binaries live (jump tables, inline data, padding).
enum class ByteClass : std::uint8_t {
    Unknown = 0,      // never examined
    ProbablyData,     // looks like data, low confidence
    ProbablyCode,     // decoded cleanly but reached only by speculation
    Code,             // decoded and reached through trusted control flow
    Data,             // known data (literal pool, jump table, relocation)
    Padding,          // alignment filler between functions
};

const char* to_string(ByteClass bc);

} // namespace sp::core
