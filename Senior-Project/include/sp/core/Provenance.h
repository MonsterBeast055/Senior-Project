#pragma once
//
// Provenance.h - Why do we believe this?
//
// Every derived fact records the evidence that produced it. This is what makes
// analysis revisable: when a later pass proves that a region is a jump table,
// we can find every instruction that was only believed because of a linear
// sweep and retract it, without disturbing conclusions backed by unwind info
// or direct call edges.
//
#include "Types.h"
#include "Confidence.h"

#include <vector>

namespace sp::core {

enum class ProvenanceKind : std::uint8_t {
    Unknown = 0,

    // --- Ground truth from the file format -------------------------------
    EntryPoint,        // PE optional header AddressOfEntryPoint
    PeExport,          // named or ordinal export
    PeUnwindInfo,      // .pdata / RUNTIME_FUNCTION - very strong on x64
    TlsCallback,       // TLS directory callback array
    DebugSymbol,       // PDB / COFF symbol

    // --- Derived from control flow ---------------------------------------
    DirectCallTarget,  // reached by a call with an immediate operand
    DirectJumpTarget,  // reached by a jmp/jcc with an immediate operand
    FallThrough,       // sequentially follows a non-terminating instruction
    JumpTableEntry,    // resolved indirect jump through a table

    // --- Heuristic --------------------------------------------------------
    ProloguePattern,   // matched a known function prologue signature
    LinearSweep,       // decoded by sweeping unclaimed bytes; weakest evidence
    RelocationTarget,  // appears as the target of a base relocation

    // --- External assertion ----------------------------------------------
    UserSpecified,     // a human said so; overrides everything
    AiInferred,        // produced by the model layer; must be marked as such
};

const char* to_string(ProvenanceKind k);

// The confidence a given kind of evidence carries on its own.
Confidence base_confidence(ProvenanceKind k);

struct Provenance {
    ProvenanceKind kind = ProvenanceKind::Unknown;

    // Address that generated this belief, where meaningful. For
    // DirectCallTarget this is the address of the call instruction; for
    // EntryPoint it is unused.
    VA source = kInvalidVA;

    Confidence confidence = Confidence::None;

    // Set when the belief has been retracted by a later pass. Retracted
    // records are kept rather than erased so the reasoning trail survives.
    bool retracted = false;
};

// A fact may accumulate several independent justifications. Effective
// confidence is the strongest surviving one.
class ProvenanceSet {
public:
    void add(Provenance p);

    // Retract every record produced by a given kind of evidence.
    void retract_kind(ProvenanceKind k);

    Confidence effective_confidence() const;

    // Strongest surviving record, or nullptr if there are none.
    const Provenance* strongest() const;

    bool has_kind(ProvenanceKind k) const;

    const std::vector<Provenance>& records() const { return records_; }

private:
    std::vector<Provenance> records_;
};

} // namespace sp::core
