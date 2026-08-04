#include "sp/core/Provenance.h"

#include <algorithm>

namespace sp::core {

const char* to_string(ProvenanceKind k)
{
    switch (k) {
    case ProvenanceKind::EntryPoint:       return "entry-point";
    case ProvenanceKind::PeExport:         return "pe-export";
    case ProvenanceKind::PeUnwindInfo:     return "pe-unwind-info";
    case ProvenanceKind::TlsCallback:      return "tls-callback";
    case ProvenanceKind::DebugSymbol:      return "debug-symbol";
    case ProvenanceKind::DirectCallTarget: return "direct-call-target";
    case ProvenanceKind::DirectJumpTarget: return "direct-jump-target";
    case ProvenanceKind::FallThrough:      return "fall-through";
    case ProvenanceKind::JumpTableEntry:   return "jump-table-entry";
    case ProvenanceKind::ProloguePattern:  return "prologue-pattern";
    case ProvenanceKind::LinearSweep:      return "linear-sweep";
    case ProvenanceKind::RelocationTarget: return "relocation-target";
    case ProvenanceKind::UserSpecified:    return "user-specified";
    case ProvenanceKind::AiInferred:       return "ai-inferred";
    case ProvenanceKind::Unknown:
    default:                               return "unknown";
    }
}

Confidence base_confidence(ProvenanceKind k)
{
    switch (k) {
    // Stated by the file format or by a human: not open to debate.
    case ProvenanceKind::EntryPoint:
    case ProvenanceKind::PeExport:
    case ProvenanceKind::PeUnwindInfo:
    case ProvenanceKind::TlsCallback:
    case ProvenanceKind::DebugSymbol:
    case ProvenanceKind::UserSpecified:
        return Confidence::Certain;

    // Structural evidence from control flow we already trust.
    case ProvenanceKind::DirectCallTarget:
    case ProvenanceKind::DirectJumpTarget:
    case ProvenanceKind::FallThrough:
    case ProvenanceKind::JumpTableEntry:
        return Confidence::High;

    // Pattern matching: usually right, occasionally embarrassing.
    case ProvenanceKind::ProloguePattern:
    case ProvenanceKind::RelocationTarget:
        return Confidence::Medium;

    // A guess, and recorded as one. Model output stays provisional until a
    // human accepts it.
    case ProvenanceKind::LinearSweep:
    case ProvenanceKind::AiInferred:
        return Confidence::Low;

    case ProvenanceKind::Unknown:
    default:
        return Confidence::None;
    }
}

void ProvenanceSet::add(Provenance p)
{
    if (p.confidence == Confidence::None) {
        p.confidence = base_confidence(p.kind);
    }
    records_.push_back(p);
}

void ProvenanceSet::retract_kind(ProvenanceKind k)
{
    for (auto& record : records_) {
        if (record.kind == k) {
            record.retracted = true;
        }
    }
}

Confidence ProvenanceSet::effective_confidence() const
{
    Confidence best = Confidence::None;
    for (const auto& record : records_) {
        if (!record.retracted) {
            best = combine(best, record.confidence);
        }
    }
    return best;
}

const Provenance* ProvenanceSet::strongest() const
{
    const Provenance* best = nullptr;
    for (const auto& record : records_) {
        if (record.retracted) {
            continue;
        }
        if (best == nullptr || record.confidence > best->confidence) {
            best = &record;
        }
    }
    return best;
}

bool ProvenanceSet::has_kind(ProvenanceKind k) const
{
    return std::any_of(records_.begin(), records_.end(),
                       [k](const Provenance& p) { return p.kind == k && !p.retracted; });
}

} // namespace sp::core
