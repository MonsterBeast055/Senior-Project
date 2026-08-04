#pragma once
//
// CodeMap.h - Byte-level code/data classification with confidence.
//
// A binary's executable sections are not pure code. They contain jump tables,
// string literals, alignment padding and, in obfuscated binaries, deliberate
// garbage. Disassembling blindly produces convincing nonsense.
//
// CodeMap tracks what we believe each byte is and how sure we are, so that a
// speculative linear sweep can be overridden later by hard evidence without
// re-analysing the whole image.
//
#include "sp/core/Types.h"
#include "sp/core/Confidence.h"
#include "sp/core/Provenance.h"

#include <cstddef>
#include <map>
#include <vector>

namespace sp::disasm {

struct ClassifiedRange {
    core::VA start = core::kInvalidVA;
    core::VA end = core::kInvalidVA;   // exclusive
    core::ByteClass klass = core::ByteClass::Unknown;
    core::Confidence confidence = core::Confidence::None;
    core::ProvenanceKind reason = core::ProvenanceKind::Unknown;

    std::size_t length() const { return static_cast<std::size_t>(end - start); }
    bool contains(core::VA va) const { return va >= start && va < end; }
};

class CodeMap {
public:
    // Classify [start, end). A weaker claim never overwrites a stronger one,
    // so speculation cannot clobber ground truth regardless of pass ordering.
    void classify(core::VA start, core::VA end,
                  core::ByteClass klass,
                  core::Confidence confidence,
                  core::ProvenanceKind reason);

    // Force a classification regardless of existing confidence. For user
    // assertions and for retracting a proven-wrong region.
    void reclassify_forced(core::VA start, core::VA end,
                           core::ByteClass klass,
                           core::ProvenanceKind reason);

    core::ByteClass class_of(core::VA va) const;
    core::Confidence confidence_of(core::VA va) const;
    const ClassifiedRange* range_containing(core::VA va) const;

    bool is_claimed(core::VA va) const;

    // Byte ranges still unexplained after all passes. These are what a linear
    // sweep should attack, and what the UI should flag as unanalysed.
    std::vector<ClassifiedRange> unclaimed_ranges(core::VA start, core::VA end) const;

    const std::map<core::VA, ClassifiedRange>& ranges() const { return ranges_; }

    // Coverage statistic: fraction of [start, end) classified as code.
    double code_coverage(core::VA start, core::VA end) const;

private:
    // Keyed by start address, non-overlapping, sorted.
    std::map<core::VA, ClassifiedRange> ranges_;
};

} // namespace sp::disasm
