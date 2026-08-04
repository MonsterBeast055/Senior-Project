#include "sp/disasm/CodeMap.h"

namespace sp::disasm {

void CodeMap::classify(core::VA start, core::VA end,
                       core::ByteClass klass,
                       core::Confidence confidence,
                       core::ProvenanceKind reason)
{
    if (start >= end) {
        return;
    }

    // Weaker evidence must not overwrite stronger conclusions, which makes the
    // result independent of pass ordering.
    const ClassifiedRange* existing = range_containing(start);
    if (existing != nullptr && existing->confidence > confidence) {
        return;
    }

    ClassifiedRange range;
    range.start = start;
    range.end = end;
    range.klass = klass;
    range.confidence = confidence;
    range.reason = reason;
    ranges_[start] = range;
}

void CodeMap::reclassify_forced(core::VA start, core::VA end,
                                core::ByteClass klass,
                                core::ProvenanceKind reason)
{
    if (start >= end) {
        return;
    }

    // Drop anything overlapping, then assert the new classification.
    auto it = ranges_.lower_bound(start);
    while (it != ranges_.end() && it->first < end) {
        it = ranges_.erase(it);
    }

    ClassifiedRange range;
    range.start = start;
    range.end = end;
    range.klass = klass;
    range.confidence = core::base_confidence(reason);
    range.reason = reason;
    ranges_[start] = range;
}

const ClassifiedRange* CodeMap::range_containing(core::VA va) const
{
    auto it = ranges_.upper_bound(va);
    if (it == ranges_.begin()) {
        return nullptr;
    }
    --it;
    return it->second.contains(va) ? &it->second : nullptr;
}

core::ByteClass CodeMap::class_of(core::VA va) const
{
    const ClassifiedRange* range = range_containing(va);
    return range == nullptr ? core::ByteClass::Unknown : range->klass;
}

core::Confidence CodeMap::confidence_of(core::VA va) const
{
    const ClassifiedRange* range = range_containing(va);
    return range == nullptr ? core::Confidence::None : range->confidence;
}

bool CodeMap::is_claimed(core::VA va) const
{
    return range_containing(va) != nullptr;
}

std::vector<ClassifiedRange> CodeMap::unclaimed_ranges(core::VA start, core::VA end) const
{
    std::vector<ClassifiedRange> gaps;
    core::VA cursor = start;

    for (auto it = ranges_.lower_bound(start); it != ranges_.end() && it->first < end; ++it) {
        if (it->second.start > cursor) {
            ClassifiedRange gap;
            gap.start = cursor;
            gap.end = it->second.start;
            gaps.push_back(gap);
        }
        cursor = (it->second.end > cursor) ? it->second.end : cursor;
    }

    if (cursor < end) {
        ClassifiedRange gap;
        gap.start = cursor;
        gap.end = end;
        gaps.push_back(gap);
    }
    return gaps;
}

double CodeMap::code_coverage(core::VA start, core::VA end) const
{
    if (start >= end) {
        return 0.0;
    }

    std::size_t code_bytes = 0;
    for (auto it = ranges_.lower_bound(start); it != ranges_.end() && it->first < end; ++it) {
        const ClassifiedRange& range = it->second;
        if (range.klass != core::ByteClass::Code && range.klass != core::ByteClass::ProbablyCode) {
            continue;
        }
        const core::VA lo = (range.start > start) ? range.start : start;
        const core::VA hi = (range.end < end) ? range.end : end;
        if (hi > lo) {
            code_bytes += static_cast<std::size_t>(hi - lo);
        }
    }
    return static_cast<double>(code_bytes) / static_cast<double>(end - start);
}

} // namespace sp::disasm
