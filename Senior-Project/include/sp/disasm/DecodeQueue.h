#pragma once
//
// DecodeQueue.h - Worklist driving recursive-descent disassembly.
//
// Linear sweep alone misdecodes real binaries; recursive descent alone misses
// code reachable only through indirect calls. The disassembler runs descent
// from every trusted entry point first, then sweeps whatever bytes remain
// unclaimed at strictly lower confidence.
//
// Each queued address carries the evidence that put it there, so the resulting
// instructions inherit honest provenance.
//
#include "sp/core/Types.h"
#include "sp/core/Provenance.h"

#include <cstddef>
#include <queue>
#include <unordered_set>

namespace sp::disasm {

struct DecodeRequest {
    core::VA address = core::kInvalidVA;
    core::ProvenanceKind reason = core::ProvenanceKind::Unknown;
    core::VA source = core::kInvalidVA;  // instruction that referenced it

    // Priority: trusted evidence is decoded before speculation, so that
    // speculative decodes can never claim bytes that solid evidence wants.
    core::Confidence priority = core::Confidence::None;
};

class DecodeQueue {
public:
    // Enqueue unless this address was already processed.
    void push(DecodeRequest request);

    // Highest-confidence pending request.
    bool pop(DecodeRequest& out);

    bool empty() const;
    std::size_t pending() const;

    // Already decoded or already queued.
    bool seen(core::VA address) const;

    // Allow an address to be revisited, e.g. after a retraction.
    void forget(core::VA address);

    void clear();

private:
    struct Compare {
        bool operator()(const DecodeRequest& a, const DecodeRequest& b) const
        {
            return a.priority < b.priority;  // max-heap on confidence
        }
    };

    std::priority_queue<DecodeRequest, std::vector<DecodeRequest>, Compare> queue_;
    std::unordered_set<core::VA> seen_;
};

} // namespace sp::disasm
