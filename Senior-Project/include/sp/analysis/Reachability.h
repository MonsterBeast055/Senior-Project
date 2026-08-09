#pragma once
//
// Reachability.h - Is this risky operation actually exposed to untrusted input?
//
// The distinction that separates an impactful finding from noise.
//
// A `strcpy` in a function nothing untrusted ever reaches is a code-quality
// remark. The same `strcpy` on a path from `ReadFile` or `recv` is a real
// finding, and the call path is the evidence.
//
// WHAT THIS IS NOT: full taint analysis. We do not track individual values
// through registers and memory, so we cannot prove attacker-controlled data
// reaches the sink's buffer argument - only that a call path exists between a
// function that reads untrusted input and a function that performs a risky
// operation. That is a necessary condition for exploitability, not a sufficient
// one, and every finding must be worded to say so.
//
// Being honest about that boundary is the whole point. A tool that reports
// "CRITICAL" on graph reachability alone is worse than no tool, because someone
// will believe it.
//
#include "sp/analysis/ApiClassifier.h"
#include "sp/analysis/CallGraph.h"
#include "sp/analysis/Function.h"
#include "sp/core/Types.h"

#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace sp::analysis {

// An untrusted-input entry point found in a specific function.
struct SourceSite {
    core::VA function = core::kInvalidVA;
    InputSource source = InputSource::None;
    std::string api;             // qualified name, e.g. "kernel32.dll!ReadFile"
};

// A risky operation found in a specific function.
struct SinkSite {
    core::VA function = core::kInvalidVA;
    SinkKind kind = SinkKind::None;
    std::string api;
};

// A sink together with what we could establish about its exposure.
struct ReachabilityResult {
    core::VA function = core::kInvalidVA;
    SinkKind sink = SinkKind::None;
    std::string sink_api;

    // Could untrusted input reach this function through the call graph?
    bool reachable_from_input = false;

    // Which kinds of input, when reachable.
    std::set<InputSource> sources;

    // Shortest call path from an input-reading function to this one, as
    // function entry addresses. The evidence a reader needs to judge the
    // finding; without it a claim of reachability is unverifiable.
    std::vector<core::VA> path;

    // Severity of the sink alone, before exposure is considered.
    SinkSeverity base_severity = SinkSeverity::Informational;

    // Severity after composing reachability with the sink kind. This is the
    // number a report should lead with, and it is derived rather than asserted.
    SinkSeverity effective_severity = SinkSeverity::Informational;

    // Why the analysis cannot go further. Always populated for reachable
    // findings, so no consumer can present one as proven exploitable.
    std::string limitation;
};

struct ReachabilityOptions {
    // Cap on call-graph depth from a source. Beyond a handful of hops the claim
    // "untrusted input reaches here" stops being meaningful.
    std::size_t max_depth = 8;

    // Treat indirect calls as edges to every known function. Enormously
    // over-approximate; off by default because it turns almost everything
    // "reachable" and destroys the signal.
    bool assume_indirect_calls_reach_anything = false;

    // Report sinks that are not reachable, marked informational. Useful for a
    // complete inventory; noisy for a summary.
    bool include_unreachable = true;
};

class Reachability {
public:
    void analyze(const std::map<core::VA, Function>& functions,
                const CallGraph& call_graph,
                const ReachabilityOptions& options);

    // Every sink found, reachable or not.
    const std::vector<ReachabilityResult>& results() const { return results_; }

    // Only the reachable ones, worst severity first. What a report leads with.
    std::vector<const ReachabilityResult*> impactful() const;

    const std::vector<SourceSite>& sources() const { return sources_; }
    const std::vector<SinkSite>& sinks() const { return sinks_; }

    // Per-function view, for annotating the function JSON.
    bool is_reachable_from_input(core::VA function) const;
    const std::set<InputSource>* sources_reaching(core::VA function) const;

    void clear();

    // Compose sink severity with exposure.
    //
    // An unbounded copy reachable from untrusted input is the real thing. The
    // same call with no reachable path is a code-quality note. Deriving severity
    // from both is what makes the number defensible.
    static SinkSeverity compose_severity(SinkKind kind, bool reachable);

private:
    std::vector<SourceSite> sources_;
    std::vector<SinkSite> sinks_;
    std::vector<ReachabilityResult> results_;

    // function -> which input kinds can reach it
    std::unordered_map<core::VA, std::set<InputSource>> reaching_;

    // function -> predecessor on the shortest path from a source
    std::unordered_map<core::VA, core::VA> came_from_;
};

} // namespace sp::analysis
