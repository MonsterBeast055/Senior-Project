#pragma once
//
// CallGraph.h - Function-level call relationships.
//
// Distinct from the per-function CFGs. Its main use here is ordering: a reverse
// topological walk lets the model summarise leaf functions first and then reuse
// those summaries as context when it reaches their callers, which is
// dramatically more effective than analysing functions in address order.
//
#include "Function.h"
#include "sp/core/Types.h"

#include <map>
#include <set>
#include <vector>

namespace sp::analysis {

class CallGraph {
public:
    void build(const std::map<core::VA, Function>& functions);

    void add_edge(core::VA caller, core::VA callee);

    const std::set<core::VA>* callees_of(core::VA function) const;
    const std::set<core::VA>* callers_of(core::VA function) const;

    // Functions that call nothing. Analysed first during bottom-up lifting.
    std::vector<core::VA> leaf_functions() const;

    // Functions nobody calls. Real entry points, or evidence of missing
    // indirect-call resolution.
    std::vector<core::VA> root_functions() const;

    // Callees before callers. Cycles (recursion) are broken deterministically
    // and reported through `out_cycles`.
    std::vector<core::VA> reverse_topological_order(
        std::vector<std::vector<core::VA>>* out_cycles = nullptr) const;

    // Transitive callees, for building a context bundle with a call-depth
    // budget rather than dumping the whole program.
    std::set<core::VA> transitive_callees(core::VA function, std::size_t max_depth) const;

    std::size_t function_count() const { return callees_.size(); }

private:
    std::map<core::VA, std::set<core::VA>> callees_;
    std::map<core::VA, std::set<core::VA>> callers_;
};

} // namespace sp::analysis
