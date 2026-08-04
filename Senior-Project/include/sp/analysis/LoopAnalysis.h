#pragma once
//
// LoopAnalysis.h - Dominators, natural loops, nesting.
//
// Loop structure is what turns a block soup into something explicable. A model
// told "blocks 4-7 form a loop over a counter, exiting when the counter reaches
// the value in edx" produces far better output than one handed the same blocks
// with no structure at all.
//
#include "CFG.h"
#include "sp/core/Types.h"

#include <map>
#include <optional>
#include <set>
#include <vector>

namespace sp::analysis {

// Immediate-dominator tree, computed with Lengauer-Tarjan.
class DominatorTree {
public:
    void build(const CFG& cfg);

    std::optional<core::VA> immediate_dominator(core::VA block) const;
    bool dominates(core::VA a, core::VA b) const;

    const std::vector<core::VA>* children_of(core::VA block) const;

    // Where control paths re-converge. Needed to recover if/else structure.
    std::set<core::VA> dominance_frontier(core::VA block) const;

private:
    std::map<core::VA, core::VA> idom_;
    std::map<core::VA, std::vector<core::VA>> children_;
};

struct Loop {
    core::VA header = core::kInvalidVA;      // dominates all body blocks
    std::set<core::VA> body;
    std::vector<core::VA> back_edges;        // latches jumping to the header
    std::vector<core::VA> exit_blocks;

    std::optional<core::VA> parent_header;   // enclosing loop, if nested
    std::size_t depth = 0;

    // A single latch and single exit is the shape of a for/while loop; anything
    // else is irreducible and needs different handling.
    bool is_reducible = true;
};

class LoopAnalysis {
public:
    // Natural loops from back edges in the dominator tree.
    void analyze(const CFG& cfg, const DominatorTree& doms);

    const std::vector<Loop>& loops() const { return loops_; }

    const Loop* loop_containing(core::VA block) const;

    // Deepest nesting level in the function. A useful complexity signal for
    // both the UI and for deciding how much context the model needs.
    std::size_t max_depth() const;

private:
    std::vector<Loop> loops_;
    std::map<core::VA, std::size_t> block_to_loop_;
};

} // namespace sp::analysis
