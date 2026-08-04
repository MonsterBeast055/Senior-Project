#include "sp/analysis/LoopAnalysis.h"

namespace sp::analysis {

void DominatorTree::build(const CFG& cfg)
{
    // TODO: Lengauer-Tarjan over cfg.reverse_post_order(). The iterative
    // Cooper-Harvey-Kennedy formulation is simpler and fast enough at the scale
    // of a single function, so prefer it unless profiling says otherwise.
    (void)cfg;
}

std::optional<core::VA> DominatorTree::immediate_dominator(core::VA block) const
{
    auto it = idom_.find(block);
    if (it == idom_.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool DominatorTree::dominates(core::VA a, core::VA b) const
{
    // Walk up the dominator tree from b looking for a.
    core::VA current = b;
    while (true) {
        if (current == a) {
            return true;
        }
        auto parent = immediate_dominator(current);
        if (!parent.has_value() || *parent == current) {
            return false;
        }
        current = *parent;
    }
}

const std::vector<core::VA>* DominatorTree::children_of(core::VA block) const
{
    auto it = children_.find(block);
    return it == children_.end() ? nullptr : &it->second;
}

std::set<core::VA> DominatorTree::dominance_frontier(core::VA block) const
{
    // TODO: standard Cytron dominance-frontier computation. Needed to find where
    // divergent paths re-converge, which is how if/else regions are recovered.
    (void)block;
    return {};
}

void LoopAnalysis::analyze(const CFG& cfg, const DominatorTree& doms)
{
    // TODO: a back edge is an edge b -> h where h dominates b. The natural loop
    // for that back edge is h plus every block that reaches b without passing
    // through h. Loops sharing a header are merged; nesting comes from body
    // containment. Loops with multiple headers are irreducible - mark them
    // rather than forcing a structured shape onto them.
    (void)cfg; (void)doms;
    loops_.clear();
    block_to_loop_.clear();
}

const Loop* LoopAnalysis::loop_containing(core::VA block) const
{
    auto it = block_to_loop_.find(block);
    if (it == block_to_loop_.end()) {
        return nullptr;
    }
    return &loops_[it->second];
}

std::size_t LoopAnalysis::max_depth() const
{
    std::size_t deepest = 0;
    for (const Loop& loop : loops_) {
        if (loop.depth > deepest) {
            deepest = loop.depth;
        }
    }
    return deepest;
}

} // namespace sp::analysis
