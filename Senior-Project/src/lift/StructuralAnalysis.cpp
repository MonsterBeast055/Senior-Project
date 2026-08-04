#include "sp/lift/StructuralAnalysis.h"

namespace sp::lift {

const char* to_string(RegionKind k)
{
    switch (k) {
    case RegionKind::Block:       return "block";
    case RegionKind::Sequence:    return "sequence";
    case RegionKind::IfThen:      return "if-then";
    case RegionKind::IfThenElse:  return "if-then-else";
    case RegionKind::While:       return "while";
    case RegionKind::DoWhile:     return "do-while";
    case RegionKind::Switch:      return "switch";
    case RegionKind::Irreducible: return "irreducible";
    default:                      return "?";
    }
}

std::size_t StructuralAnalysis::cyclomatic_complexity(const analysis::CFG& cfg)
{
    if (cfg.empty()) {
        return 0;
    }
    // E - N + 2 for a single connected component.
    const std::size_t edges = cfg.edge_count();
    const std::size_t nodes = cfg.block_count();
    return (edges + 2 > nodes) ? (edges - nodes + 2) : 1;
}

std::unique_ptr<Region> StructuralAnalysis::analyze(const analysis::CFG& cfg,
                                                   const analysis::DominatorTree& doms,
                                                   const analysis::LoopAnalysis& loops)
{
    // TODO: structural analysis by interval collapsing. Repeatedly scan in
    // post-order for a matching pattern and reduce it to a single region:
    //   Sequence    a -> b, b has exactly one predecessor
    //   IfThen      cond with one branch rejoining the other
    //   IfThenElse  cond whose branches meet at a common successor
    //   While       loop header whose test is the first block
    //   DoWhile     loop whose test is in the latch
    //   Switch      resolved jump table fanning out to n cases
    // Anything left unmatched becomes Irreducible, holding its raw blocks.
    //
    // Emitting Irreducible honestly matters: a wrong structural claim misleads
    // the model far more than an admission that the shape was not recovered.
    (void)doms; (void)loops;

    auto root = std::make_unique<Region>();
    root->kind = RegionKind::Irreducible;
    root->entry = cfg.entry();
    for (const analysis::BasicBlock* block : cfg.blocks()) {
        root->blocks.push_back(block->start);
    }
    return root;
}

} // namespace sp::lift
