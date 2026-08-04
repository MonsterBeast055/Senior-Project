#pragma once
//
// StructuralAnalysis.h - Recovering high-level shape from a CFG.
//
// Between raw disassembly and full decompilation there is a large, achievable
// middle ground: recognising that a block group is an if/else, a while loop, or
// a switch. That structure is most of what makes disassembly explicable, and it
// is far cheaper than a real decompiler.
//
#include "sp/analysis/CFG.h"
#include "sp/analysis/Function.h"
#include "sp/analysis/LoopAnalysis.h"
#include "sp/core/Types.h"

#include <memory>
#include <string>
#include <vector>

namespace sp::lift {

enum class RegionKind : std::uint8_t {
    Block = 0,      // single basic block
    Sequence,       // straight-line run of regions
    IfThen,
    IfThenElse,
    While,          // loop with the test at the top
    DoWhile,        // loop with the test at the bottom
    Switch,         // resolved jump table
    Irreducible,    // no structured form found; fall back to raw blocks
};

const char* to_string(RegionKind k);

// Regions nest, forming a tree over the CFG. The leaves are basic blocks and
// the root is the whole function.
struct Region {
    RegionKind kind = RegionKind::Block;

    core::VA entry = core::kInvalidVA;
    std::vector<core::VA> blocks;
    std::vector<std::unique_ptr<Region>> children;

    // Block holding the controlling comparison, for conditionals and loops.
    core::VA condition_block = core::kInvalidVA;

    // Human-readable summary of the condition, when recoverable.
    std::string condition_expr;
};

class StructuralAnalysis {
public:
    // Structural analysis by interval collapsing: repeatedly match known
    // patterns and reduce them until only the root remains. Blocks that never
    // match are emitted as Irreducible rather than forced into a wrong shape.
    std::unique_ptr<Region> analyze(const analysis::CFG& cfg,
                                    const analysis::DominatorTree& doms,
                                    const analysis::LoopAnalysis& loops);

    // Cyclomatic complexity: edges - nodes + 2. A cheap difficulty metric.
    static std::size_t cyclomatic_complexity(const analysis::CFG& cfg);
};

} // namespace sp::lift
