#pragma once
//
// CFG.h - Control-flow graph of a single function.
//
// Scoped per function rather than one graph per image: it is the unit the UI
// renders, the unit the model reasons about, and the unit that can be
// re-analysed in isolation when an inference invalidates it.
//
#include "BasicBlock.h"
#include "sp/core/Types.h"
#include "sp/db/EntityId.h"

#include <cstddef>
#include <map>
#include <optional>
#include <vector>

namespace sp::analysis {

class CFG {
public:
    void add_block(BasicBlock block);

    BasicBlock* block_at(core::VA start);
    const BasicBlock* block_at(core::VA start) const;

    // Block whose range covers `va`, even mid-block.
    const BasicBlock* block_containing(core::VA va) const;

    void set_entry(core::VA va) { entry_ = va; }
    core::VA entry() const { return entry_; }
    const BasicBlock* entry_block() const { return block_at(entry_); }

    void add_edge(core::VA from, Edge edge);

    // Blocks in address order.
    std::vector<const BasicBlock*> blocks() const;

    // Reverse post-order from the entry: the correct visitation order for
    // forward dataflow, and a reasonable top-to-bottom layout order for the UI.
    std::vector<core::VA> reverse_post_order() const;

    // Blocks unreachable from the entry. Often a sign of a bad decode or of an
    // unresolved indirect branch, so worth surfacing rather than hiding.
    std::vector<core::VA> unreachable_blocks() const;

    std::size_t block_count() const { return blocks_.size(); }
    std::size_t edge_count() const;
    bool empty() const { return blocks_.empty(); }

private:
    std::map<core::VA, BasicBlock> blocks_;
    core::VA entry_ = core::kInvalidVA;
};

} // namespace sp::analysis
