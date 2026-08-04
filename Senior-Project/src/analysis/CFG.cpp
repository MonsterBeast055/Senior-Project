#include "sp/analysis/CFG.h"

#include <algorithm>
#include <unordered_set>

namespace sp::analysis {

void CFG::add_block(BasicBlock block)
{
    const core::VA start = block.start;
    blocks_[start] = std::move(block);
}

BasicBlock* CFG::block_at(core::VA start)
{
    auto it = blocks_.find(start);
    return it == blocks_.end() ? nullptr : &it->second;
}

const BasicBlock* CFG::block_at(core::VA start) const
{
    auto it = blocks_.find(start);
    return it == blocks_.end() ? nullptr : &it->second;
}

const BasicBlock* CFG::block_containing(core::VA va) const
{
    auto it = blocks_.upper_bound(va);
    if (it == blocks_.begin()) {
        return nullptr;
    }
    --it;
    if (va >= it->second.start && va < it->second.end) {
        return &it->second;
    }
    return nullptr;
}

void CFG::add_edge(core::VA from, Edge edge)
{
    BasicBlock* source = block_at(from);
    if (source == nullptr) {
        return;
    }
    source->successors.push_back(edge);

    BasicBlock* target = block_at(edge.target);
    if (target != nullptr) {
        target->predecessors.push_back(from);
    }
}

std::vector<const BasicBlock*> CFG::blocks() const
{
    std::vector<const BasicBlock*> result;
    result.reserve(blocks_.size());
    for (const auto& [address, block] : blocks_) {
        result.push_back(&block);
    }
    return result;
}

std::vector<core::VA> CFG::reverse_post_order() const
{
    std::vector<core::VA> order;
    if (entry_ == core::kInvalidVA || blocks_.empty()) {
        return order;
    }

    // Iterative DFS post-order, then reverse. Iterative rather than recursive
    // because deeply nested functions would otherwise risk a stack overflow.
    std::unordered_set<core::VA> visited;
    std::vector<std::pair<core::VA, std::size_t>> stack;
    stack.emplace_back(entry_, 0);
    visited.insert(entry_);

    while (!stack.empty()) {
        auto& [address, index] = stack.back();
        const BasicBlock* block = block_at(address);

        if (block == nullptr || index >= block->successors.size()) {
            order.push_back(address);
            stack.pop_back();
            continue;
        }

        const core::VA next = block->successors[index].target;
        ++index;

        if (visited.insert(next).second && block_at(next) != nullptr) {
            stack.emplace_back(next, 0);
        }
    }

    std::reverse(order.begin(), order.end());
    return order;
}

std::vector<core::VA> CFG::unreachable_blocks() const
{
    const std::vector<core::VA> reachable_order = reverse_post_order();
    const std::unordered_set<core::VA> reachable(reachable_order.begin(), reachable_order.end());

    std::vector<core::VA> orphans;
    for (const auto& [address, block] : blocks_) {
        if (reachable.find(address) == reachable.end()) {
            orphans.push_back(address);
        }
    }
    return orphans;
}

std::size_t CFG::edge_count() const
{
    std::size_t total = 0;
    for (const auto& [address, block] : blocks_) {
        total += block.successors.size();
    }
    return total;
}

} // namespace sp::analysis
