#include "test_harness.h"

#include "sp/analysis/CFG.h"

using namespace sp::core;
using namespace sp::analysis;

namespace {

BasicBlock make_block(VA start, VA end)
{
    BasicBlock block;
    block.start = start;
    block.end = end;
    return block;
}

// entry -> a, entry -> b, a -> c, b -> c, plus an orphan.
CFG make_diamond()
{
    CFG cfg;
    cfg.add_block(make_block(0x1000, 0x1010));  // entry
    cfg.add_block(make_block(0x1010, 0x1020));  // a
    cfg.add_block(make_block(0x1020, 0x1030));  // b
    cfg.add_block(make_block(0x1030, 0x1040));  // c
    cfg.add_block(make_block(0x2000, 0x2010));  // orphan
    cfg.set_entry(0x1000);

    cfg.add_edge(0x1000, { 0x1010, EdgeKind::Taken, Confidence::High });
    cfg.add_edge(0x1000, { 0x1020, EdgeKind::FallThrough, Confidence::High });
    cfg.add_edge(0x1010, { 0x1030, EdgeKind::Jump, Confidence::High });
    cfg.add_edge(0x1020, { 0x1030, EdgeKind::FallThrough, Confidence::High });
    return cfg;
}

} // namespace

void test_cfg()
{
    SP_TEST("cfg: block lookup by containment");
    {
        const CFG cfg = make_diamond();
        const BasicBlock* block = cfg.block_containing(0x1018);
        SP_CHECK(block != nullptr);
        if (block != nullptr) {
            SP_CHECK_EQ(block->start, VA{ 0x1010 });
        }
        SP_CHECK(cfg.block_containing(0x1500) == nullptr);
    }

    SP_TEST("cfg: edges are wired in both directions");
    {
        const CFG cfg = make_diamond();
        const BasicBlock* join = cfg.block_at(0x1030);
        SP_CHECK(join != nullptr);
        if (join != nullptr) {
            SP_CHECK_EQ(join->predecessors.size(), std::size_t{ 2 });
        }
        SP_CHECK_EQ(cfg.edge_count(), std::size_t{ 4 });
    }

    SP_TEST("cfg: reverse post-order starts at the entry and precedes successors");
    {
        const CFG cfg = make_diamond();
        const auto order = cfg.reverse_post_order();
        SP_CHECK(!order.empty());
        if (!order.empty()) {
            SP_CHECK_EQ(order.front(), VA{ 0x1000 });
        }
        // The join block must come after both of its predecessors.
        SP_CHECK_EQ(order.size(), std::size_t{ 4 });
        if (order.size() == 4) {
            SP_CHECK_EQ(order.back(), VA{ 0x1030 });
        }
    }

    SP_TEST("cfg: unreachable blocks are surfaced, not hidden");
    {
        const CFG cfg = make_diamond();
        const auto orphans = cfg.unreachable_blocks();
        SP_CHECK_EQ(orphans.size(), std::size_t{ 1 });
        if (orphans.size() == 1) {
            SP_CHECK_EQ(orphans[0], VA{ 0x2000 });
        }
    }
}
