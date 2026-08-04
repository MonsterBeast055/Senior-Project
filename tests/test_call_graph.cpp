#include "test_harness.h"

#include "sp/analysis/CallGraph.h"

#include <algorithm>
#include <vector>

using namespace sp;
using namespace sp::analysis;

namespace {

// Position of `va` in `order`, or npos.
std::size_t position(const std::vector<core::VA>& order, core::VA va)
{
    for (std::size_t i = 0; i < order.size(); ++i) {
        if (order[i] == va) {
            return i;
        }
    }
    return static_cast<std::size_t>(-1);
}

bool before(const std::vector<core::VA>& order, core::VA a, core::VA b)
{
    return position(order, a) < position(order, b);
}

} // namespace

void test_call_graph()
{
    SP_TEST("call graph: leaves are ordered before their callers");
    {
        // main -> helper -> leaf
        CallGraph graph;
        graph.add_edge(0x1000, 0x2000);
        graph.add_edge(0x2000, 0x3000);

        const auto order = graph.reverse_topological_order();
        SP_CHECK_EQ(order.size(), std::size_t{ 3 });

        // This is the whole point: by the time the lifting agent reaches a
        // caller, its callees already have summaries.
        SP_CHECK(before(order, 0x3000, 0x2000));
        SP_CHECK(before(order, 0x2000, 0x1000));
    }

    SP_TEST("call graph: diamond respects both paths");
    {
        //   main -> a -> shared
        //   main -> b -> shared
        CallGraph graph;
        graph.add_edge(0x1000, 0x2000);
        graph.add_edge(0x1000, 0x3000);
        graph.add_edge(0x2000, 0x4000);
        graph.add_edge(0x3000, 0x4000);

        const auto order = graph.reverse_topological_order();
        SP_CHECK_EQ(order.size(), std::size_t{ 4 });
        SP_CHECK(before(order, 0x4000, 0x2000));
        SP_CHECK(before(order, 0x4000, 0x3000));
        SP_CHECK(before(order, 0x2000, 0x1000));
        SP_CHECK(before(order, 0x3000, 0x1000));
    }

    SP_TEST("call graph: mutual recursion is reported, not looped forever");
    {
        // a <-> b, both called by main
        CallGraph graph;
        graph.add_edge(0x1000, 0x2000);
        graph.add_edge(0x2000, 0x3000);
        graph.add_edge(0x3000, 0x2000);

        std::vector<std::vector<core::VA>> cycles;
        const auto order = graph.reverse_topological_order(&cycles);

        SP_CHECK_EQ(order.size(), std::size_t{ 3 });

        // The recursion group must be surfaced so the caller knows the cycle was
        // broken arbitrarily.
        SP_CHECK_EQ(cycles.size(), std::size_t{ 1 });
        if (cycles.size() == 1) {
            SP_CHECK_EQ(cycles[0].size(), std::size_t{ 2 });
        }

        // The pair still comes out before main.
        SP_CHECK(before(order, 0x2000, 0x1000));
        SP_CHECK(before(order, 0x3000, 0x1000));
    }

    SP_TEST("call graph: direct self-recursion is reported");
    {
        CallGraph graph;
        graph.add_edge(0x1000, 0x2000);
        graph.add_edge(0x2000, 0x2000);

        std::vector<std::vector<core::VA>> cycles;
        const auto order = graph.reverse_topological_order(&cycles);

        SP_CHECK_EQ(order.size(), std::size_t{ 2 });
        SP_CHECK_EQ(cycles.size(), std::size_t{ 1 });
        SP_CHECK(before(order, 0x2000, 0x1000));
    }

    SP_TEST("call graph: leaves, roots and transitive callees");
    {
        CallGraph graph;
        graph.add_edge(0x1000, 0x2000);
        graph.add_edge(0x2000, 0x3000);
        graph.add_edge(0x3000, 0x4000);

        const auto leaves = graph.leaf_functions();
        SP_CHECK_EQ(leaves.size(), std::size_t{ 1 });
        if (leaves.size() == 1) {
            SP_CHECK_EQ(leaves[0], core::VA{ 0x4000 });
        }

        const auto roots = graph.root_functions();
        SP_CHECK_EQ(roots.size(), std::size_t{ 1 });
        if (roots.size() == 1) {
            SP_CHECK_EQ(roots[0], core::VA{ 0x1000 });
        }

        // Depth limit is what keeps a context bundle inside its token budget.
        const auto depth1 = graph.transitive_callees(0x1000, 1);
        SP_CHECK_EQ(depth1.size(), std::size_t{ 1 });

        const auto depth2 = graph.transitive_callees(0x1000, 2);
        SP_CHECK_EQ(depth2.size(), std::size_t{ 2 });
    }

    SP_TEST("call graph: disconnected components are all included");
    {
        CallGraph graph;
        graph.add_edge(0x1000, 0x2000);
        graph.add_edge(0x5000, 0x6000);

        const auto order = graph.reverse_topological_order();
        SP_CHECK_EQ(order.size(), std::size_t{ 4 });
        SP_CHECK(before(order, 0x2000, 0x1000));
        SP_CHECK(before(order, 0x6000, 0x5000));
    }

    SP_TEST("call graph: empty graph is handled");
    {
        CallGraph graph;
        SP_CHECK(graph.reverse_topological_order().empty());
        SP_CHECK_EQ(graph.function_count(), std::size_t{ 0 });
    }
}
