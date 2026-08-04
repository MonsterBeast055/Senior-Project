#include "sp/analysis/CallGraph.h"

#include <algorithm>

namespace sp::analysis {

void CallGraph::add_edge(core::VA caller, core::VA callee)
{
    callees_[caller].insert(callee);
    callers_[callee].insert(caller);
    // Ensure both nodes exist even with no edges of their own.
    callees_.try_emplace(callee);
    callers_.try_emplace(caller);
}

void CallGraph::build(const std::map<core::VA, Function>& functions)
{
    callees_.clear();
    callers_.clear();

    for (const auto& [entry, function] : functions) {
        callees_.try_emplace(entry);
        callers_.try_emplace(entry);
        for (core::VA callee : function.callees) {
            add_edge(entry, callee);
        }
    }
}

const std::set<core::VA>* CallGraph::callees_of(core::VA function) const
{
    auto it = callees_.find(function);
    return it == callees_.end() ? nullptr : &it->second;
}

const std::set<core::VA>* CallGraph::callers_of(core::VA function) const
{
    auto it = callers_.find(function);
    return it == callers_.end() ? nullptr : &it->second;
}

std::vector<core::VA> CallGraph::leaf_functions() const
{
    std::vector<core::VA> leaves;
    for (const auto& [function, callees] : callees_) {
        if (callees.empty()) {
            leaves.push_back(function);
        }
    }
    return leaves;
}

std::vector<core::VA> CallGraph::root_functions() const
{
    std::vector<core::VA> roots;
    for (const auto& [function, callers] : callers_) {
        if (callers.empty()) {
            roots.push_back(function);
        }
    }
    return roots;
}

std::vector<core::VA> CallGraph::reverse_topological_order(
    std::vector<std::vector<core::VA>>* out_cycles) const
{
    // Tarjan's strongly-connected-components algorithm.
    //
    // Its emission order is already what we want: an SCC is emitted only after
    // every SCC reachable from it, so callees come out before callers. That is
    // exactly the order the lifting agent needs - by the time it reaches a
    // caller, its callees have summaries that can go in the prompt.
    //
    // Iterative rather than recursive: a deep call chain in a real binary would
    // otherwise risk a stack overflow.
    if (out_cycles != nullptr) {
        out_cycles->clear();
    }

    // Indexable adjacency, since the iterative form needs to resume mid-child.
    std::vector<core::VA> nodes;
    std::unordered_map<core::VA, std::size_t> node_index;
    nodes.reserve(callees_.size());
    for (const auto& entry : callees_) {
        node_index.emplace(entry.first, nodes.size());
        nodes.push_back(entry.first);
    }

    std::vector<std::vector<std::size_t>> adjacency(nodes.size());
    for (std::size_t i = 0; i < nodes.size(); ++i) {
        auto it = callees_.find(nodes[i]);
        if (it == callees_.end()) {
            continue;
        }
        for (core::VA callee : it->second) {
            auto found = node_index.find(callee);
            if (found != node_index.end()) {
                adjacency[i].push_back(found->second);
            }
        }
    }

    constexpr std::size_t kUnvisited = static_cast<std::size_t>(-1);

    std::vector<std::size_t> index(nodes.size(), kUnvisited);
    std::vector<std::size_t> lowlink(nodes.size(), 0);
    std::vector<char> on_stack(nodes.size(), 0);
    std::vector<std::size_t> scc_stack;
    std::vector<core::VA> order;
    order.reserve(nodes.size());

    std::size_t next_index = 0;

    struct Frame {
        std::size_t node;
        std::size_t child;
    };
    std::vector<Frame> work;

    for (std::size_t root = 0; root < nodes.size(); ++root) {
        if (index[root] != kUnvisited) {
            continue;
        }

        work.push_back({ root, 0 });

        while (!work.empty()) {
            Frame& frame = work.back();
            const std::size_t v = frame.node;

            if (frame.child == 0) {
                index[v] = next_index;
                lowlink[v] = next_index;
                ++next_index;
                scc_stack.push_back(v);
                on_stack[v] = 1;
            }

            bool descended = false;
            while (frame.child < adjacency[v].size()) {
                const std::size_t w = adjacency[v][frame.child];
                ++frame.child;

                if (index[w] == kUnvisited) {
                    work.push_back({ w, 0 });
                    descended = true;
                    break;
                }
                if (on_stack[w] != 0) {
                    lowlink[v] = std::min(lowlink[v], index[w]);
                }
            }
            if (descended) {
                continue;
            }

            // v is an SCC root: pop the component.
            if (lowlink[v] == index[v]) {
                std::vector<core::VA> component;
                while (true) {
                    const std::size_t w = scc_stack.back();
                    scc_stack.pop_back();
                    on_stack[w] = 0;
                    component.push_back(nodes[w]);
                    if (w == v) {
                        break;
                    }
                }

                // A component with more than one member is mutual recursion; so
                // is a single node that calls itself. Report both, because the
                // caller has to break the cycle when summarising bottom-up.
                const bool self_recursive =
                    component.size() == 1
                    && std::find(adjacency[v].begin(), adjacency[v].end(), v)
                           != adjacency[v].end();

                if (out_cycles != nullptr && (component.size() > 1 || self_recursive)) {
                    out_cycles->push_back(component);
                }

                // Deterministic order within a component so output is stable
                // across runs.
                std::sort(component.begin(), component.end());
                order.insert(order.end(), component.begin(), component.end());
            }

            work.pop_back();
            if (!work.empty()) {
                const std::size_t parent = work.back().node;
                lowlink[parent] = std::min(lowlink[parent], lowlink[v]);
            }
        }
    }

    return order;
}

std::set<core::VA> CallGraph::transitive_callees(core::VA function, std::size_t max_depth) const
{
    // Bounded BFS: the depth limit is what keeps a context bundle inside its
    // token budget on a densely connected binary.
    std::set<core::VA> result;
    std::vector<core::VA> frontier{ function };

    for (std::size_t depth = 0; depth < max_depth && !frontier.empty(); ++depth) {
        std::vector<core::VA> next;
        for (core::VA current : frontier) {
            const std::set<core::VA>* callees = callees_of(current);
            if (callees == nullptr) {
                continue;
            }
            for (core::VA callee : *callees) {
                if (result.insert(callee).second) {
                    next.push_back(callee);
                }
            }
        }
        frontier = std::move(next);
    }
    return result;
}

} // namespace sp::analysis
