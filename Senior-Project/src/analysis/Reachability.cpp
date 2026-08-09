#include "sp/analysis/Reachability.h"

#include "sp/core/Log.h"

#include <algorithm>
#include <deque>

namespace sp::analysis {
namespace {

// Wording that keeps every finding honest about what was and was not proven.
//
// Graph reachability shows a call path exists. It does not show that
// attacker-controlled bytes reach the sink's buffer argument, nor that any
// length check between the two is absent or wrong. Saying so on every finding is
// not hedging - it is the difference between a tool a reviewer can trust and one
// that cries wolf.
constexpr const char* kReachableLimitation =
    "A call path exists from a function that reads untrusted input to this "
    "operation. Value-level dataflow was not analysed, so it is not established "
    "that attacker-controlled data reaches the affected argument, nor that "
    "intervening length checks are absent. Manual review required to confirm "
    "exploitability.";

constexpr const char* kUnreachableLimitation =
    "No call path from a known untrusted-input source was found. This may be "
    "because none exists, or because the path runs through an indirect call that "
    "static analysis cannot resolve.";

} // namespace

SinkSeverity Reachability::compose_severity(SinkKind kind, bool reachable)
{
    const SinkSeverity base = base_severity(kind);

    if (!reachable) {
        // Unreachable: a code-quality observation, not a security finding. Never
        // report these above Low, whatever the sink is.
        return (base >= SinkSeverity::Medium) ? SinkSeverity::Low
                                              : SinkSeverity::Informational;
    }

    // Reachable: the sink's own severity stands. Unbounded copies stay High
    // because there is no safe way to call them on untrusted data.
    return base;
}

void Reachability::analyze(const std::map<core::VA, Function>& functions,
                          const CallGraph& call_graph,
                          const ReachabilityOptions& options)
{
    clear();

    // --- 1. Locate sources and sinks --------------------------------------
    // Both come from the resolved api_calls list, which is why IAT resolution
    // had to work first: on a real binary nearly every API call is indirect, and
    // an unresolved indirect call is invisible here.
    std::unordered_map<core::VA, std::set<InputSource>> source_functions;

    for (const auto& entry : functions) {
        const core::VA address = entry.first;
        const Function& function = entry.second;

        for (const std::string& api : function.api_calls) {
            const InputSource source = ApiClassifier::input_source_of(api);
            if (source != InputSource::None) {
                sources_.push_back({ address, source, api });
                source_functions[address].insert(source);
            }

            const SinkKind sink = ApiClassifier::sink_of(api);
            if (sink != SinkKind::None) {
                sinks_.push_back({ address, sink, api });
            }
        }
    }

    // --- 2. Breadth-first search from every source ------------------------
    // Breadth-first rather than depth-first so the recorded path is the shortest
    // one - a 3-hop path is far more convincing evidence than a 30-hop path that
    // happens to exist.
    struct Item {
        core::VA function;
        std::size_t depth;
    };
    std::deque<Item> queue;

    for (const auto& entry : source_functions) {
        reaching_[entry.first] = entry.second;
        queue.push_back({ entry.first, 0 });
    }

    while (!queue.empty()) {
        const Item current = queue.front();
        queue.pop_front();

        if (current.depth >= options.max_depth) {
            continue;
        }

        const std::set<core::VA>* callees = call_graph.callees_of(current.function);
        if (callees == nullptr) {
            continue;
        }

        const std::set<InputSource>& inherited = reaching_[current.function];

        for (core::VA callee : *callees) {
            auto& existing = reaching_[callee];
            const std::size_t before = existing.size();
            existing.insert(inherited.begin(), inherited.end());

            // Only re-queue when this actually taught us something new,
            // otherwise a cyclic call graph loops forever.
            if (existing.size() != before || before == 0) {
                if (came_from_.find(callee) == came_from_.end()) {
                    came_from_[callee] = current.function;
                }
                queue.push_back({ callee, current.depth + 1 });
            }
        }
    }

    // --- 3. Build a result per sink ---------------------------------------
    for (const SinkSite& sink : sinks_) {
        const bool reachable = is_reachable_from_input(sink.function);

        if (!reachable && !options.include_unreachable) {
            continue;
        }

        ReachabilityResult result;
        result.function = sink.function;
        result.sink = sink.kind;
        result.sink_api = sink.api;
        result.reachable_from_input = reachable;
        result.base_severity = base_severity(sink.kind);
        result.effective_severity = compose_severity(sink.kind, reachable);
        result.limitation = reachable ? kReachableLimitation : kUnreachableLimitation;

        if (reachable) {
            if (const std::set<InputSource>* sources = sources_reaching(sink.function)) {
                result.sources = *sources;
            }

            // Walk predecessors back to the source, then reverse.
            std::vector<core::VA> path;
            core::VA cursor = sink.function;
            std::set<core::VA> guard;

            while (guard.insert(cursor).second) {
                path.push_back(cursor);
                auto previous = came_from_.find(cursor);
                if (previous == came_from_.end()) {
                    break;
                }
                cursor = previous->second;
            }
            std::reverse(path.begin(), path.end());
            result.path = std::move(path);
        }

        results_.push_back(std::move(result));
    }

    std::size_t reachable_count = 0;
    for (const ReachabilityResult& result : results_) {
        if (result.reachable_from_input) {
            ++reachable_count;
        }
    }

    core::log_info("reachability: " + std::to_string(sources_.size())
                   + " input sources, " + std::to_string(sinks_.size())
                   + " risky operations, " + std::to_string(reachable_count)
                   + " reachable from untrusted input");
}

std::vector<const ReachabilityResult*> Reachability::impactful() const
{
    std::vector<const ReachabilityResult*> out;
    for (const ReachabilityResult& result : results_) {
        if (result.reachable_from_input
            && result.effective_severity >= SinkSeverity::Medium) {
            out.push_back(&result);
        }
    }

    std::sort(out.begin(), out.end(),
              [](const ReachabilityResult* a, const ReachabilityResult* b) {
                  if (a->effective_severity != b->effective_severity) {
                      return a->effective_severity > b->effective_severity;
                  }
                  // Shorter paths are stronger evidence.
                  return a->path.size() < b->path.size();
              });
    return out;
}

bool Reachability::is_reachable_from_input(core::VA function) const
{
    auto it = reaching_.find(function);
    return it != reaching_.end() && !it->second.empty();
}

const std::set<InputSource>* Reachability::sources_reaching(core::VA function) const
{
    auto it = reaching_.find(function);
    return it == reaching_.end() ? nullptr : &it->second;
}

void Reachability::clear()
{
    sources_.clear();
    sinks_.clear();
    results_.clear();
    reaching_.clear();
    came_from_.clear();
}

} // namespace sp::analysis
