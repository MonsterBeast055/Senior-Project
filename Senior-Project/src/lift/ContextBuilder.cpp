#include "sp/lift/ContextBuilder.h"

#include <sstream>

namespace sp::lift {

std::vector<core::VA> ContextBuilder::recommended_processing_order(
    const analysis::CallGraph& call_graph)
{
    // Leaves first. A caller summarised after its callees can be described in
    // terms of what those callees do, which is the whole reason bottom-up
    // ordering beats address order for logic lifting.
    return call_graph.reverse_topological_order();
}

core::Result<FunctionContext> ContextBuilder::build(const Inputs& inputs,
                                                   core::VA function,
                                                   const ContextBudget& budget)
{
    // TODO:
    //  1. locate the Function; error out if absent
    //  2. walk blocks in reverse post-order, emitting annotated disassembly with
    //     call targets replaced by SymbolTable names - this alone is the single
    //     biggest quality win over feeding raw disassembly
    //  3. collect api_calls from calls resolving to imports
    //  4. collect referenced_strings via XrefTable data references into
    //     read-only sections
    //  5. render the region tree into structure_outline
    //  6. fill complexity, loop count and depth
    //  7. pull callee summaries from known_summaries, honouring
    //     max_callee_depth and max_callee_summaries
    //  8. record analysis_caveats wherever the underlying data is weak:
    //     low-confidence decodes, unresolved indirect branches, unreachable
    //     blocks. Telling the model where our own analysis is shaky is what
    //     keeps it from confidently describing a bad decode
    //  9. enforce budget.max_tokens by dropping optional sections in priority
    //     order - never by truncating mid-function
    (void)inputs; (void)function; (void)budget;
    return core::Error(core::ErrorCode::Internal, "ContextBuilder::build not implemented");
}

std::string ContextBuilder::to_prompt_payload(const FunctionContext& context)
{
    // TODO: render the bundle as structured text. Lead with the strongest
    // signals - API calls, strings, callee summaries - before the disassembly
    // body, since those are what most often determine a function's purpose.
    std::ostringstream out;
    out << "function " << context.current_name << "\n";
    return out.str();
}

} // namespace sp::lift
