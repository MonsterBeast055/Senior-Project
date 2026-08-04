#pragma once
//
// ContextBuilder.h - Assembling what the model actually sees.
//
// The quality of AI logic lifting is decided here, not in the prompt. Handing a
// model a flat instruction dump wastes most of what we know. This module builds
// a per-function bundle: disassembly with resolved symbol names, CFG shape,
// recovered loop and conditional structure, referenced strings and constants,
// the API calls made, and summaries already produced for the callees.
//
// It also enforces a context budget, degrading gracefully by dropping the least
// informative material first rather than truncating mid-function.
//
#include "StructuralAnalysis.h"
#include "sp/analysis/CallGraph.h"
#include "sp/analysis/Function.h"
#include "sp/analysis/SymbolTable.h"
#include "sp/analysis/XrefTable.h"
#include "sp/db/AnnotationStore.h"
#include "sp/db/FactStore.h"
#include "sp/disasm/InstructionStorage.h"

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace sp::lift {

struct ContextBudget {
    // Approximate ceiling for the assembled bundle. Enforced by dropping
    // optional sections in priority order.
    std::size_t max_tokens = 8000;

    // How far down the call graph to pull in callee summaries.
    std::size_t max_callee_depth = 1;

    // Cap on functions whose summaries are included as context.
    std::size_t max_callee_summaries = 8;

    bool include_raw_bytes = false;
    bool include_string_refs = true;
    bool include_api_calls = true;
    bool include_caller_context = true;
};

// A previously produced natural-language summary, reused as context for callers.
struct FunctionSummary {
    core::VA function = core::kInvalidVA;
    std::string suggested_name;
    std::string description;
    std::vector<std::string> tags;
    core::Confidence confidence = core::Confidence::None;
};

// Everything the model is given about one function.
struct FunctionContext {
    core::VA function = core::kInvalidVA;
    std::string current_name;

    // Disassembly with call targets replaced by resolved symbol names.
    std::vector<std::string> annotated_disassembly;

    // Textual rendering of the recovered region tree.
    std::string structure_outline;

    std::size_t block_count = 0;
    std::size_t cyclomatic_complexity = 0;
    std::size_t loop_count = 0;
    std::size_t max_loop_depth = 0;

    // Imported APIs called, e.g. "kernel32!CreateFileW". Often the single most
    // informative signal about a function's purpose.
    std::vector<std::string> api_calls;

    std::vector<std::string> referenced_strings;
    std::vector<std::string> notable_constants;

    analysis::CallingConvention convention = analysis::CallingConvention::Unknown;
    analysis::StackFrame frame;

    // Summaries for functions this one calls, enabling bottom-up reasoning.
    std::vector<FunctionSummary> callee_summaries;

    // How this function is used by its callers.
    std::vector<std::string> caller_names;

    // Regions where our own analysis is weak. Told to the model explicitly so
    // it can hedge instead of confidently describing a bad decode.
    std::vector<std::string> analysis_caveats;
};

class ContextBuilder {
public:
    struct Inputs {
        const db::FactStore* facts = nullptr;
        const db::AnnotationStore* annotations = nullptr;
        const disasm::InstructionStorage* instructions = nullptr;
        const analysis::SymbolTable* symbols = nullptr;
        const analysis::XrefTable* xrefs = nullptr;
        const analysis::CallGraph* call_graph = nullptr;
        const std::map<core::VA, analysis::Function>* functions = nullptr;

        // Summaries produced so far, keyed by function entry.
        const std::map<core::VA, FunctionSummary>* known_summaries = nullptr;
    };

    core::Result<FunctionContext> build(const Inputs& inputs,
                                       core::VA function,
                                       const ContextBudget& budget);

    // Serialise a context bundle into the payload sent to the model.
    static std::string to_prompt_payload(const FunctionContext& context);

    // Bottom-up order over the call graph, so callee summaries exist before
    // their callers are processed.
    static std::vector<core::VA> recommended_processing_order(
        const analysis::CallGraph& call_graph);
};

} // namespace sp::lift
