#pragma once
//
// JsonExporter.h - The contract with the frontend.
//
// Single structured representation consumed by both the graph renderer and the
// model layer, rather than a UI format plus a scraped text dump.
//
// Emits confidence and provenance alongside every derived fact, so the UI can
// visually mark speculative regions instead of presenting guesses as certainty.
//
#include "sp/analysis/CallGraph.h"
#include "sp/analysis/Function.h"
#include "sp/analysis/SymbolTable.h"
#include "sp/analysis/XrefTable.h"
#include "sp/core/Error.h"
#include "sp/db/AnnotationStore.h"
#include "sp/db/FactStore.h"
#include "sp/disasm/CodeMap.h"
#include "sp/disasm/InstructionStorage.h"

#include <map>
#include <ostream>
#include <string>

namespace sp::serialize {

struct JsonOptions {
    bool pretty = true;

    bool include_bytes = true;
    bool include_provenance = true;
    bool include_confidence = true;
    bool include_xrefs = true;
    bool include_annotations = true;

    // Emit ranges the analysis could not explain. Honest about incompleteness,
    // and lets the UI shade unanalysed regions.
    bool include_unclaimed_ranges = true;
};

class JsonExporter {
public:
    struct Inputs {
        const db::FactStore* facts = nullptr;
        const db::AnnotationStore* annotations = nullptr;
        const disasm::InstructionStorage* instructions = nullptr;
        const disasm::CodeMap* code_map = nullptr;
        const analysis::SymbolTable* symbols = nullptr;
        const analysis::XrefTable* xrefs = nullptr;
        const analysis::CallGraph* call_graph = nullptr;
        const std::map<core::VA, analysis::Function>* functions = nullptr;
    };

    // Whole-image document: metadata, sections, symbols, function index.
    static core::Status export_image(const Inputs& inputs,
                                    const JsonOptions& options,
                                    std::ostream& out);

    // One function with its blocks, edges and instructions. What the UI fetches
    // when the user opens a function.
    static core::Status export_function(const Inputs& inputs,
                                       core::VA function,
                                       const JsonOptions& options,
                                       std::ostream& out);

    // Function index only. Cheap enough to load on startup.
    static core::Status export_function_list(const Inputs& inputs,
                                            const JsonOptions& options,
                                            std::ostream& out);

    static core::Status export_call_graph(const Inputs& inputs,
                                         const JsonOptions& options,
                                         std::ostream& out);
};

} // namespace sp::serialize
