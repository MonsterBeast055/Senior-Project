#pragma once
//
// Pipeline.h - Orchestration and the single owner of analysis state.
//
// Runs load -> disassemble -> discover functions -> build CFGs -> xrefs ->
// call graph -> structure, and holds the results. Also the entry point for
// incremental re-analysis: when an inference invalidates part of the image,
// only the affected functions are rebuilt.
//
#include "analysis/CFGBuilder.h"
#include "analysis/CallGraph.h"
#include "analysis/Function.h"
#include "analysis/FunctionDiscovery.h"
#include "analysis/LoopAnalysis.h"
#include "analysis/FunctionSummarizer.h"
#include "analysis/Reachability.h"
#include "analysis/StringExtractor.h"
#include "analysis/SymbolTable.h"
#include "analysis/XrefTable.h"
#include "core/Error.h"
#include "db/AnnotationStore.h"
#include "db/EntityId.h"
#include "db/FactStore.h"
#include "disasm/CodeMap.h"
#include "disasm/Disassembler.h"
#include "loader/BinaryLoader.h"

#include <map>
#include <string>

namespace sp {

struct PipelineOptions {
    loader::LoadOptions load;
    disasm::DisassemblyOptions disassembly;
    analysis::FunctionDiscoveryOptions discovery;
    analysis::CFGBuildOptions cfg;

    analysis::StringExtractionOptions strings;

    bool extract_strings = true;
    bool summarize_functions = true;
    analysis::ReachabilityOptions reachability;

    bool analyze_reachability = true;
    bool build_xrefs = true;
    bool build_call_graph = true;
    bool run_structural_analysis = true;
};

struct PipelineStats {
    disasm::DisassemblyStats disassembly;
    analysis::CFGBuildStats cfg;
    std::size_t functions_found = 0;
    std::size_t xrefs_found = 0;
    std::size_t strings_found = 0;
    std::size_t risky_operations = 0;
    std::size_t reachable_operations = 0;
    double analysis_seconds = 0.0;
};

class Pipeline {
public:
    core::Status analyze(const std::string& path, const PipelineOptions& options);

    // Re-run analysis for a single function, e.g. after a user or model
    // assertion changed something it depends on. The reason the fact and
    // annotation stores are kept separate.
    core::Status reanalyze_function(core::VA entry, const PipelineOptions& options);

    // Declare a region misdecoded, drop the affected instructions, and rebuild
    // every function that overlapped it.
    core::Status retract_region(core::VA start, core::VA end,
                               core::ProvenanceKind reason,
                               const PipelineOptions& options);

    // --- Accessors --------------------------------------------------------
    db::FactStore& facts() { return facts_; }
    const db::FactStore& facts() const { return facts_; }

    db::AnnotationStore& annotations() { return annotations_; }
    const db::AnnotationStore& annotations() const { return annotations_; }

    const disasm::InstructionStorage& instructions() const { return instructions_; }
    const disasm::CodeMap& code_map() const { return code_map_; }
    const analysis::SymbolTable& symbols() const { return symbols_; }
    const analysis::XrefTable& xrefs() const { return xrefs_; }
    const analysis::CallGraph& call_graph() const { return call_graph_; }
    const analysis::StringExtractor& strings() const { return strings_; }
    const analysis::Reachability& reachability() const { return reachability_; }

    const std::map<core::VA, analysis::Function>& functions() const { return functions_; }
    const analysis::Function* function_at(core::VA entry) const;

    // Function whose extent covers `va`.
    const analysis::Function* function_containing(core::VA va) const;

    const PipelineStats& stats() const { return stats_; }

private:
    db::FactStore facts_;
    db::AnnotationStore annotations_;
    db::EntityIdAllocator ids_;

    disasm::Disassembler disassembler_;
    disasm::InstructionStorage instructions_;
    disasm::CodeMap code_map_;

    analysis::SymbolTable symbols_;
    analysis::XrefTable xrefs_;
    analysis::CallGraph call_graph_;
    analysis::StringExtractor strings_;
    analysis::Reachability reachability_;
    std::map<core::VA, analysis::Function> functions_;

    PipelineStats stats_;
};

} // namespace sp
