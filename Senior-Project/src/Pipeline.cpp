#include "sp/Pipeline.h"

#include "sp/core/Log.h"

#include <chrono>
#include <sstream>

namespace sp {
namespace {

std::string hex(std::uint64_t value)
{
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}

// Populate the cross-reference table from the instruction stream.
//
// Calls and jumps are the cheap, reliable half. Data references would need
// operand-level analysis and are deferred.
std::size_t build_xrefs(const disasm::InstructionStorage& instructions,
                       analysis::XrefTable& out)
{
    out.clear();
    std::size_t count = 0;

    for (const auto& entry : instructions) {
        const core::VA from = entry.first;
        const disasm::InstructionInfo& insn = entry.second;

        auto record = [&](core::VA to, analysis::XrefType type) {
            analysis::Xref xref;
            xref.from = from;
            xref.to = to;
            xref.type = type;
            xref.confidence = insn.provenance.effective_confidence();
            out.add(xref);
            ++count;
        };

        if (insn.direct_target.has_value()) {
            record(*insn.direct_target,
                   insn.is_call() ? analysis::XrefType::Call : analysis::XrefType::Jump);
        }
        for (core::VA resolved : insn.resolved_targets) {
            record(resolved, analysis::XrefType::Jump);
        }
    }

    return count;
}

} // namespace

const analysis::Function* Pipeline::function_at(core::VA entry) const
{
    auto it = functions_.find(entry);
    return it == functions_.end() ? nullptr : &it->second;
}

const analysis::Function* Pipeline::function_containing(core::VA va) const
{
    // Greatest entry <= va, then confirm with a block-level check. Functions are
    // not guaranteed contiguous, so extent alone is only an approximation.
    auto it = functions_.upper_bound(va);
    if (it == functions_.begin()) {
        return nullptr;
    }
    --it;
    if (va >= it->second.entry && va < it->second.extent_end) {
        if (it->second.cfg.block_containing(va) != nullptr) {
            return &it->second;
        }
    }

    // Fall back to a scan: a cold path hoisted elsewhere in .text will not be
    // found by the ordered lookup above.
    for (const auto& [entry, function] : functions_) {
        if (function.cfg.block_containing(va) != nullptr) {
            return &function;
        }
    }
    return nullptr;
}

core::Status Pipeline::analyze(const std::string& path, const PipelineOptions& options)
{
    const auto started = std::chrono::steady_clock::now();
    stats_ = PipelineStats{};

    // --- 1. Load ----------------------------------------------------------
    if (auto status = loader::BinaryLoader::load_pe(path, options.load, facts_); !status.ok()) {
        return status;
    }

    // --- 2. Symbols -------------------------------------------------------
    // Before disassembly, so branch annotation has names available immediately.
    symbols_.build(facts_);

    // --- 3. Disassemble ---------------------------------------------------
    if (auto status = disassembler_.initialize(facts_); !status.ok()) {
        return status;
    }
    if (auto status = disassembler_.run(facts_, options.disassembly, ids_,
                                       instructions_, code_map_);
        !status.ok()) {
        return status;
    }
    stats_.disassembly = disassembler_.stats();

    if (instructions_.empty()) {
        return core::Error(core::ErrorCode::DecodeFailed,
                           "no instructions decoded; nothing to analyse");
    }

    // --- 4. Discover functions -------------------------------------------
    const auto candidates = analysis::FunctionDiscovery::find_candidates(
        facts_, instructions_, code_map_, options.discovery);

    core::log_info("found " + std::to_string(candidates.size()) + " function candidates");

    // --- 5. Build CFGs ----------------------------------------------------
    analysis::CFGBuilder builder;
    if (auto status = builder.build_all(facts_, instructions_, code_map_, candidates,
                                        options.cfg, ids_, functions_);
        !status.ok()) {
        return status;
    }
    stats_.cfg = builder.stats();
    stats_.functions_found = functions_.size();

    // Give every discovered function a fallback name so nothing downstream has
    // to deal with an unnamed address.
    for (const auto& [entry, function] : functions_) {
        if (symbols_.lookup(entry) == nullptr) {
            analysis::Symbol symbol;
            symbol.address = entry;
            symbol.name = analysis::SymbolTable::generated_name(entry, true);
            symbol.source = analysis::SymbolSource::Generated;
            symbol.is_function = true;
            symbols_.add(std::move(symbol));
        }
    }

    // --- 6. Strings -------------------------------------------------------
    // Runs before summarisation so functions can pick up their referenced
    // strings. Highest information-per-token input the AI layer receives.
    if (options.extract_strings) {
        strings_.extract(facts_, instructions_, options.strings);
        stats_.strings_found = strings_.size();
    }

    // --- 7. Function summaries -------------------------------------------
    // Content hashes for caching, complexity for model routing, API names and
    // strings for prompt quality, information score for triage.
    if (options.summarize_functions) {
        analysis::FunctionSummarizer::Inputs summary_inputs;
        summary_inputs.facts = &facts_;
        summary_inputs.instructions = &instructions_;
        summary_inputs.symbols = &symbols_;
        summary_inputs.strings = &strings_;
        analysis::FunctionSummarizer::summarize_all(summary_inputs, functions_);
    }

    // --- 8. Cross-references ---------------------------------------------
    if (options.build_xrefs) {
        stats_.xrefs_found = build_xrefs(instructions_, xrefs_);
    }

    // --- 9. Call graph ----------------------------------------------------
    if (options.build_call_graph) {
        call_graph_.build(functions_);
    }

    // --- 10. Reachability -------------------------------------------------
    // Must run after the call graph: this is what separates an impactful
    // finding from a code-quality remark, and it needs the graph to do it.
    if (options.analyze_reachability && options.build_call_graph) {
        reachability_.analyze(functions_, call_graph_, options.reachability);
        stats_.risky_operations = reachability_.results().size();
        stats_.reachable_operations = reachability_.impactful().size();
    }

    // --- 11. Structural analysis -----------------------------------------
    // Deferred: dominators, loops and region recovery are not implemented yet,
    // and nothing in the v1 output depends on them.
    if (options.run_structural_analysis) {
        core::log_debug("structural analysis requested but not yet implemented");
    }

    const auto finished = std::chrono::steady_clock::now();
    stats_.analysis_seconds =
        std::chrono::duration<double>(finished - started).count();

    std::ostringstream summary;
    summary << "analysis complete in " << stats_.analysis_seconds << "s: "
            << stats_.functions_found << " functions, "
            << stats_.disassembly.instructions_decoded << " instructions, "
            << stats_.xrefs_found << " xrefs, "
            << stats_.strings_found << " strings";
    core::log_info(summary.str());

    return core::Status::success();
}

core::Status Pipeline::reanalyze_function(core::VA entry, const PipelineOptions& options)
{
    auto it = functions_.find(entry);
    if (it == functions_.end()) {
        return core::Error(core::ErrorCode::InvalidAddress,
                           "no function at " + hex(entry));
    }

    // Rebuild against the current instruction stream. The payoff from keeping
    // facts and annotations separate: a name or type asserted by a user or the
    // model is incorporated without discarding disassembly or other functions.
    std::vector<core::VA> entry_list;
    entry_list.reserve(functions_.size());
    for (const auto& [address, function] : functions_) {
        entry_list.push_back(address);
    }

    const std::set<core::VA> entry_set(entry_list.begin(), entry_list.end());
    const std::set<core::VA> leaders =
        analysis::CFGBuilder::compute_leaders(instructions_, entry_list);
    const std::set<core::VA> noreturn =
        analysis::CFGBuilder::find_noreturn_functions(facts_);

    analysis::CFGBuildContext context;
    context.function_entries = &entry_set;
    context.leaders = &leaders;
    context.noreturn_functions = &noreturn;

    analysis::CFGBuilder builder;
    auto rebuilt = builder.build_function(facts_, instructions_, entry, context,
                                          options.cfg, ids_);
    if (!rebuilt.ok()) {
        return core::Error(rebuilt.error().code, rebuilt.error().message);
    }

    // Preserve the original discovery evidence; only the graph is regenerated.
    core::ProvenanceSet provenance = it->second.provenance;
    it->second = std::move(rebuilt.value());
    it->second.provenance = std::move(provenance);

    if (options.build_call_graph) {
        call_graph_.build(functions_);
    }

    return core::Status::success();
}

core::Status Pipeline::retract_region(core::VA start, core::VA end,
                                    core::ProvenanceKind reason,
                                    const PipelineOptions& options)
{
    if (start >= end) {
        return core::Error(core::ErrorCode::InvalidArgument, "empty retraction range");
    }

    // Collect affected functions before the instructions disappear.
    std::vector<core::VA> affected;
    for (const auto& [entry, function] : functions_) {
        if (function.entry < end && function.extent_end > start) {
            affected.push_back(entry);
        }
    }

    if (auto status = disassembler_.retract_range(start, end, reason,
                                                 instructions_, code_map_);
        !status.ok()) {
        return status;
    }

    for (core::VA entry : affected) {
        // A function whose own entry was retracted no longer exists.
        if (instructions_.get(entry) == nullptr) {
            functions_.erase(entry);
            continue;
        }
        reanalyze_function(entry, options);
    }

    if (options.build_xrefs) {
        stats_.xrefs_found = build_xrefs(instructions_, xrefs_);
    }
    if (options.build_call_graph) {
        call_graph_.build(functions_);
    }

    core::log_info("retracted " + hex(start) + "-" + hex(end) + ", rebuilt "
                   + std::to_string(affected.size()) + " functions");

    return core::Status::success();
}

} // namespace sp
