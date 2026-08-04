#include "sp/analysis/CFGBuilder.h"

#include "sp/core/Log.h"

#include <algorithm>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

namespace sp::analysis {
namespace {

// Imported functions that never return. A call to one of these ends the block:
// the bytes that follow are not a continuation of this control flow, they are
// usually the next function or unreachable padding.
const char* const kNoReturnNames[] = {
    "ExitProcess", "ExitThread", "TerminateProcess", "RtlExitUserProcess",
    "exit", "_exit", "_Exit", "abort", "quick_exit",
    "_invalid_parameter_noinfo_noreturn", "_CxxThrowException",
    "longjmp", "__stack_chk_fail",
};

bool name_is_noreturn(const std::string& name)
{
    for (const char* candidate : kNoReturnNames) {
        if (name == candidate) {
            return true;
        }
    }
    return false;
}

std::string hex(std::uint64_t value)
{
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}

bool contains(const std::set<core::VA>* set, core::VA value)
{
    return set != nullptr && set->find(value) != set->end();
}

} // namespace

std::set<core::VA> CFGBuilder::compute_leaders(const disasm::InstructionStorage& instructions,
                                               const std::vector<core::VA>& function_entries)
{
    std::set<core::VA> leaders(function_entries.begin(), function_entries.end());

    for (const auto& entry : instructions) {
        const disasm::InstructionInfo& insn = entry.second;

        if (insn.is_jump() && insn.direct_target.has_value()) {
            leaders.insert(*insn.direct_target);
        }
        for (core::VA target : insn.resolved_targets) {
            leaders.insert(target);
        }

        // The fall-through of a conditional branch begins a new block. Easy to
        // remember for the edge and easy to forget here - miss it and blocks run
        // straight through branch boundaries.
        if (insn.is_conditional_jump() && insn.fall_through.has_value()) {
            leaders.insert(*insn.fall_through);
        }
    }

    return leaders;
}

std::set<core::VA> CFGBuilder::find_noreturn_functions(const db::FactStore& facts)
{
    std::set<core::VA> noreturn;

    // Imports are reached through their IAT slot, which is the address an
    // indirect call actually reads.
    for (const auto& import : facts.imports()) {
        if (!import.name.empty() && name_is_noreturn(import.name)
            && import.iat_slot != core::kInvalidVA) {
            noreturn.insert(import.iat_slot);
        }
    }

    for (const auto& exported : facts.exports()) {
        if (name_is_noreturn(exported.name) && exported.address != core::kInvalidVA) {
            noreturn.insert(exported.address);
        }
    }

    return noreturn;
}

core::Result<Function> CFGBuilder::build_function(const db::FactStore& facts,
                                                 const disasm::InstructionStorage& instructions,
                                                 core::VA entry,
                                                 const CFGBuildContext& context,
                                                 const CFGBuildOptions& options,
                                                 db::EntityIdAllocator& ids)
{
    if (instructions.get(entry) == nullptr) {
        return core::Error(core::ErrorCode::InvalidAddress,
                           "no instruction at function entry " + hex(entry));
    }

    Function function;
    function.id = ids.allocate(db::EntityKind::Function);
    function.entry = entry;
    function.cfg.set_entry(entry);

    // Hard upper bound from .pdata, when this function has an entry there.
    core::VA declared_end = core::kInvalidVA;
    if (context.function_extents != nullptr) {
        auto it = context.function_extents->find(entry);
        if (it != context.function_extents->end()) {
            declared_end = it->second;
        }
    }
    const bool bounded = (declared_end != core::kInvalidVA);

    // Is `target` outside what .pdata says this function covers? A cold path
    // hoisted elsewhere gets its own .pdata entry, so it becomes its own
    // function rather than being lost.
    auto outside_declared_extent = [&](core::VA target) {
        return bounded && (target < entry || target >= declared_end);
    };

    std::vector<core::VA> worklist{ entry };
    std::unordered_set<core::VA> queued{ entry };
    std::vector<core::VA> callee_list;
    core::VA extent_end = entry;

    while (!worklist.empty()) {
        const core::VA block_start = worklist.back();
        worklist.pop_back();

        if (function.cfg.block_at(block_start) != nullptr) {
            continue;
        }
        if (instructions.get(block_start) == nullptr) {
            // Edge into undecoded bytes: do not fabricate a block for it.
            continue;
        }

        BasicBlock block;
        block.id = ids.allocate(db::EntityKind::BasicBlock);
        block.start = block_start;
        block.end = block_start;

        const disasm::InstructionInfo* last = nullptr;
        bool ended_on_leader = false;
        bool noreturn_call = false;
        core::VA cursor = block_start;

        // --- Walk the straight-line run ----------------------------------
        while (true) {
            if (bounded && cursor >= declared_end) {
                // Reached the end .pdata declared for this function.
                break;
            }

            const disasm::InstructionInfo* insn = instructions.get(cursor);
            if (insn == nullptr) {
                // Ran into undecoded bytes. Leave the block short rather than
                // inventing instructions; has_unresolved_exit records the gap.
                block.has_unresolved_exit = true;
                break;
            }

            block.instructions.push_back(cursor);
            block.end = insn->end_address();
            last = insn;
            extent_end = std::max(extent_end, block.end);

            if (insn->is_call()) {
                if (insn->direct_target.has_value()) {
                    callee_list.push_back(*insn->direct_target);
                    if (options.respect_noreturn
                        && contains(context.noreturn_functions, *insn->direct_target)) {
                        noreturn_call = true;
                    }
                } else {
                    ++function.indirect_call_count;
                }
            }

            // A call does not end a block: it returns, so control continues into
            // the next instruction. A call to a noreturn function is the only
            // exception.
            if (noreturn_call || insn->terminates_block()) {
                break;
            }

            const core::VA next = insn->end_address();

            // Another block starts here, so this one has to stop.
            if (contains(context.leaders, next)) {
                ended_on_leader = true;
                break;
            }
            cursor = next;
        }

        // --- Wire successors ---------------------------------------------
        std::vector<Edge> successors;

        // Flowing into another function's entry is a boundary, not an edge -
        // whether we get there by jumping or by falling through. Missing the
        // fall-through case is catastrophic rather than merely wrong: this
        // function absorbs the next one, whose own tail then falls into the one
        // after, and the cascade can swallow most of the image.
        //
        // The usual cause is a call to a noreturn function we did not recognise,
        // or an `int3` filler byte after one: control "continues" into whatever
        // the linker placed next.
        auto crosses_function_boundary = [&](core::VA target) {
            if (target == entry) {
                return false;
            }
            return contains(context.function_entries, target)
                || outside_declared_extent(target);
        };

        if (last != nullptr && !noreturn_call) {
            switch (last->flow) {
            case disasm::FlowKind::ConditionalJump: {
                // Two edges: taken and not taken.
                if (last->direct_target.has_value()) {
                    if (outside_declared_extent(*last->direct_target)) {
                        ++stats_.fallthrough_boundaries;
                    } else {
                        successors.push_back({ *last->direct_target, EdgeKind::Taken,
                                               core::Confidence::High });
                    }
                } else if (last->is_indirect) {
                    block.has_unresolved_exit = true;
                    ++stats_.unresolved_indirect_jumps;
                }
                if (last->fall_through.has_value()) {
                    if (crosses_function_boundary(*last->fall_through)) {
                        ++stats_.fallthrough_boundaries;
                    } else {
                        successors.push_back({ *last->fall_through, EdgeKind::FallThrough,
                                               core::Confidence::High });
                    }
                }
                break;
            }

            case disasm::FlowKind::UnconditionalJump: {
                if (last->direct_target.has_value()) {
                    const core::VA target = *last->direct_target;

                    // Tail call: a jmp landing on another function's entry, or
                    // outside what .pdata says this function covers, is a
                    // boundary rather than an edge. Following it would merge
                    // that function - and everything it tail-calls in turn -
                    // into this one.
                    const bool tail_call = crosses_function_boundary(target);

                    if (tail_call) {
                        callee_list.push_back(target);
                    } else {
                        successors.push_back({ target, EdgeKind::Jump,
                                               core::Confidence::High });
                    }
                } else if (!last->resolved_targets.empty()) {
                    for (core::VA target : last->resolved_targets) {
                        successors.push_back({ target, EdgeKind::IndirectJump,
                                               core::Confidence::Medium });
                    }
                    ++stats_.jump_tables_resolved;
                } else {
                    // Unresolved indirect jump, typically a switch table. Say so
                    // rather than emitting a successor-less block that makes the
                    // rest of the function look unreachable.
                    block.has_unresolved_exit = true;
                    ++stats_.unresolved_indirect_jumps;
                }
                break;
            }

            case disasm::FlowKind::Return:
            case disasm::FlowKind::Halt:
                break;

            default: {
                // Sequential, Call or Interrupt that stopped because the next
                // address is a leader.
                if (ended_on_leader && last->fall_through.has_value()) {
                    if (crosses_function_boundary(*last->fall_through)) {
                        // End of this function, not a continuation of it.
                        ++stats_.fallthrough_boundaries;
                    } else {
                        successors.push_back({ *last->fall_through, EdgeKind::FallThrough,
                                               core::Confidence::High });
                    }
                }
                break;
            }
            }
        }

        function.cfg.add_block(std::move(block));

        for (const Edge& edge : successors) {
            function.cfg.add_edge(block_start, edge);
            ++stats_.edges_built;

            if (queued.insert(edge.target).second) {
                worklist.push_back(edge.target);
            }
        }

        ++stats_.blocks_built;
    }

    // --- Function-level summary ------------------------------------------
    function.extent_end = extent_end;

    std::sort(callee_list.begin(), callee_list.end());
    callee_list.erase(std::unique(callee_list.begin(), callee_list.end()), callee_list.end());
    function.callees = std::move(callee_list);

    for (const BasicBlock* block : function.cfg.blocks()) {
        function.instruction_count += block->instruction_count();
    }

    // A single-instruction function that is one jump is a thunk, not real code.
    // Presenting these as ordinary functions clutters the list badly - an
    // import-heavy binary has hundreds.
    if (options.detect_thunks && function.cfg.block_count() == 1
        && function.instruction_count == 1) {
        const disasm::InstructionInfo* only = instructions.get(entry);
        if (only != nullptr && only->is_unconditional_jump()) {
            function.is_thunk = true;
            if (only->is_indirect) {
                // jmp qword [rip+N] through the import address table.
                function.is_imported_stub = true;
            }
        }
    }

    // Recover what we can of the frame from the prologue.
    if (const disasm::InstructionInfo* first = instructions.get(entry); first != nullptr) {
        if (first->mnemonic == "push" && first->op_str.find("bp") != std::string::npos) {
            function.frame.uses_frame_pointer = true;
            function.frame.saved_regs_size = static_cast<std::int64_t>(first->size);
        }
        const disasm::InstructionInfo* scan = first;
        for (int i = 0; i < 4 && scan != nullptr; ++i) {
            if (scan->mnemonic == "sub" && scan->op_str.find("sp") != std::string::npos) {
                const std::size_t comma = scan->op_str.find(',');
                if (comma != std::string::npos) {
                    try {
                        function.frame.local_size =
                            std::stoll(scan->op_str.substr(comma + 1), nullptr, 0);
                    } catch (...) {
                        // Non-constant frame adjustment; leave local_size at 0.
                    }
                }
                break;
            }
            scan = instructions.get(scan->end_address());
        }
    }

    function.convention = (facts.arch() == core::Arch::X86_64)
        ? CallingConvention::Win64
        : CallingConvention::Unknown;

    // Does this function return? True if any terminal block ends in a ret.
    function.returns = false;
    for (const BasicBlock* block : function.cfg.blocks()) {
        if (!block->successors.empty() || block->instructions.empty()) {
            continue;
        }
        const disasm::InstructionInfo* insn = instructions.get(block->instructions.back());
        if (insn != nullptr && insn->is_return()) {
            function.returns = true;
            break;
        }
    }
    if (function.cfg.block_count() == 0) {
        function.returns = true;
    }

    return function;
}

core::Status CFGBuilder::build_all(const db::FactStore& facts,
                                  const disasm::InstructionStorage& instructions,
                                  const disasm::CodeMap& map,
                                  const std::vector<FunctionCandidate>& candidates,
                                  const CFGBuildOptions& options,
                                  db::EntityIdAllocator& ids,
                                  std::map<core::VA, Function>& out_functions)
{
    (void)map;
    stats_ = CFGBuildStats{};

    // Every candidate entry is a leader and a potential tail-call destination,
    // so both sets are computed from the full candidate list before any single
    // function is built.
    std::vector<core::VA> entry_list;
    entry_list.reserve(candidates.size());
    for (const auto& candidate : candidates) {
        entry_list.push_back(candidate.entry);
    }

    const std::set<core::VA> entry_set(entry_list.begin(), entry_list.end());
    const std::set<core::VA> leaders = compute_leaders(instructions, entry_list);
    const std::set<core::VA> noreturn = find_noreturn_functions(facts);

    CFGBuildContext context;
    context.function_entries = &entry_set;
    context.leaders = &leaders;
    context.noreturn_functions = &noreturn;
    context.function_extents = &facts.unwind_function_extents();

    // Process strongest evidence first, so trusted boundaries are established
    // before weaker candidates can claim overlapping code.
    std::vector<const FunctionCandidate*> ordered;
    ordered.reserve(candidates.size());
    for (const auto& candidate : candidates) {
        ordered.push_back(&candidate);
    }
    std::stable_sort(ordered.begin(), ordered.end(),
                     [](const FunctionCandidate* a, const FunctionCandidate* b) {
                         return a->provenance.effective_confidence()
                              > b->provenance.effective_confidence();
                     });

    for (const FunctionCandidate* candidate : ordered) {
        if (out_functions.find(candidate->entry) != out_functions.end()) {
            continue;
        }

        auto built = build_function(facts, instructions, candidate->entry,
                                    context, options, ids);
        if (!built.ok()) {
            // A candidate pointing at undecoded bytes is normal - a call target
            // inside a data region, for instance. Skip it quietly.
            continue;
        }

        Function function = std::move(built.value());
        function.provenance = candidate->provenance;
        out_functions.emplace(function.entry, std::move(function));
        ++stats_.functions_built;
    }

    // Backfill callers now that every function is known.
    for (auto& outer : out_functions) {
        for (core::VA callee : outer.second.callees) {
            auto it = out_functions.find(callee);
            if (it != out_functions.end()) {
                it->second.callers.push_back(outer.first);
            }
        }
    }
    for (auto& outer : out_functions) {
        auto& callers = outer.second.callers;
        std::sort(callers.begin(), callers.end());
        callers.erase(std::unique(callers.begin(), callers.end()), callers.end());
    }

    std::ostringstream summary;
    summary << "built " << stats_.functions_built << " functions, "
            << stats_.blocks_built << " blocks, "
            << stats_.edges_built << " edges"
            << " (unresolved indirect jumps=" << stats_.unresolved_indirect_jumps << ")";
    core::log_info(summary.str());

    return core::Status::success();
}

} // namespace sp::analysis
