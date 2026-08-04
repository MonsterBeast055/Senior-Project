#include "sp/analysis/FunctionDiscovery.h"

#include <algorithm>
#include <iterator>
#include <map>
#include <string>

namespace sp::analysis {
namespace {

// Merge candidates sharing an entry address, combining their provenance.
//
// Merging rather than plain deduplication is the point: a boundary backed by
// both unwind info and a direct call is stronger evidence than either alone, and
// that combined justification is what the UI and the model get to see.
std::vector<FunctionCandidate> merge_candidates(std::vector<FunctionCandidate> input)
{
    std::map<core::VA, FunctionCandidate> merged;

    for (auto& candidate : input) {
        if (candidate.entry == core::kInvalidVA) {
            continue;
        }
        auto it = merged.find(candidate.entry);
        if (it == merged.end()) {
            merged.emplace(candidate.entry, std::move(candidate));
            continue;
        }
        for (const auto& record : candidate.provenance.records()) {
            it->second.provenance.add(record);
        }
    }

    std::vector<FunctionCandidate> output;
    output.reserve(merged.size());
    for (auto& entry : merged) {
        output.push_back(std::move(entry.second));
    }
    return output;
}

// Does a plausible function prologue begin at this instruction?
//
// Recognises the common Microsoft and GCC openings:
//   push rbp / mov rbp, rsp     classic frame pointer setup
//   sub rsp, imm                frame allocation without a frame pointer
//   push rbx / rdi / rsi        callee-saved register save runs
//   mov [rsp+8], rcx            Win64 incoming-argument spill
//
// Heuristic by nature, so callers record it at Medium confidence and never let
// it displace an unwind-info boundary.
bool matches_prologue(const disasm::InstructionStorage& instructions,
                      const disasm::InstructionInfo& first,
                      std::size_t min_instructions)
{
    const std::string& mnemonic = first.mnemonic;
    const std::string& operands = first.op_str;

    const bool starts_frame =
           (mnemonic == "push" && operands.find("bp") != std::string::npos)
        || (mnemonic == "sub" && operands.find("sp") != std::string::npos)
        || (mnemonic == "push" && (operands == "rbx" || operands == "rdi"
                                   || operands == "rsi" || operands == "ebx"))
        || (mnemonic == "mov" && operands.find("[rsp") != std::string::npos);

    if (!starts_frame) {
        return false;
    }

    // Require a short run of decodable instructions after the opening. A lone
    // matching byte pattern inside data is common; several in sequence is much
    // less likely to be coincidence.
    std::size_t seen = 1;
    core::VA cursor = first.end_address();

    while (seen < min_instructions) {
        const disasm::InstructionInfo* next = instructions.get(cursor);
        if (next == nullptr) {
            return false;
        }
        if (next->flow == disasm::FlowKind::Return) {
            break;
        }
        cursor = next->end_address();
        ++seen;
    }

    return seen >= min_instructions;
}

} // namespace

std::vector<FunctionCandidate> FunctionDiscovery::from_unwind_info(const db::FactStore& facts)
{
    // .pdata is authoritative on x64 PE: the linker emitted one RUNTIME_FUNCTION
    // per function with a real prologue. Nothing else comes close for accuracy,
    // so this runs first.
    std::vector<FunctionCandidate> candidates;
    for (core::VA va : facts.unwind_function_starts()) {
        FunctionCandidate candidate;
        candidate.entry = va;
        candidate.provenance.add({ core::ProvenanceKind::PeUnwindInfo, core::kInvalidVA,
                                   core::Confidence::Certain, false });
        candidates.push_back(std::move(candidate));
    }
    return candidates;
}

std::vector<FunctionCandidate> FunctionDiscovery::from_call_targets(
    const disasm::InstructionStorage& instructions)
{
    std::vector<FunctionCandidate> candidates;
    for (const auto& entry : instructions) {
        const disasm::InstructionInfo& insn = entry.second;
        if (!insn.is_call() || !insn.direct_target.has_value()) {
            continue;
        }
        FunctionCandidate candidate;
        candidate.entry = *insn.direct_target;
        candidate.provenance.add({ core::ProvenanceKind::DirectCallTarget, entry.first,
                                   core::Confidence::High, false });
        candidates.push_back(std::move(candidate));
    }
    return candidates;
}

std::vector<FunctionCandidate> FunctionDiscovery::from_prologue_patterns(
    const db::FactStore& facts,
    const disasm::InstructionStorage& instructions,
    const disasm::CodeMap& map,
    const std::set<core::VA>& known_entries)
{
    std::vector<FunctionCandidate> candidates;

    const auto& extents = facts.unwind_function_extents();

    // Reject any address strictly inside a .pdata-declared function body.
    //
    // This guard is what makes it safe to scan the whole image rather than only
    // low-confidence bytes. .pdata states authoritatively that one function
    // spans that range, so a prologue-shaped byte sequence in the middle of it
    // is a coincidence - a register save in the middle of a routine, say. Acting
    // on it would fragment a correctly-identified function, which is a worse
    // failure than missing one.
    auto inside_known_function = [&extents](core::VA address) {
        auto it = extents.upper_bound(address);
        if (it == extents.begin()) {
            return false;
        }
        --it;
        return address > it->first && address < it->second;
    };

    auto already_known = [&known_entries](core::VA address) {
        return known_entries.find(address) != known_entries.end();
    };

    for (const auto& entry : instructions) {
        const core::VA address = entry.first;
        const disasm::InstructionInfo& insn = entry.second;

        // Consider any address that holds code. An earlier version restricted
        // this to low-confidence bytes, which was a category error: decode
        // confidence answers "are these bytes code?", not "is this a function
        // start?". Since recursive descent claims almost the whole image at High
        // confidence, that filter skipped essentially every real function - and
        // in a region reached only through function pointers, where there are no
        // direct call targets either, nothing was left to split it. One 45KB
        // stretch of notepad.exe came out as a single 1620-block function.
        const core::ByteClass klass = map.class_of(address);
        if (klass != core::ByteClass::Code && klass != core::ByteClass::ProbablyCode
            && klass != core::ByteClass::Unknown) {
            continue;
        }
        if (!facts.address_space().is_executable(address)) {
            continue;
        }

        // A function start already backed by stronger evidence needs no guess.
        if (already_known(address) || inside_known_function(address)) {
            continue;
        }
        if (!matches_prologue(instructions, insn, 2)) {
            continue;
        }

        FunctionCandidate candidate;
        candidate.entry = address;
        candidate.provenance.add({ core::ProvenanceKind::ProloguePattern, core::kInvalidVA,
                                   core::Confidence::Medium, false });
        candidates.push_back(std::move(candidate));
    }
    return candidates;
}

std::vector<FunctionCandidate> FunctionDiscovery::find_candidates(
    const db::FactStore& facts,
    const disasm::InstructionStorage& instructions,
    const disasm::CodeMap& map,
    const FunctionDiscoveryOptions& options)
{
    std::vector<FunctionCandidate> all;

    auto append = [&all](std::vector<FunctionCandidate> more) {
        all.insert(all.end(), std::make_move_iterator(more.begin()),
                   std::make_move_iterator(more.end()));
    };

    if (options.use_unwind_info) {
        append(from_unwind_info(facts));
    }

    if (options.use_exports) {
        for (const auto& sym : facts.exports()) {
            if (sym.is_forwarder || sym.address == core::kInvalidVA) {
                continue;
            }
            FunctionCandidate candidate;
            candidate.entry = sym.address;
            candidate.provenance.add({ core::ProvenanceKind::PeExport, core::kInvalidVA,
                                       core::Confidence::Certain, false });
            all.push_back(std::move(candidate));
        }
    }

    if (facts.entry_point() != core::kInvalidVA) {
        FunctionCandidate candidate;
        candidate.entry = facts.entry_point();
        candidate.provenance.add({ core::ProvenanceKind::EntryPoint, core::kInvalidVA,
                                   core::Confidence::Certain, false });
        all.push_back(std::move(candidate));
    }

    for (core::VA va : facts.tls_callbacks()) {
        FunctionCandidate candidate;
        candidate.entry = va;
        candidate.provenance.add({ core::ProvenanceKind::TlsCallback, core::kInvalidVA,
                                   core::Confidence::Certain, false });
        all.push_back(std::move(candidate));
    }

    if (options.use_call_targets) {
        append(from_call_targets(instructions));
    }

    // Prologue matching runs last and is told what the stronger sources already
    // found, so it only ever proposes genuinely new boundaries.
    if (options.use_prologue_patterns) {
        std::set<core::VA> known;
        for (const auto& candidate : all) {
            known.insert(candidate.entry);
        }
        append(from_prologue_patterns(facts, instructions, map, known));
    }

    return merge_candidates(std::move(all));
}

} // namespace sp::analysis
