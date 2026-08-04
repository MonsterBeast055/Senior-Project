#pragma once
//
// FunctionDiscovery.h - Locating function boundaries.
//
// Functions are not marked in a stripped binary; they are inferred. Sources,
// strongest first:
//   1. .pdata unwind info    - authoritative on x64 PE
//   2. PE entry point, exports, TLS callbacks
//   3. direct call targets
//   4. prologue pattern matching over unclaimed code
//
// Each candidate carries its evidence, so a prologue-heuristic function is
// visibly weaker than one backed by unwind data instead of both being asserted
// with equal confidence.
//
#include "Function.h"
#include "sp/core/Error.h"
#include "sp/core/Provenance.h"
#include "sp/disasm/CodeMap.h"
#include "sp/disasm/InstructionStorage.h"
#include "sp/db/FactStore.h"
#include "sp/db/EntityId.h"

#include <map>
#include <set>
#include <vector>

namespace sp::analysis {

struct FunctionDiscoveryOptions {
    bool use_unwind_info = true;
    bool use_exports = true;
    bool use_call_targets = true;
    bool use_prologue_patterns = true;

    // Detect single-jump thunks and import stubs so they are not presented as
    // real functions.
    bool detect_thunks = true;

    // Minimum instruction count before a prologue match is accepted.
    std::size_t min_prologue_instructions = 2;
};

// FunctionCandidate is declared in Function.h.

class FunctionDiscovery {
public:
    // Collect candidate entry points. Does not build CFGs; CFGBuilder does.
    static std::vector<FunctionCandidate> find_candidates(
        const db::FactStore& facts,
        const disasm::InstructionStorage& instructions,
        const disasm::CodeMap& map,
        const FunctionDiscoveryOptions& options);

    // Candidates from .pdata RUNTIME_FUNCTION entries.
    static std::vector<FunctionCandidate> from_unwind_info(const db::FactStore& facts);

    // Every direct call destination in the instruction stream.
    static std::vector<FunctionCandidate> from_call_targets(
        const disasm::InstructionStorage& instructions);

    // Heuristic prologue scan (push rbp / mov rbp,rsp / sub rsp,N and friends).
    //
    // Scans every code address, skipping those in `known_entries` and any
    // address strictly inside a .pdata-declared function body. Runs last, so the
    // stronger sources get first claim on every boundary.
    static std::vector<FunctionCandidate> from_prologue_patterns(
        const db::FactStore& facts,
        const disasm::InstructionStorage& instructions,
        const disasm::CodeMap& map,
        const std::set<core::VA>& known_entries);
};

} // namespace sp::analysis
