#pragma once
//
// CFGBuilder.h - Instructions to per-function control-flow graphs.
//
// Two passes: collect every branch target to establish leaders, then walk each
// function's reachable instructions splitting at leaders and terminators.
//
// Also resolves jump tables where it can, and records where it cannot, so an
// incomplete CFG is labelled incomplete rather than presented as final.
//
#include "CFG.h"
#include "Function.h"        // FunctionCandidate
#include "sp/core/Error.h"
#include "sp/disasm/CodeMap.h"
#include "sp/disasm/InstructionStorage.h"
#include "sp/db/EntityId.h"
#include "sp/db/FactStore.h"

#include <map>
#include <set>
#include <vector>

namespace sp::analysis {

struct CFGBuildOptions {
    // Attempt bounded jump-table recovery for indirect jumps.
    bool resolve_jump_tables = true;

    // Split a block when a branch lands mid-instruction (overlapping code).
    // Rare in compiler output, common in obfuscated binaries.
    bool handle_overlapping_instructions = true;

    // Treat calls to known noreturn functions as block terminators, which
    // materially improves boundary accuracy around error paths.
    bool respect_noreturn = true;

    // Flag single-jump functions as thunks. An import-heavy binary has hundreds
    // of these and listing them as ordinary functions buries the real ones.
    bool detect_thunks = true;
};

struct CFGBuildStats {
    std::size_t functions_built = 0;
    std::size_t blocks_built = 0;
    std::size_t edges_built = 0;
    std::size_t unresolved_indirect_jumps = 0;
    std::size_t jump_tables_resolved = 0;
    std::size_t overlapping_blocks = 0;

    // Times a block's fall-through landed on another function's entry and was
    // treated as end-of-function instead of an edge. A high count means many
    // noreturn calls are going unrecognised.
    std::size_t fallthrough_boundaries = 0;
};

// Shared knowledge a single-function build needs about the rest of the image.
//
// `function_entries` exists specifically for tail-call detection. A `jmp` whose
// target is another function's entry is a boundary, not an edge - follow it as
// an edge and this function silently absorbs the next one, and then the one
// after that. Distinguishing the two cases is impossible without knowing where
// other functions start, which is why discovery must run before CFG building.
struct CFGBuildContext {
    const std::set<core::VA>* function_entries = nullptr;

    // Block leaders across the whole image. Precomputed once in build_all.
    const std::set<core::VA>* leaders = nullptr;

    // Functions that never return (exit, abort, ExitProcess). A call to one
    // terminates its block; without this, unrelated code sitting after an error
    // path gets merged into the same block.
    const std::set<core::VA>* noreturn_functions = nullptr;

    // Authoritative function extents from .pdata, keyed by start address.
    //
    // Inferring a function's end from where the next one begins only works if
    // the next one was found. In a region reached entirely through function
    // pointers there are no direct call targets and nothing to infer from, so
    // the walk runs on until it happens to hit a return. This is the hard bound
    // that stops that.
    const std::map<core::VA, core::VA>* function_extents = nullptr;
};

class CFGBuilder {
public:
    // Build a CFG for each candidate. Candidates that turn out to be inside an
    // already-built function are merged rather than duplicated.
    core::Status build_all(const db::FactStore& facts,
                          const disasm::InstructionStorage& instructions,
                          const disasm::CodeMap& map,
                          const std::vector<FunctionCandidate>& candidates,
                          const CFGBuildOptions& options,
                          db::EntityIdAllocator& ids,
                          std::map<core::VA, Function>& out_functions);

    // Build one function's CFG starting at `entry`.
    core::Result<Function> build_function(const db::FactStore& facts,
                                         const disasm::InstructionStorage& instructions,
                                         core::VA entry,
                                         const CFGBuildContext& context,
                                         const CFGBuildOptions& options,
                                         db::EntityIdAllocator& ids);

    // Addresses that must begin a basic block: branch targets, the fall-through
    // of a conditional branch, and function entries.
    static std::set<core::VA> compute_leaders(const disasm::InstructionStorage& instructions,
                                              const std::vector<core::VA>& function_entries);

    // Imported or exported symbols known never to return.
    static std::set<core::VA> find_noreturn_functions(const db::FactStore& facts);

    const CFGBuildStats& stats() const { return stats_; }

private:
    CFGBuildStats stats_;
};

} // namespace sp::analysis
