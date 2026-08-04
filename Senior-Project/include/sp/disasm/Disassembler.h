#pragma once
//
// Disassembler.h - Bytes to classified instructions.
//
// Wraps Capstone and owns the decode strategy. Responsibilities:
//   1. seed the worklist from trusted function starts (entry point, exports,
//      .pdata unwind info, TLS callbacks)
//   2. recursive descent, following direct branches and calls
//   3. optional linear sweep over bytes still unclaimed afterwards, recorded at
//      Low confidence
//   4. maintain the CodeMap so every byte's status is known
//   5. support retraction when a later pass proves a region was data
//
// The Capstone handle never escapes this class.
//
#include "InstructionInfo.h"
#include "InstructionStorage.h"
#include "CodeMap.h"
#include "DecodeQueue.h"

#include "sp/core/Error.h"
#include "sp/core/Types.h"
#include "sp/db/FactStore.h"
#include "sp/db/EntityId.h"

#include <memory>
#include <vector>

namespace sp::disasm {

struct DisassemblyOptions {
    // Follow direct call and jump targets. The main strategy.
    bool recursive_descent = true;

    // After descent is exhausted, sweep unclaimed executable bytes. Finds code
    // reached only indirectly, at the cost of some false positives - which is
    // why the results are marked Low confidence rather than silently mixed in.
    bool linear_sweep_fallback = true;

    // Attempt to recover jump-table targets for indirect jumps.
    bool resolve_jump_tables = true;

    // Treat long runs of int3 / nop / zero as padding rather than code.
    bool detect_padding = true;

    // 0 = unlimited. Safety valve for pathological inputs.
    std::size_t max_instructions = 0;
};

struct DisassemblyStats {
    std::size_t instructions_decoded = 0;
    std::size_t decode_failures = 0;
    std::size_t from_recursive_descent = 0;
    std::size_t from_linear_sweep = 0;
    std::size_t retracted = 0;
    double code_coverage = 0.0;   // fraction of executable bytes explained
};

class Disassembler {
public:
    Disassembler();
    ~Disassembler();

    Disassembler(const Disassembler&) = delete;
    Disassembler& operator=(const Disassembler&) = delete;

    // Open the Capstone engine for the architecture recorded in `facts`.
    core::Status initialize(const db::FactStore& facts);

    // Run the full strategy over every executable section.
    core::Status run(const db::FactStore& facts,
                    const DisassemblyOptions& options,
                    db::EntityIdAllocator& ids,
                    InstructionStorage& out_instructions,
                    CodeMap& out_map);

    // Decode a single instruction at `address`. Building block for the passes
    // above and for on-demand decoding from the UI.
    core::Result<InstructionInfo> decode_one(const db::FactStore& facts,
                                            core::VA address,
                                            db::EntityIdAllocator& ids);

    // Decode a straight run starting at `address` until a block terminator, a
    // decode failure, or a byte already claimed as data.
    core::Status decode_block(const db::FactStore& facts,
                             core::VA address,
                             db::EntityIdAllocator& ids,
                             InstructionStorage& out,
                             CodeMap& map,
                             DecodeQueue& queue);

    // Withdraw a misdecoded region: drop its instructions and mark it data.
    // The mechanism behind revisable analysis.
    core::Status retract_range(core::VA start, core::VA end,
                              core::ProvenanceKind reason,
                              InstructionStorage& instructions,
                              CodeMap& map);

    const DisassemblyStats& stats() const { return stats_; }

private:
    // Seed the worklist from every trusted source in `facts`.
    void seed_from_facts(const db::FactStore& facts, DecodeQueue& queue);

    struct Impl;                  // hides csh / cs_insn
    std::unique_ptr<Impl> impl_;
    DisassemblyStats stats_;
};

} // namespace sp::disasm
