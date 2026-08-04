#pragma once
//
// BasicBlock.h - Maximal straight-line instruction run.
//
// A block starts at a branch target or a function entry and ends at the first
// control-flow terminator or immediately before the next known target.
//
#include "sp/core/Types.h"
#include "sp/core/Confidence.h"
#include "sp/db/EntityId.h"

#include <cstddef>
#include <vector>

namespace sp::analysis {

enum class EdgeKind : std::uint8_t {
    FallThrough = 0,   // untaken conditional branch, or sequential flow
    Taken,             // taken conditional branch
    Jump,              // unconditional jump
    IndirectJump,      // resolved through a jump table
    Call,              // included only in the call graph, not the CFG
    Return,
};

const char* to_string(EdgeKind k);

struct Edge {
    core::VA target = core::kInvalidVA;
    EdgeKind kind = EdgeKind::FallThrough;
    core::Confidence confidence = core::Confidence::None;
};

struct BasicBlock {
    db::EntityId id = db::kNoEntity;

    core::VA start = core::kInvalidVA;
    core::VA end = core::kInvalidVA;      // exclusive; == last insn end_address

    // Instruction start addresses in order. Instructions themselves live in
    // InstructionStorage; blocks index into it rather than owning copies.
    std::vector<core::VA> instructions;

    std::vector<Edge> successors;
    std::vector<core::VA> predecessors;

    // Set when control leaves through an unresolved indirect branch, so the CFG
    // is explicit about being incomplete here rather than looking closed.
    bool has_unresolved_exit = false;

    std::size_t instruction_count() const { return instructions.size(); }
    std::size_t byte_size() const { return static_cast<std::size_t>(end - start); }
};

} // namespace sp::analysis
