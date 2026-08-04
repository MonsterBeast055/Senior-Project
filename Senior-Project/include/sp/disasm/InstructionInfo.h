#pragma once
//
// InstructionInfo.h - One decoded instruction.
//
// Architecture-neutral view of a decoded instruction, carrying enough
// classification for CFG construction without the rest of the project needing
// to include Capstone headers.
//
#include "sp/core/Types.h"
#include "sp/core/Provenance.h"
#include "sp/db/EntityId.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sp::disasm {

// How control leaves this instruction. Drives basic-block termination.
enum class FlowKind : std::uint8_t {
    Sequential = 0,        // falls through to the next instruction
    ConditionalJump,       // two successors: target and fall-through
    UnconditionalJump,     // one successor: target
    Call,                  // returns, so fall-through is a successor
    Return,                // leaves the function
    Interrupt,             // int3, syscall - may or may not return
    Halt,                  // hlt, ud2 - terminal
    Unknown,
};

const char* to_string(FlowKind k);

struct InstructionInfo {
    // Stable identity, so annotations survive re-analysis.
    db::EntityId id = db::kNoEntity;

    core::VA address = core::kInvalidVA;
    std::uint16_t size = 0;

    std::string mnemonic;
    std::string op_str;

    std::vector<std::uint8_t> bytes;

    FlowKind flow = FlowKind::Sequential;

    // True when the branch/call destination is computed at runtime (register or
    // memory operand) and therefore not statically known here.
    bool is_indirect = false;

    // Resolved destination for direct branches and calls. Absent for indirect
    // control flow until a later pass resolves it.
    std::optional<core::VA> direct_target;

    // For indirect control flow resolved through a jump table, the recovered
    // set of possible destinations.
    std::vector<core::VA> resolved_targets;

    // Address of the next instruction, when control can fall through.
    std::optional<core::VA> fall_through;

    // Why we believe these bytes are an instruction at all.
    core::ProvenanceSet provenance;

    // --- Convenience predicates ------------------------------------------
    bool is_call() const { return flow == FlowKind::Call; }
    bool is_return() const { return flow == FlowKind::Return; }

    bool is_jump() const
    {
        return flow == FlowKind::ConditionalJump || flow == FlowKind::UnconditionalJump;
    }

    bool is_conditional_jump() const { return flow == FlowKind::ConditionalJump; }
    bool is_unconditional_jump() const { return flow == FlowKind::UnconditionalJump; }

    // Does control flow continue past this instruction linearly?
    bool has_fall_through() const
    {
        switch (flow) {
        case FlowKind::UnconditionalJump:
        case FlowKind::Return:
        case FlowKind::Halt:
            return false;
        default:
            return true;
        }
    }

    // Terminates a basic block?
    bool terminates_block() const
    {
        return flow != FlowKind::Sequential && flow != FlowKind::Call;
    }

    core::VA end_address() const { return address + size; }
};

} // namespace sp::disasm
