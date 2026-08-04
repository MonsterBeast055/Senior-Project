#pragma once
//
// Function.h - The primary unit of analysis and display.
//
// Wraps a CFG with the metadata the frontend and the model both need: extent,
// how it was discovered, calling convention, callers and callees.
//
#include "CFG.h"
#include "sp/core/Types.h"
#include "sp/core/Provenance.h"
#include "sp/db/EntityId.h"

#include <optional>
#include <string>
#include <vector>

namespace sp::analysis {

enum class CallingConvention : std::uint8_t {
    Unknown = 0,
    Cdecl,
    Stdcall,
    Fastcall,
    Thiscall,
    Win64,      // Microsoft x64
    SysV64,
};

const char* to_string(CallingConvention c);

// Recovered stack frame shape. Needed to distinguish parameters from locals,
// which is the difference between disassembly a model can reason about and a
// wall of rbp-relative offsets.
struct StackFrame {
    std::int64_t local_size = 0;      // bytes reserved for locals
    std::int64_t saved_regs_size = 0;
    bool uses_frame_pointer = false;
    bool has_variadic_tail = false;
};

// A possible function start plus the evidence for it. Produced by
// FunctionDiscovery and consumed by CFGBuilder, so it lives here rather than in
// either pass.
struct FunctionCandidate {
    core::VA entry = core::kInvalidVA;
    core::ProvenanceSet provenance;
};

struct Function {
    db::EntityId id = db::kNoEntity;

    core::VA entry = core::kInvalidVA;

    // Highest address reached by any block, exclusive. Functions are not
    // necessarily contiguous, so this is an extent rather than a size.
    core::VA extent_end = core::kInvalidVA;

    CFG cfg;

    // Why we believe a function starts here.
    core::ProvenanceSet provenance;

    CallingConvention convention = CallingConvention::Unknown;
    StackFrame frame;

    std::vector<core::VA> callees;   // direct calls out
    std::vector<core::VA> callers;   // direct calls in

    // Calls through registers or unresolved memory operands. Their presence
    // means the call graph is incomplete for this function - stated explicitly
    // so downstream consumers do not over-trust it.
    std::size_t indirect_call_count = 0;

    bool is_thunk = false;           // single jmp to another function
    bool is_imported_stub = false;   // jmp [IAT slot]
    bool returns = true;             // false for noreturn (exit, abort, ...)
    bool is_library_code = false;    // matched a known library signature

    std::size_t instruction_count = 0;

    core::Confidence confidence() const { return provenance.effective_confidence(); }
};

} // namespace sp::analysis
