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

    // --- Consumer-facing summary -----------------------------------------

    // Hash of this function's instruction bytes.
    //
    // Exists for the AI layer's cache. Only the engine can compute it, because
    // only the engine has the bytes - and library code is byte-identical across
    // binaries, so `memcpy` need only ever be analysed once. This is the single
    // biggest cost reduction available downstream.
    std::uint64_t content_hash = 0;

    // Edges - nodes + 2. A cheap difficulty metric, used downstream to route
    // simple functions to a cheaper model.
    std::size_t cyclomatic_complexity = 0;

    // Imported APIs this function calls, e.g. "kernel32!CreateFileW".
    // Resolved through IAT slots, so indirect calls are included. Usually the
    // most informative single field about what a function does.
    std::vector<std::string> api_calls;

    // Read-only string literals referenced by this function.
    std::vector<std::string> referenced_strings;

    // How much there is here worth explaining, 0-100.
    //
    // A triage hint so the AI layer does not have to reimplement half of this
    // analysis in JavaScript to decide what deserves an expensive model call.
    unsigned information_score = 0;

    core::Confidence confidence() const { return provenance.effective_confidence(); }
};

} // namespace sp::analysis
