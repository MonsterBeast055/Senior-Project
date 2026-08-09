#pragma once
//
// FunctionSummarizer.h - Fills in the consumer-facing fields of a Function.
//
// Everything here exists to serve the layers above: content hashes for caching,
// complexity for model routing, API names and strings for prompt quality, and an
// information score for triage.
//
// Deliberately separate from CFGBuilder. Graph construction is about
// correctness; this is about presentation, and mixing the two would make the
// builder's tests harder to reason about.
//
#include "sp/analysis/Function.h"
#include "sp/analysis/StringExtractor.h"
#include "sp/analysis/SymbolTable.h"
#include "sp/db/FactStore.h"
#include "sp/disasm/InstructionStorage.h"

#include <cstdint>
#include <map>

namespace sp::analysis {

class FunctionSummarizer {
public:
    struct Inputs {
        const db::FactStore* facts = nullptr;
        const disasm::InstructionStorage* instructions = nullptr;
        const SymbolTable* symbols = nullptr;
        const StringExtractor* strings = nullptr;
    };

    // Populate content_hash, cyclomatic_complexity, api_calls,
    // referenced_strings and information_score for every function.
    static void summarize_all(const Inputs& inputs,
                             std::map<core::VA, Function>& functions);

    static void summarize(const Inputs& inputs, Function& function);

    // FNV-1a over the function's instruction bytes.
    //
    // Immediate operands are masked out so that the same code compiled at a
    // different base address, or with different relocated constants, still
    // hashes identically. Without that masking the cache would miss on nearly
    // every library function, which defeats the point.
    static std::uint64_t compute_content_hash(
        const disasm::InstructionStorage& instructions,
        const Function& function);

    // 0-100 estimate of how much there is worth explaining here.
    static unsigned compute_information_score(const Function& function);
};

} // namespace sp::analysis
