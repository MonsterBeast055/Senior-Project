#include "sp/analysis/FunctionSummarizer.h"

#include <algorithm>
#include <set>

namespace sp::analysis {
namespace {

constexpr std::uint64_t kFnvOffset = 1469598103934665603ull;
constexpr std::uint64_t kFnvPrime = 1099511628211ull;

void hash_byte(std::uint64_t& state, std::uint8_t byte)
{
    state ^= byte;
    state *= kFnvPrime;
}

} // namespace

std::uint64_t FunctionSummarizer::compute_content_hash(
    const disasm::InstructionStorage& instructions,
    const Function& function)
{
    std::uint64_t state = kFnvOffset;

    // Walk blocks in address order so the hash is independent of the order the
    // CFG builder happened to discover them in.
    std::vector<core::VA> addresses;
    for (const BasicBlock* block : function.cfg.blocks()) {
        addresses.insert(addresses.end(),
                         block->instructions.begin(), block->instructions.end());
    }
    std::sort(addresses.begin(), addresses.end());

    for (core::VA address : addresses) {
        const disasm::InstructionInfo* insn = instructions.get(address);
        if (insn == nullptr) {
            continue;
        }

        // Hash the mnemonic rather than raw bytes, plus the instruction length.
        //
        // Raw bytes embed absolute addresses and relocated constants, so the
        // same library function compiled into two different binaries would hash
        // differently and the cache would never hit. The mnemonic sequence is
        // stable across builds while still being specific enough that two
        // genuinely different functions do not collide.
        for (char c : insn->mnemonic) {
            hash_byte(state, static_cast<std::uint8_t>(c));
        }
        hash_byte(state, static_cast<std::uint8_t>(insn->size));
        hash_byte(state, static_cast<std::uint8_t>(insn->flow));
    }

    // Fold in the shape of the function so two different routines that happen
    // to share a mnemonic sequence still separate.
    hash_byte(state, static_cast<std::uint8_t>(function.cfg.block_count() & 0xFF));
    hash_byte(state, static_cast<std::uint8_t>(function.cfg.edge_count() & 0xFF));

    return state;
}

unsigned FunctionSummarizer::compute_information_score(const Function& function)
{
    // A rough, deliberately transparent heuristic. The point is not precision -
    // it is giving the AI layer a single number to sort and threshold on, so it
    // does not have to reimplement this analysis to decide what is worth an
    // expensive model call.
    unsigned score = 0;

    // Imported API calls are the strongest signal of purpose.
    score += static_cast<unsigned>(std::min<std::size_t>(function.api_calls.size(), 8) * 7);

    // Strings are nearly as good, often better.
    score += static_cast<unsigned>(
        std::min<std::size_t>(function.referenced_strings.size(), 6) * 6);

    // Some size, but with diminishing returns - a 5000-instruction function is
    // not 100x more interesting than a 50-instruction one.
    if (function.instruction_count >= 10)  score += 5;
    if (function.instruction_count >= 40)  score += 5;
    if (function.instruction_count >= 150) score += 5;

    // Branching means logic worth explaining.
    score += static_cast<unsigned>(
        std::min<std::size_t>(function.cyclomatic_complexity, 10));

    // Widely-called code is worth understanding well.
    if (function.callers.size() >= 3)  score += 3;
    if (function.callers.size() >= 10) score += 3;

    // --- Reasons to spend nothing on this ---------------------------------
    if (function.is_thunk || function.is_imported_stub) {
        return 0;
    }
    if (function.is_library_code) {
        score /= 4;
    }
    // Tiny and featureless: describe it mechanically instead.
    if (function.instruction_count < 5 && function.api_calls.empty()
        && function.referenced_strings.empty()) {
        return 0;
    }

    return std::min<unsigned>(score, 100);
}

void FunctionSummarizer::summarize(const Inputs& inputs, Function& function)
{
    if (inputs.instructions == nullptr) {
        return;
    }

    function.content_hash = compute_content_hash(*inputs.instructions, function);

    // E - N + 2, floored at 1 for a single-block function.
    const std::size_t nodes = function.cfg.block_count();
    const std::size_t edges = function.cfg.edge_count();
    function.cyclomatic_complexity = (edges + 2 > nodes) ? (edges - nodes + 2) : 1;

    // --- API calls and strings -------------------------------------------
    std::set<std::string> apis;
    std::set<std::string> strings;

    for (const BasicBlock* block : function.cfg.blocks()) {
        for (core::VA address : block->instructions) {
            const disasm::InstructionInfo* insn = inputs.instructions->get(address);
            if (insn == nullptr) {
                continue;
            }

            if (insn->is_call() && inputs.symbols != nullptr) {
                // Direct call to a named function.
                if (insn->direct_target.has_value()) {
                    const Symbol* symbol = inputs.symbols->lookup(*insn->direct_target);
                    if (symbol != nullptr && symbol->source != SymbolSource::Generated) {
                        apis.insert(symbol->name);
                    }
                }
                // Indirect call reading an IAT slot. This is how nearly every
                // Windows API call actually appears, so without resolving it the
                // api_calls list would be almost empty on real binaries.
                else if (insn->memory_reference.has_value()) {
                    const Symbol* symbol =
                        inputs.symbols->resolve_iat_slot(*insn->memory_reference);
                    if (symbol != nullptr) {
                        apis.insert(symbol->name);
                    }
                }
            }

            // A tail-call jmp through the IAT is also an API use.
            if (insn->is_unconditional_jump() && insn->memory_reference.has_value()
                && inputs.symbols != nullptr) {
                const Symbol* symbol =
                    inputs.symbols->resolve_iat_slot(*insn->memory_reference);
                if (symbol != nullptr) {
                    apis.insert(symbol->name);
                }
            }

            if (inputs.strings != nullptr && insn->memory_reference.has_value()) {
                const ExtractedString* text =
                    inputs.strings->string_at(*insn->memory_reference);
                if (text != nullptr) {
                    strings.insert(text->text);
                }
            }
        }
    }

    function.api_calls.assign(apis.begin(), apis.end());
    function.referenced_strings.assign(strings.begin(), strings.end());

    function.information_score = compute_information_score(function);
}

void FunctionSummarizer::summarize_all(const Inputs& inputs,
                                      std::map<core::VA, Function>& functions)
{
    for (auto& entry : functions) {
        summarize(inputs, entry.second);
    }
}

} // namespace sp::analysis
