#pragma once
//
// DotExporter.h - Graphviz output.
//
// Not the product surface - the frontend renders from JSON. This exists because
// during development you need to eyeball a CFG immediately, and it is the
// fastest way to spot a wrong edge or a bad block split.
//
#include "sp/analysis/CFG.h"
#include "sp/analysis/CallGraph.h"
#include "sp/analysis/Function.h"
#include "sp/analysis/SymbolTable.h"
#include "sp/core/Error.h"
#include "sp/disasm/InstructionStorage.h"

#include <map>
#include <ostream>

namespace sp::serialize {

struct DotOptions {
    bool show_instructions = true;
    bool show_addresses = true;

    // Colour blocks by confidence, making speculative decodes obvious at a
    // glance.
    bool color_by_confidence = true;

    std::size_t max_instructions_per_block = 40;
};

class DotExporter {
public:
    static core::Status export_cfg(const analysis::Function& function,
                                  const disasm::InstructionStorage& instructions,
                                  const analysis::SymbolTable& symbols,
                                  const DotOptions& options,
                                  std::ostream& out);

    static core::Status export_call_graph(const analysis::CallGraph& call_graph,
                                         const analysis::SymbolTable& symbols,
                                         const DotOptions& options,
                                         std::ostream& out);
};

} // namespace sp::serialize
