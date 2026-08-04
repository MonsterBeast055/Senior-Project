#include "sp/serialize/DotExporter.h"

#include <iomanip>
#include <sstream>

namespace sp::serialize {
namespace {

std::string hex(std::uint64_t value)
{
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}

// Graphviz record labels treat these as syntax, so they have to be escaped or
// the whole graph fails to render.
std::string escape(const std::string& text)
{
    std::string out;
    out.reserve(text.size() + 8);
    for (char c : text) {
        switch (c) {
        case '<': case '>': case '{': case '}':
        case '|': case '"': case '\\':
            out.push_back('\\');
            out.push_back(c);
            break;
        case '\n':
            out += "\\l";
            break;
        default:
            out.push_back(c);
            break;
        }
    }
    return out;
}

const char* confidence_color(core::Confidence c)
{
    // Speculative blocks should be obvious at a glance - that is the entire
    // reason this exporter exists during development.
    switch (c) {
    case core::Confidence::Certain: return "#1d9e75";  // teal
    case core::Confidence::High:    return "#378add";  // blue
    case core::Confidence::Medium:  return "#ba7517";  // amber
    case core::Confidence::Low:     return "#e24b4a";  // red
    case core::Confidence::None:
    default:                        return "#888780";  // grey
    }
}

const char* edge_style(analysis::EdgeKind kind)
{
    switch (kind) {
    case analysis::EdgeKind::Taken:        return "color=\"#1d9e75\", label=\"T\"";
    case analysis::EdgeKind::FallThrough:  return "color=\"#888780\"";
    case analysis::EdgeKind::Jump:         return "color=\"#378add\"";
    case analysis::EdgeKind::IndirectJump: return "color=\"#ba7517\", style=dashed";
    case analysis::EdgeKind::Call:         return "color=\"#7f77dd\", style=dotted";
    case analysis::EdgeKind::Return:       return "color=\"#888780\", style=dotted";
    default:                               return "color=\"#888780\"";
    }
}

std::string node_id(core::VA address)
{
    std::ostringstream out;
    out << "b" << std::hex << address;
    return out.str();
}

} // namespace

core::Status DotExporter::export_cfg(const analysis::Function& function,
                                    const disasm::InstructionStorage& instructions,
                                    const analysis::SymbolTable& symbols,
                                    const DotOptions& options,
                                    std::ostream& out)
{
    const std::string name = symbols.name_for(function.entry);

    out << "digraph cfg_" << std::hex << function.entry << " {\n";
    out << "  graph [label=\"" << escape(name) << "  " << hex(function.entry)
        << "\", labelloc=t, fontname=\"Consolas\", fontsize=12];\n";
    out << "  node [shape=record, fontname=\"Consolas\", fontsize=10];\n";
    out << "  edge [fontname=\"Consolas\", fontsize=9];\n\n";

    // Emit in reverse post-order so the layout reads roughly top to bottom the
    // way execution runs.
    std::vector<core::VA> order = function.cfg.reverse_post_order();
    for (const analysis::BasicBlock* block : function.cfg.blocks()) {
        bool present = false;
        for (core::VA va : order) {
            if (va == block->start) { present = true; break; }
        }
        if (!present) {
            // Unreachable block: still drawn, so a bad decode is visible rather
            // than silently dropped from the picture.
            order.push_back(block->start);
        }
    }

    for (core::VA block_start : order) {
        const analysis::BasicBlock* block = function.cfg.block_at(block_start);
        if (block == nullptr) {
            continue;
        }

        std::ostringstream label;

        // Only print a standalone block header when the instruction listing is
        // suppressed. Otherwise the first instruction already shows this exact
        // address and the header is just noise.
        if (!options.show_instructions || !options.show_addresses) {
            label << hex(block->start) << "\\l";
        }

        if (options.show_instructions) {
            std::size_t shown = 0;
            for (core::VA address : block->instructions) {
                if (shown >= options.max_instructions_per_block) {
                    label << "... (" << (block->instructions.size() - shown) << " more)\\l";
                    break;
                }
                const disasm::InstructionInfo* insn = instructions.get(address);
                if (insn == nullptr) {
                    continue;
                }
                if (options.show_addresses) {
                    label << hex(address) << "  ";
                }
                label << escape(insn->mnemonic);
                if (!insn->op_str.empty()) {
                    label << " " << escape(insn->op_str);
                }

                // Annotate the destination of a call or branch with its name -
                // the difference between a readable graph and a wall of hex.
                if (insn->direct_target.has_value()
                    && (insn->is_call() || insn->is_jump())) {
                    const std::string target = symbols.name_for(*insn->direct_target);
                    if (target.rfind("sub_", 0) != 0) {
                        label << "   ; " << escape(target);
                    }
                }
                label << "\\l";
                ++shown;
            }
        }

        if (block->has_unresolved_exit) {
            // Stated on the graph itself, so an incomplete CFG never reads as a
            // complete one.
            label << "[unresolved exit]\\l";
        }

        core::Confidence confidence = core::Confidence::None;
        if (!block->instructions.empty()) {
            const disasm::InstructionInfo* first = instructions.get(block->instructions.front());
            if (first != nullptr) {
                confidence = first->provenance.effective_confidence();
            }
        }

        out << "  " << node_id(block->start) << " [label=\"{" << label.str() << "}\"";
        if (options.color_by_confidence) {
            out << ", color=\"" << confidence_color(confidence) << "\"";
        }
        if (block->start == function.entry) {
            out << ", penwidth=2";
        }
        if (block->has_unresolved_exit) {
            out << ", style=dashed";
        }
        out << "];\n";
    }

    out << "\n";

    for (const analysis::BasicBlock* block : function.cfg.blocks()) {
        for (const analysis::Edge& edge : block->successors) {
            out << "  " << node_id(block->start) << " -> " << node_id(edge.target)
                << " [" << edge_style(edge.kind) << "];\n";
        }
    }

    out << "}\n";
    return core::Status::success();
}

core::Status DotExporter::export_call_graph(const analysis::CallGraph& call_graph,
                                           const analysis::SymbolTable& symbols,
                                           const DotOptions& options,
                                           std::ostream& out)
{
    (void)options;

    out << "digraph callgraph {\n";
    out << "  node [shape=box, fontname=\"Consolas\", fontsize=10];\n";
    out << "  edge [color=\"#888780\"];\n\n";

    for (core::VA function : call_graph.root_functions()) {
        out << "  " << node_id(function)
            << " [label=\"" << escape(symbols.name_for(function)) << "\", penwidth=2];\n";
    }

    for (core::VA caller : call_graph.reverse_topological_order()) {
        const std::set<core::VA>* callees = call_graph.callees_of(caller);
        out << "  " << node_id(caller)
            << " [label=\"" << escape(symbols.name_for(caller)) << "\"];\n";

        if (callees == nullptr) {
            continue;
        }
        for (core::VA callee : *callees) {
            out << "  " << node_id(caller) << " -> " << node_id(callee) << ";\n";
        }
    }

    out << "}\n";
    return core::Status::success();
}

} // namespace sp::serialize
