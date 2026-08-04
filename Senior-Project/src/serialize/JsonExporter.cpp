#include "sp/serialize/JsonExporter.h"

#include <iomanip>
#include <sstream>

namespace sp::serialize {
namespace {

// Minimal JSON writer. A dependency-free hand-rolled emitter is deliberate: the
// output shape is a published contract with the frontend and the n8n layer, and
// keeping it in one readable file makes that contract auditable.
class JsonWriter {
public:
    JsonWriter(std::ostream& out, bool pretty) : out_(out), pretty_(pretty) {}

    void begin_object() { punctuate(); out_ << '{'; ++depth_; first_ = true; }
    void end_object()   { --depth_; newline(); out_ << '}'; first_ = false; }
    void begin_array()  { punctuate(); out_ << '['; ++depth_; first_ = true; }
    void end_array()    { --depth_; newline(); out_ << ']'; first_ = false; }

    void key(const std::string& name)
    {
        punctuate();
        out_ << '"' << name << '"' << ':';
        if (pretty_) out_ << ' ';
        pending_key_ = true;
    }

    void string_value(const std::string& value)
    {
        punctuate();
        out_ << '"' << escape(value) << '"';
        first_ = false;
    }

    void raw_value(const std::string& value) { punctuate(); out_ << value; first_ = false; }

    // One overload per distinct arithmetic category. No std::size_t overload:
    // on every 64-bit target size_t and uint64_t are the same type, so having
    // both is a redefinition rather than an overload.
    void number(std::uint64_t v) { raw_value(std::to_string(v)); }
    void signed_number(std::int64_t v) { raw_value(std::to_string(v)); }
    void number(double v)
    {
        std::ostringstream tmp;
        tmp << std::fixed << std::setprecision(4) << v;
        raw_value(tmp.str());
    }
    void boolean(bool v) { raw_value(v ? "true" : "false"); }
    void null_value()    { raw_value("null"); }

    // Addresses go out as hex strings, never numbers: a 64-bit VA does not
    // survive a round trip through a JavaScript number.
    void address(core::VA va)
    {
        if (va == core::kInvalidVA) { null_value(); return; }
        std::ostringstream tmp;
        tmp << "0x" << std::hex << va;
        string_value(tmp.str());
    }

    void field(const std::string& name, const std::string& value) { key(name); string_value(value); }

    // This overload is load-bearing. Without it, field(name, some_to_string())
    // binds const char* to the bool overload - pointer-to-bool is a standard
    // conversion and beats const char* -> std::string, which is user-defined.
    // Every enum name in the output silently becomes `true`.
    void field(const std::string& name, const char* value)
    {
        key(name);
        string_value(value != nullptr ? value : "");
    }

    void field(const std::string& name, std::uint64_t value)      { key(name); number(value); }
    void field(const std::string& name, double value)             { key(name); number(value); }
    void field(const std::string& name, bool value)               { key(name); boolean(value); }
    void signed_field(const std::string& name, std::int64_t value) { key(name); signed_number(value); }
    void address_field(const std::string& name, core::VA va)      { key(name); address(va); }

private:
    void punctuate()
    {
        if (pending_key_) { pending_key_ = false; return; }
        if (!first_) out_ << ',';
        newline();
        first_ = false;
    }

    void newline()
    {
        if (!pretty_) return;
        out_ << '\n';
        for (int i = 0; i < depth_; ++i) out_ << "  ";
    }

    static std::string escape(const std::string& text)
    {
        std::string out;
        out.reserve(text.size() + 8);
        for (unsigned char c : text) {
            switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    std::ostringstream tmp;
                    tmp << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(c);
                    out += tmp.str();
                } else {
                    out.push_back(static_cast<char>(c));
                }
            }
        }
        return out;
    }

    std::ostream& out_;
    bool pretty_;
    int depth_ = 0;
    bool first_ = true;
    bool pending_key_ = false;
};

std::string bytes_to_hex(const std::vector<std::uint8_t>& bytes)
{
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::uint8_t b : bytes) {
        out << std::setw(2) << static_cast<int>(b);
    }
    return out.str();
}

core::Status require(const JsonExporter::Inputs& inputs)
{
    if (inputs.facts == nullptr) {
        return core::Error(core::ErrorCode::InvalidArgument, "facts is required");
    }
    return core::Status::success();
}

void write_provenance(JsonWriter& json, const core::ProvenanceSet& provenance)
{
    json.begin_array();
    for (const auto& record : provenance.records()) {
        if (record.retracted) {
            continue;
        }
        json.begin_object();
        json.field("kind", core::to_string(record.kind));
        json.field("confidence", core::to_string(record.confidence));
        json.address_field("source", record.source);
        json.end_object();
    }
    json.end_array();
}

void write_instruction(JsonWriter& json,
                      const disasm::InstructionInfo& insn,
                      const analysis::SymbolTable* symbols,
                      const JsonOptions& options)
{
    json.begin_object();
    json.address_field("va", insn.address);
    json.field("size", static_cast<std::uint64_t>(insn.size));
    json.field("mnemonic", insn.mnemonic);
    json.field("operands", insn.op_str);
    json.field("flow", disasm::to_string(insn.flow));

    if (options.include_bytes) {
        json.field("bytes", bytes_to_hex(insn.bytes));
    }

    json.key("target");
    if (insn.direct_target.has_value()) {
        json.address(*insn.direct_target);
    } else {
        json.null_value();
    }

    // Resolved symbol for the branch destination. This single field is what
    // turns "call 0x140001a20" into something a human or a model can act on.
    json.key("target_name");
    if (insn.direct_target.has_value() && symbols != nullptr) {
        json.string_value(symbols->name_for(*insn.direct_target));
    } else {
        json.null_value();
    }

    json.field("indirect", insn.is_indirect);

    if (!insn.resolved_targets.empty()) {
        json.key("resolved_targets");
        json.begin_array();
        for (core::VA target : insn.resolved_targets) {
            json.address(target);
        }
        json.end_array();
    }

    if (options.include_confidence) {
        json.field("confidence", core::to_string(insn.provenance.effective_confidence()));
    }
    if (options.include_provenance) {
        json.key("provenance");
        write_provenance(json, insn.provenance);
    }

    json.end_object();
}

void write_function_summary(JsonWriter& json,
                          const analysis::Function& function,
                          const analysis::SymbolTable* symbols,
                          const JsonOptions& options)
{
    json.begin_object();
    json.field("id", function.id.raw);
    json.address_field("va", function.entry);
    json.field("name", symbols != nullptr ? symbols->name_for(function.entry)
                                          : analysis::SymbolTable::generated_name(function.entry, true));
    json.address_field("extent_end", function.extent_end);
    json.field("block_count", function.cfg.block_count());
    json.field("instruction_count", function.instruction_count);
    json.field("is_thunk", function.is_thunk);
    json.field("is_imported_stub", function.is_imported_stub);
    json.field("returns", function.returns);
    json.field("indirect_call_count", function.indirect_call_count);
    json.field("callee_count", function.callees.size());
    json.field("caller_count", function.callers.size());

    if (options.include_confidence) {
        json.field("confidence", core::to_string(function.confidence()));
    }
    json.end_object();
}

} // namespace

core::Status JsonExporter::export_image(const Inputs& inputs,
                                       const JsonOptions& options,
                                       std::ostream& out)
{
    if (auto status = require(inputs); !status.ok()) {
        return status;
    }

    const db::FactStore& facts = *inputs.facts;
    const core::AddressSpace& space = facts.address_space();

    JsonWriter json(out, options.pretty);
    json.begin_object();

    json.field("schema_version", std::string("1.0"));
    json.field("format", std::string("pe"));
    json.field("arch", core::to_string(facts.arch()));
    json.address_field("image_base", space.image_base());
    json.address_field("entry_point", facts.entry_point());
    json.field("image_size", facts.image_size());

    // --- Sections ---------------------------------------------------------
    json.key("sections");
    json.begin_array();
    for (const auto& section : space.sections()) {
        json.begin_object();
        json.field("name", section.name);
        json.address_field("va", space.to_va(section.rva));
        json.field("rva", static_cast<std::uint64_t>(section.rva));
        json.field("virtual_size", static_cast<std::uint64_t>(section.virtual_size));
        json.field("raw_size", static_cast<std::uint64_t>(section.raw_size));
        json.field("raw_offset", section.raw_offset);
        json.field("executable", section.executable);
        json.field("readable", section.readable);
        json.field("writable", section.writable);
        json.field("entropy", section.entropy);
        json.end_object();
    }
    json.end_array();

    // --- Imports ----------------------------------------------------------
    json.key("imports");
    json.begin_array();
    for (const auto& import : facts.imports()) {
        json.begin_object();
        json.field("library", import.library);
        json.field("name", import.name);
        json.field("by_ordinal", import.by_ordinal);
        json.field("ordinal", static_cast<std::uint64_t>(import.ordinal));
        json.address_field("iat_slot", import.iat_slot);
        json.end_object();
    }
    json.end_array();

    // --- Exports ----------------------------------------------------------
    json.key("exports");
    json.begin_array();
    for (const auto& exported : facts.exports()) {
        json.begin_object();
        json.field("name", exported.name);
        json.field("ordinal", static_cast<std::uint64_t>(exported.ordinal));
        json.address_field("va", exported.address);
        json.field("is_forwarder", exported.is_forwarder);
        json.end_object();
    }
    json.end_array();

    // --- Unwind table -----------------------------------------------------
    // Authoritative function boundaries straight from .pdata. Emitted because
    // it is the ground truth every other boundary decision is checked against,
    // and because a mismatch between this and the discovered function list is
    // the fastest way to spot a boundary bug.
    json.key("unwind_functions");
    json.begin_array();
    for (const auto& extent : facts.unwind_function_extents()) {
        json.begin_object();
        json.address_field("start", extent.first);
        json.address_field("end", extent.second);
        json.field("size", static_cast<std::uint64_t>(extent.second - extent.first));
        json.end_object();
    }
    json.end_array();

    // --- Coverage ---------------------------------------------------------
    // Reported so consumers know how much of the image was actually explained.
    // A tool that hides its own blind spots is worse than one that names them.
    json.key("coverage");
    json.begin_object();
    if (inputs.code_map != nullptr) {
        std::size_t executable_bytes = 0;
        double weighted = 0.0;
        for (const auto& section : space.sections()) {
            if (!section.executable) {
                continue;
            }
            const core::VA start = space.to_va(section.rva);
            const core::VA end = start + section.virtual_size;
            executable_bytes += section.virtual_size;
            weighted += inputs.code_map->code_coverage(start, end) * section.virtual_size;
        }
        json.field("executable_bytes", executable_bytes);
        json.field("code_fraction",
                   executable_bytes > 0 ? (weighted / executable_bytes) : 0.0);
    }
    json.field("instruction_count",
               inputs.instructions != nullptr ? inputs.instructions->size() : std::size_t{ 0 });
    json.field("function_count",
               inputs.functions != nullptr ? inputs.functions->size() : std::size_t{ 0 });

    if (options.include_unclaimed_ranges && inputs.code_map != nullptr) {
        json.key("unclaimed_ranges");
        json.begin_array();
        for (const auto& section : space.sections()) {
            if (!section.executable) {
                continue;
            }
            const core::VA start = space.to_va(section.rva);
            const core::VA end = start + section.virtual_size;
            for (const auto& gap : inputs.code_map->unclaimed_ranges(start, end)) {
                json.begin_object();
                json.address_field("start", gap.start);
                json.address_field("end", gap.end);
                json.field("size", gap.length());
                json.end_object();
            }
        }
        json.end_array();
    }
    json.end_object();

    json.end_object();
    out << "\n";
    return core::Status::success();
}

core::Status JsonExporter::export_function_list(const Inputs& inputs,
                                               const JsonOptions& options,
                                               std::ostream& out)
{
    if (auto status = require(inputs); !status.ok()) {
        return status;
    }

    JsonWriter json(out, options.pretty);
    json.begin_object();
    json.field("schema_version", std::string("1.0"));
    json.field("count",
               inputs.functions != nullptr ? inputs.functions->size() : std::size_t{ 0 });

    json.key("functions");
    json.begin_array();
    if (inputs.functions != nullptr) {
        for (const auto& [entry, function] : *inputs.functions) {
            write_function_summary(json, function, inputs.symbols, options);
        }
    }
    json.end_array();

    json.end_object();
    out << "\n";
    return core::Status::success();
}

core::Status JsonExporter::export_function(const Inputs& inputs,
                                          core::VA function_va,
                                          const JsonOptions& options,
                                          std::ostream& out)
{
    if (auto status = require(inputs); !status.ok()) {
        return status;
    }
    if (inputs.functions == nullptr || inputs.instructions == nullptr) {
        return core::Error(core::ErrorCode::InvalidArgument,
                           "functions and instructions are required");
    }

    auto it = inputs.functions->find(function_va);
    if (it == inputs.functions->end()) {
        std::ostringstream message;
        message << "no function at 0x" << std::hex << function_va;
        return core::Error(core::ErrorCode::InvalidAddress, message.str());
    }

    const analysis::Function& function = it->second;
    const analysis::SymbolTable* symbols = inputs.symbols;

    JsonWriter json(out, options.pretty);
    json.begin_object();

    json.field("schema_version", std::string("1.0"));
    json.field("id", function.id.raw);
    json.address_field("va", function.entry);
    json.field("name", symbols != nullptr ? symbols->name_for(function.entry)
                                          : analysis::SymbolTable::generated_name(function.entry, true));
    json.address_field("extent_end", function.extent_end);
    json.field("convention", analysis::to_string(function.convention));
    json.field("is_thunk", function.is_thunk);
    json.field("is_imported_stub", function.is_imported_stub);
    json.field("returns", function.returns);
    json.field("instruction_count", function.instruction_count);
    json.field("indirect_call_count", function.indirect_call_count);

    if (options.include_confidence) {
        json.field("confidence", core::to_string(function.confidence()));
    }
    if (options.include_provenance) {
        json.key("provenance");
        write_provenance(json, function.provenance);
    }

    json.key("frame");
    json.begin_object();
    json.signed_field("local_size", static_cast<std::int64_t>(function.frame.local_size));
    json.signed_field("saved_regs_size", static_cast<std::int64_t>(function.frame.saved_regs_size));
    json.field("uses_frame_pointer", function.frame.uses_frame_pointer);
    json.end_object();

    // --- Blocks -----------------------------------------------------------
    // Emitted in reverse post-order: a sensible top-to-bottom layout hint for
    // the graph view, and the correct visitation order for dataflow.
    json.key("block_order");
    json.begin_array();
    for (core::VA block_start : function.cfg.reverse_post_order()) {
        json.address(block_start);
    }
    json.end_array();

    json.key("blocks");
    json.begin_array();
    for (const analysis::BasicBlock* block : function.cfg.blocks()) {
        json.begin_object();
        json.field("id", block->id.raw);
        json.address_field("start", block->start);
        json.address_field("end", block->end);
        json.field("instruction_count", block->instruction_count());

        // Explicitly declares an incomplete graph rather than presenting a
        // successor-less block as a genuine dead end.
        json.field("has_unresolved_exit", block->has_unresolved_exit);

        json.key("instructions");
        json.begin_array();
        for (core::VA address : block->instructions) {
            const disasm::InstructionInfo* insn = inputs.instructions->get(address);
            if (insn != nullptr) {
                write_instruction(json, *insn, symbols, options);
            }
        }
        json.end_array();

        json.key("successors");
        json.begin_array();
        for (const analysis::Edge& edge : block->successors) {
            json.begin_object();
            json.address_field("target", edge.target);
            json.field("kind", analysis::to_string(edge.kind));
            if (options.include_confidence) {
                json.field("confidence", core::to_string(edge.confidence));
            }
            json.end_object();
        }
        json.end_array();

        json.key("predecessors");
        json.begin_array();
        for (core::VA pred : block->predecessors) {
            json.address(pred);
        }
        json.end_array();

        json.end_object();
    }
    json.end_array();

    // --- Relationships ----------------------------------------------------
    auto write_related = [&](const char* name, const std::vector<core::VA>& list) {
        json.key(name);
        json.begin_array();
        for (core::VA va : list) {
            json.begin_object();
            json.address_field("va", va);
            json.field("name", symbols != nullptr ? symbols->name_for(va)
                                                  : analysis::SymbolTable::generated_name(va, true));
            json.end_object();
        }
        json.end_array();
    };
    write_related("callees", function.callees);
    write_related("callers", function.callers);

    // Unreachable blocks are surfaced, not quietly dropped - they usually mean a
    // bad decode or an unresolved indirect branch.
    json.key("unreachable_blocks");
    json.begin_array();
    for (core::VA va : function.cfg.unreachable_blocks()) {
        json.address(va);
    }
    json.end_array();

    json.end_object();
    out << "\n";
    return core::Status::success();
}

core::Status JsonExporter::export_call_graph(const Inputs& inputs,
                                            const JsonOptions& options,
                                            std::ostream& out)
{
    if (auto status = require(inputs); !status.ok()) {
        return status;
    }
    if (inputs.call_graph == nullptr) {
        return core::Error(core::ErrorCode::InvalidArgument, "call_graph is required");
    }

    JsonWriter json(out, options.pretty);
    json.begin_object();
    json.field("schema_version", std::string("1.0"));
    json.field("function_count", inputs.call_graph->function_count());

    json.key("nodes");
    json.begin_array();
    if (inputs.functions != nullptr) {
        for (const auto& [entry, function] : *inputs.functions) {
            json.begin_object();
            json.address_field("va", entry);
            json.field("name", inputs.symbols != nullptr
                                   ? inputs.symbols->name_for(entry)
                                   : analysis::SymbolTable::generated_name(entry, true));
            json.field("is_thunk", function.is_thunk);

            // A function with indirect calls has an incomplete outgoing edge
            // set, so the UI can mark the graph as partial here.
            json.field("has_indirect_calls", function.indirect_call_count > 0);
            json.end_object();
        }
    }
    json.end_array();

    json.key("edges");
    json.begin_array();
    if (inputs.functions != nullptr) {
        for (const auto& [entry, function] : *inputs.functions) {
            for (core::VA callee : function.callees) {
                json.begin_object();
                json.address_field("from", entry);
                json.address_field("to", callee);
                json.end_object();
            }
        }
    }
    json.end_array();

    // Bottom-up order for the lifting agent: leaves first, so a caller's prompt
    // can include summaries its callees already produced.
    json.key("processing_order");
    json.begin_array();
    for (core::VA va : inputs.call_graph->reverse_topological_order()) {
        json.address(va);
    }
    json.end_array();

    json.end_object();
    out << "\n";
    return core::Status::success();
}

} // namespace sp::serialize
