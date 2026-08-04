#include "test_harness.h"

#include "sp/analysis/CFGBuilder.h"
#include "sp/analysis/SymbolTable.h"
#include "sp/db/EntityId.h"
#include "sp/db/FactStore.h"
#include "sp/disasm/InstructionStorage.h"
#include "sp/serialize/JsonExporter.h"

#include <map>
#include <sstream>
#include <string>

using namespace sp;
using sp::disasm::FlowKind;
using sp::disasm::InstructionInfo;
using sp::disasm::InstructionStorage;

namespace {

bool has(const std::string& haystack, const std::string& needle)
{
    return haystack.find(needle) != std::string::npos;
}

db::FactStore make_facts()
{
    db::FactStore facts;
    facts.set_arch(core::Arch::X86_64);
    facts.set_entry_point(0x140001000);

    std::vector<core::SectionRange> sections;
    core::SectionRange text;
    text.name = ".text";
    text.rva = 0x1000;
    text.virtual_size = 0x1000;
    text.raw_offset = 0x400;
    text.raw_size = 0x1000;
    text.executable = true;
    text.readable = true;
    sections.push_back(text);

    facts.set_address_space(core::AddressSpace(0x140000000, std::move(sections)));
    return facts;
}

InstructionInfo insn(core::VA address, std::uint16_t size, FlowKind flow,
                     const std::string& mnemonic)
{
    InstructionInfo i;
    i.address = address;
    i.size = size;
    i.flow = flow;
    i.mnemonic = mnemonic;
    i.bytes = { 0x48, 0x83, 0xEC, 0x28 };
    i.provenance.add({ core::ProvenanceKind::PeUnwindInfo, core::kInvalidVA,
                       core::Confidence::Certain, false });
    if (i.has_fall_through()) {
        i.fall_through = address + size;
    }
    return i;
}

} // namespace

void test_json_exporter()
{
    db::FactStore facts = make_facts();

    InstructionStorage code;
    code.add(insn(0x140001000, 4, FlowKind::Sequential, "sub"));
    InstructionInfo branch = insn(0x140001004, 2, FlowKind::ConditionalJump, "je");
    branch.direct_target = 0x140001008;
    code.add(branch);
    code.add(insn(0x140001006, 2, FlowKind::Sequential, "mov"));
    code.add(insn(0x140001008, 1, FlowKind::Return, "ret"));

    db::EntityIdAllocator ids;
    analysis::CFGBuilder builder;
    std::map<core::VA, analysis::Function> functions;

    std::vector<analysis::FunctionCandidate> candidates;
    analysis::FunctionCandidate candidate;
    candidate.entry = 0x140001000;
    candidate.provenance.add({ core::ProvenanceKind::PeUnwindInfo, core::kInvalidVA,
                               core::Confidence::Certain, false });
    candidates.push_back(candidate);

    builder.build_all(facts, code, disasm::CodeMap{}, candidates,
                      analysis::CFGBuildOptions{}, ids, functions);

    analysis::SymbolTable symbols;
    symbols.build(facts);

    serialize::JsonExporter::Inputs inputs;
    inputs.facts = &facts;
    inputs.instructions = &code;
    inputs.functions = &functions;
    inputs.symbols = &symbols;

    serialize::JsonOptions options;

    SP_TEST("json exporter: enum fields render as strings, not booleans");
    {
        // Regression guard. const char* binds to the bool overload by default,
        // because pointer-to-bool is a standard conversion while
        // const char* -> std::string is user-defined. Every enum name in the
        // output silently became `true`.
        std::ostringstream out;
        serialize::JsonExporter::export_image(inputs, options, out);
        const std::string json = out.str();

        SP_CHECK(has(json, "\"arch\": \"x86_64\""));
        SP_CHECK(!has(json, "\"arch\": true"));
    }

    SP_TEST("json exporter: image document carries the expected shape");
    {
        std::ostringstream out;
        serialize::JsonExporter::export_image(inputs, options, out);
        const std::string json = out.str();

        SP_CHECK(has(json, "\"schema_version\": \"1.0\""));
        SP_CHECK(has(json, "\"format\": \"pe\""));

        // Addresses must be hex strings: a 64-bit VA does not survive a round
        // trip through a JavaScript number.
        SP_CHECK(has(json, "\"image_base\": \"0x140000000\""));
        SP_CHECK(has(json, "\"entry_point\": \"0x140001000\""));
        SP_CHECK(has(json, "\".text\""));
        SP_CHECK(has(json, "\"coverage\""));
    }

    SP_TEST("json exporter: function document renders enums and edges");
    {
        std::ostringstream out;
        auto status = serialize::JsonExporter::export_function(inputs, 0x140001000,
                                                              options, out);
        SP_CHECK(status.ok());
        const std::string json = out.str();

        // Flow, edge kind, convention, confidence and provenance are all enums
        // reached through to_string overloads - the exact path that was broken.
        SP_CHECK(has(json, "\"flow\": \"conditional-jump\""));
        SP_CHECK(has(json, "\"flow\": \"return\""));
        SP_CHECK(has(json, "\"kind\": \"taken\""));
        SP_CHECK(has(json, "\"kind\": \"fall-through\""));
        SP_CHECK(has(json, "\"convention\": \"win64\""));
        SP_CHECK(has(json, "\"confidence\": \"certain\""));
        SP_CHECK(has(json, "\"kind\": \"pe-unwind-info\""));
        SP_CHECK(!has(json, ": true,\n      \"target\""));

        SP_CHECK(has(json, "\"has_unresolved_exit\""));
        SP_CHECK(has(json, "\"block_order\""));
        SP_CHECK(has(json, "\"predecessors\""));
    }

    SP_TEST("json exporter: function list renders");
    {
        std::ostringstream out;
        serialize::JsonExporter::export_function_list(inputs, options, out);
        const std::string json = out.str();

        SP_CHECK(has(json, "\"count\": 1"));
        SP_CHECK(has(json, "\"va\": \"0x140001000\""));
        SP_CHECK(has(json, "\"confidence\": \"certain\""));
    }

    SP_TEST("json exporter: missing function is an error, not empty output");
    {
        std::ostringstream out;
        auto status = serialize::JsonExporter::export_function(inputs, 0x999999,
                                                              options, out);
        SP_CHECK(!status.ok());
        if (!status.ok()) {
            SP_CHECK_EQ(status.error().code, core::ErrorCode::InvalidAddress);
        }
    }

    SP_TEST("json exporter: string escaping");
    {
        // A mnemonic or symbol name containing a quote or backslash must not
        // produce malformed JSON.
        InstructionStorage tricky;
        InstructionInfo odd = insn(0x140001000, 1, FlowKind::Return, "ret");
        odd.op_str = "he said \"hi\"\\path";
        tricky.add(odd);

        serialize::JsonExporter::Inputs tricky_inputs = inputs;
        tricky_inputs.instructions = &tricky;

        std::map<core::VA, analysis::Function> single;
        db::EntityIdAllocator local_ids;
        analysis::CFGBuilder local_builder;
        local_builder.build_all(facts, tricky, disasm::CodeMap{}, candidates,
                                analysis::CFGBuildOptions{}, local_ids, single);
        tricky_inputs.functions = &single;

        std::ostringstream out;
        serialize::JsonExporter::export_function(tricky_inputs, 0x140001000,
                                                 options, out);
        const std::string json = out.str();
        SP_CHECK(has(json, "\\\"hi\\\""));
        SP_CHECK(has(json, "\\\\path"));
    }
}
