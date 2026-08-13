//
// main.cpp - Thin CLI wrapper.
//
// Contains no analysis logic. Its whole job is to parse arguments, drive the
// Pipeline, and emit JSON on stdout so the frontend and the n8n layer can
// consume it without linking any C++.
//
#include "sp/Pipeline.h"
#include "sp/core/Log.h"
#include "sp/harden/PeHardener.h"
#include "sp/loader/PeFormat.h"
#include "sp/serialize/DotExporter.h"
#include "sp/serialize/JsonExporter.h"

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

void print_usage(const char* program)
{
    std::cerr
        << "usage: " << program << " <command> <binary> [options]\n"
        << "\n"
        << "commands:\n"
        << "  info       <binary>            headers, sections, imports, coverage\n"
        << "  functions  <binary>            discovered function index\n"
        << "  disasm     <binary> --at VA    one function as JSON\n"
        << "  cfg        <binary> --at VA    same as disasm (blocks + edges)\n"
        << "  dot        <binary> --at VA    one function as Graphviz\n"
        << "  callgraph  <binary>            whole-image call graph\n"
        << "  findings   <binary>            risky operations + input reachability\n"
        << "  export     <binary> --out DIR  manifest + per-function JSON (for n8n)\n"
        << "\n"
        << "  mitigations <binary>           report ASLR/DEP/CFG state, no changes\n"
        << "  harden      <binary> --out F   write a copy with mitigations enabled\n"
        << "\n"
        << "options:\n"
        << "  --at <hex-va>    target function address\n"
        << "  --out <dir|file> output directory for `export`, output file for `harden`\n"
        << "  --no-sweep       skip the linear-sweep fallback\n"
        << "  --keep-thunks    include thunks and import stubs in `export`\n"
        << "  --allow-signed   let `harden` edit a signed image, breaking its signature\n"
        << "  --fix-wx         remove write-or-execute from a section holding both.\n"
        << "                   Off by default: it is the one change that can break\n"
        << "                   a packer or self-modifying code\n"
        << "  --no-checksum    let `harden` leave a stale header checksum\n"
        << "  --compact        minified JSON\n"
        << "  --verbose        debug logging to stderr\n";
}

struct Args {
    std::string command;
    std::string path;
    std::string out_dir;
    sp::core::VA at = sp::core::kInvalidVA;
    bool linear_sweep = true;
    bool keep_thunks = false;
    bool allow_signed = false;
    bool fix_wx = false;
    bool fix_checksum = true;
    bool pretty = true;
    bool verbose = false;
    bool valid = false;
};

Args parse_args(int argc, char** argv)
{
    Args args;
    if (argc < 3) {
        return args;
    }
    args.command = argv[1];
    args.path = argv[2];

    for (int i = 3; i < argc; ++i) {
        if (std::strcmp(argv[i], "--at") == 0 && i + 1 < argc) {
            args.at = std::stoull(argv[++i], nullptr, 16);
        } else if (std::strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            args.out_dir = argv[++i];
        } else if (std::strcmp(argv[i], "--no-sweep") == 0) {
            args.linear_sweep = false;
        } else if (std::strcmp(argv[i], "--keep-thunks") == 0) {
            args.keep_thunks = true;
        } else if (std::strcmp(argv[i], "--allow-signed") == 0) {
            args.allow_signed = true;
        } else if (std::strcmp(argv[i], "--fix-wx") == 0) {
            args.fix_wx = true;
        } else if (std::strcmp(argv[i], "--no-checksum") == 0) {
            args.fix_checksum = false;
        } else if (std::strcmp(argv[i], "--compact") == 0) {
            args.pretty = false;
        } else if (std::strcmp(argv[i], "--verbose") == 0) {
            args.verbose = true;
        } else {
            std::cerr << "unknown option: " << argv[i] << "\n";
            return args;
        }
    }
    args.valid = true;
    return args;
}

std::string hex(std::uint64_t value)
{
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}

/* --- Mitigations ------------------------------------------------------------
 *
 * These two commands run before the Pipeline, and that is deliberate. They read
 * and write header bytes; they need no disassembly, no CFG and no call graph.
 * Making them wait for a full analysis would cost seconds per invocation for
 * nothing, and would refuse to report on a file the disassembler chokes on -
 * exactly the file whose mitigation state you most want to know.
 */

std::string json_escape(const std::string& text)
{
    std::string out;
    out.reserve(text.size() + 8);
    for (const char c : text) {
        if (c == '"' || c == '\\') { out.push_back('\\'); out.push_back(c); }
        else if (c == '\n') { out += "\\n"; }
        else { out.push_back(c); }
    }
    return out;
}

void emit_report(std::ostream& out, const sp::harden::MitigationReport& report,
                 const char* indent)
{
    out << indent << "\"parsed\": " << (report.parsed ? "true" : "false") << ",\n";
    if (!report.parsed) {
        out << indent << "\"problem\": \"" << json_escape(report.problem) << "\"\n";
        return;
    }
    out << indent << "\"format\": \"" << (report.pe32_plus ? "PE32+" : "PE32") << "\",\n"
        << indent << "\"dll_characteristics\": \"" << hex(report.dll_characteristics) << "\",\n"
        << indent << "\"aslr\": " << (report.aslr ? "true" : "false") << ",\n"
        << indent << "\"high_entropy_va\": " << (report.high_entropy_va ? "true" : "false") << ",\n"
        << indent << "\"dep\": " << (report.dep ? "true" : "false") << ",\n"
        << indent << "\"cfg\": " << (report.cfg ? "true" : "false") << ",\n"
        << indent << "\"has_relocations\": " << (report.has_relocations ? "true" : "false") << ",\n"
        << indent << "\"relocations_stripped\": "
                  << (report.relocations_stripped ? "true" : "false") << ",\n"
        << indent << "\"signed_image\": " << (report.signed_image ? "true" : "false") << ",\n"
        << indent << "\"checksum_valid\": " << (report.checksum_valid ? "true" : "false") << ",\n"
        << indent << "\"has_write_execute\": "
                  << (report.has_write_execute() ? "true" : "false") << ",\n";

    // Every section's permissions, so a W^X claim can be checked rather than
    // believed. A reader can compare this against `dumpbin /headers` directly.
    out << indent << "\"sections\": [";
    for (std::size_t i = 0; i < report.sections.size(); ++i) {
        const auto& section = report.sections[i];
        out << (i == 0 ? "\n" : ",\n") << indent << "  {"
            << "\"name\": \"" << json_escape(section.name) << "\", "
            << "\"read\": " << (section.readable ? "true" : "false") << ", "
            << "\"write\": " << (section.writable ? "true" : "false") << ", "
            << "\"execute\": " << (section.executable ? "true" : "false") << ", "
            << "\"code\": " << (section.code ? "true" : "false") << ", "
            << "\"write_execute\": " << (section.write_execute() ? "true" : "false")
            << "}";
    }
    out << (report.sections.empty() ? "]," : ("\n" + std::string(indent) + "],")) << "\n";

    out << indent << "\"fully_hardened\": " << (report.fully_hardened() ? "true" : "false") << "\n";
}

void emit_strings(std::ostream& out, const std::vector<std::string>& items)
{
    out << "[";
    for (std::size_t i = 0; i < items.size(); ++i) {
        out << (i == 0 ? "\n      \"" : ",\n      \"") << json_escape(items[i]) << "\"";
    }
    out << (items.empty() ? "]" : "\n    ]");
}

int run_mitigations(const Args& args)
{
    std::vector<std::uint8_t> bytes;
    if (!sp::loader::read_file(args.path, bytes)) {
        std::cerr << "cannot read " << args.path << "\n";
        return 1;
    }

    const sp::harden::MitigationReport report = sp::harden::inspect(bytes);
    std::cout << "{\n  \"schema_version\": \"1.0\",\n  \"mitigations\": {\n";
    emit_report(std::cout, report, "    ");
    std::cout << "  }\n}\n";
    return report.parsed ? 0 : 1;
}

int run_harden(const Args& args)
{
    std::vector<std::uint8_t> bytes;
    if (!sp::loader::read_file(args.path, bytes)) {
        std::cerr << "cannot read " << args.path << "\n";
        return 1;
    }

    sp::harden::HardenOptions options;
    options.allow_signed = args.allow_signed;
    options.enforce_write_xor_execute = args.fix_wx;
    options.fix_checksum = args.fix_checksum;

    const sp::harden::HardenResult result =
        sp::harden::apply_mitigations(bytes, options);

    // Never in place. The input is evidence; overwriting it would destroy the
    // thing every stored finding was derived from.
    std::filesystem::path destination = args.out_dir.empty()
        ? std::filesystem::path(args.path).replace_extension(".hardened.exe")
        : std::filesystem::path(args.out_dir);

    bool written = false;
    if (result.ok && result.changed()) {
        std::ofstream file(destination, std::ios::binary | std::ios::trunc);
        if (!file) {
            std::cerr << "cannot write " << destination.string() << "\n";
            return 1;
        }
        file.write(reinterpret_cast<const char*>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
        written = file.good();
        if (!written) {
            std::cerr << "write failed: " << destination.string() << "\n";
            return 1;
        }
    }

    std::cout << "{\n"
              << "  \"schema_version\": \"1.0\",\n"
              << "  \"ok\": " << (result.ok ? "true" : "false") << ",\n"
              << "  \"input\": \"" << json_escape(args.path) << "\",\n"
              << "  \"output\": " << (written
                     ? "\"" + json_escape(destination.string()) + "\"" : "null") << ",\n";
    if (!result.ok) {
        std::cout << "  \"problem\": \"" << json_escape(result.problem) << "\",\n";
    }
    std::cout << "  \"applied\": ";
    emit_strings(std::cout, result.applied);
    std::cout << ",\n  \"refused\": ";
    emit_strings(std::cout, result.refused);
    std::cout << ",\n  \"before\": {\n";
    emit_report(std::cout, result.before, "    ");
    std::cout << "  },\n  \"after\": {\n";
    emit_report(std::cout, result.after, "    ");
    std::cout << "  },\n"
              << "  \"note\": \"Mitigations change how the loader treats this image. "
                 "They do not repair the defects the analysis found - see the "
                 "findings for those.\"\n}\n";

    return result.ok ? 0 : 1;
}

// Batch export: analyse once, then write a manifest plus one file per function.
//
// This is the shape the n8n workflow consumes. The alternative - invoking this
// binary once per function - would re-analyse the whole image every time, which
// on a real PE means paying seconds of work thousands of times over.
int run_export(const sp::Pipeline& pipeline,
              const sp::serialize::JsonExporter::Inputs& inputs,
              const sp::serialize::JsonOptions& json,
              const Args& args)
{
    if (args.out_dir.empty()) {
        std::cerr << "export requires --out <dir>\n";
        return 2;
    }

    std::error_code ec;
    std::filesystem::create_directories(args.out_dir, ec);
    if (ec) {
        std::cerr << "cannot create " << args.out_dir << ": " << ec.message() << "\n";
        return 1;
    }

    const std::filesystem::path root(args.out_dir);

    {
        std::ofstream image_file(root / "image.json");
        sp::serialize::JsonExporter::export_image(inputs, json, image_file);
    }
    {
        std::ofstream list_file(root / "functions.json");
        sp::serialize::JsonExporter::export_function_list(inputs, json, list_file);
    }
    {
        std::ofstream graph_file(root / "callgraph.json");
        sp::serialize::JsonExporter::export_call_graph(inputs, json, graph_file);
    }
    {
        std::ofstream findings_file(root / "findings.json");
        sp::serialize::JsonExporter::export_findings(inputs, json, findings_file);
    }

    // Per-function bundles, named by address so the manifest can reference them.
    std::size_t written = 0;
    std::size_t skipped = 0;

    const std::filesystem::path functions_dir = root / "functions";
    std::filesystem::create_directories(functions_dir, ec);

    std::ostringstream manifest;
    manifest << "{\n  \"schema_version\": \"1.0\",\n  \"functions\": [\n";
    bool first = true;

    // Bottom-up order, so when the lifting agent reaches a caller its callees
    // have already been summarised.
    for (sp::core::VA va : pipeline.call_graph().reverse_topological_order()) {
        const sp::analysis::Function* function = pipeline.function_at(va);
        if (function == nullptr) {
            continue;
        }

        // Thunks and import stubs are one jump each. Sending thousands of them
        // to a language model wastes most of the budget on nothing.
        if (!args.keep_thunks && (function->is_thunk || function->is_imported_stub)) {
            ++skipped;
            continue;
        }

        std::ostringstream filename;
        filename << "func_" << std::hex << va << ".json";

        std::ofstream function_file(functions_dir / filename.str());
        if (!sp::serialize::JsonExporter::export_function(inputs, va, json, function_file).ok()) {
            continue;
        }

        if (!first) manifest << ",\n";
        first = false;
        manifest << "    {\"va\": \"" << hex(va) << "\""
                 << ", \"name\": \"" << pipeline.symbols().name_for(va) << "\""
                 << ", \"file\": \"functions/" << filename.str() << "\""
                 << ", \"instruction_count\": " << function->instruction_count
                 << ", \"block_count\": " << function->cfg.block_count() << "}";
        ++written;
    }
    manifest << "\n  ],\n  \"count\": " << written << "\n}\n";

    {
        std::ofstream manifest_file(root / "manifest.json");
        manifest_file << manifest.str();
    }

    std::cerr << "exported " << written << " functions to " << args.out_dir
              << " (" << skipped << " thunks skipped)\n";
    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    const Args args = parse_args(argc, argv);
    if (!args.valid) {
        print_usage(argv[0]);
        return 2;
    }

    if (args.verbose) {
        sp::core::set_log_level(sp::core::LogLevel::Debug);
    }

    // Header-only commands, dispatched before the Pipeline so they neither pay
    // for a full analysis nor depend on one succeeding.
    if (args.command == "mitigations") {
        return run_mitigations(args);
    }
    if (args.command == "harden") {
        return run_harden(args);
    }

    sp::PipelineOptions options;
    options.disassembly.linear_sweep_fallback = args.linear_sweep;

    sp::Pipeline pipeline;
    if (auto status = pipeline.analyze(args.path, options); !status.ok()) {
        std::cerr << "analysis failed: " << status.error().message << "\n";
        return 1;
    }

    sp::serialize::JsonOptions json;
    json.pretty = args.pretty;

    sp::serialize::JsonExporter::Inputs inputs;
    inputs.facts = &pipeline.facts();
    inputs.annotations = &pipeline.annotations();
    inputs.instructions = &pipeline.instructions();
    inputs.code_map = &pipeline.code_map();
    inputs.symbols = &pipeline.symbols();
    inputs.xrefs = &pipeline.xrefs();
    inputs.call_graph = &pipeline.call_graph();
    inputs.functions = &pipeline.functions();
    inputs.reachability = &pipeline.reachability();
    inputs.strings = &pipeline.strings();

    const bool needs_address = (args.command == "disasm")
                            || (args.command == "cfg")
                            || (args.command == "dot");

    if (needs_address && args.at == sp::core::kInvalidVA) {
        std::cerr << args.command << " requires --at <hex-va>\n";
        return 2;
    }

    sp::core::Status status = sp::core::Status::success();

    if (args.command == "info") {
        status = sp::serialize::JsonExporter::export_image(inputs, json, std::cout);
    } else if (args.command == "functions") {
        status = sp::serialize::JsonExporter::export_function_list(inputs, json, std::cout);
    } else if (args.command == "findings") {
        status = sp::serialize::JsonExporter::export_findings(inputs, json, std::cout);
    } else if (args.command == "callgraph") {
        status = sp::serialize::JsonExporter::export_call_graph(inputs, json, std::cout);
    } else if (args.command == "disasm" || args.command == "cfg") {
        status = sp::serialize::JsonExporter::export_function(inputs, args.at, json, std::cout);
    } else if (args.command == "dot") {
        const sp::analysis::Function* function = pipeline.function_at(args.at);
        if (function == nullptr) {
            std::cerr << "no function at " << hex(args.at) << "\n";
            return 1;
        }
        sp::serialize::DotOptions dot;
        status = sp::serialize::DotExporter::export_cfg(*function, pipeline.instructions(),
                                                       pipeline.symbols(), dot, std::cout);
    } else if (args.command == "export") {
        return run_export(pipeline, inputs, json, args);
    } else {
        std::cerr << "unknown command: " << args.command << "\n";
        print_usage(argv[0]);
        return 2;
    }

    if (!status.ok()) {
        std::cerr << "error: " << status.error().message << "\n";
        return 1;
    }
    return 0;
}
