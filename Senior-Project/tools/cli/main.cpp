//
// main.cpp - Thin CLI wrapper.
//
// Contains no analysis logic. Its whole job is to parse arguments, drive the
// Pipeline, and emit JSON on stdout so the frontend and the n8n layer can
// consume it without linking any C++.
//
#include "sp/Pipeline.h"
#include "sp/core/Log.h"
#include "sp/serialize/DotExporter.h"
#include "sp/serialize/JsonExporter.h"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

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
        << "  export     <binary> --out DIR  manifest + per-function JSON (for n8n)\n"
        << "\n"
        << "options:\n"
        << "  --at <hex-va>    target function address\n"
        << "  --out <dir>      output directory for `export`\n"
        << "  --no-sweep       skip the linear-sweep fallback\n"
        << "  --keep-thunks    include thunks and import stubs in `export`\n"
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
