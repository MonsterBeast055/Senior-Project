# Senior-Project analysis engine.
#
# Two targets:
#   sp_engine  - static library holding all analysis logic
#   sp_cli     - thin executable wrapper
#
# The split matters: the frontend can link the library directly or shell out to
# the CLI for JSON, and the test suite links the library without dragging in
# main().

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------
add_library(sp_engine STATIC
    # core
    "src/core/Types.cpp"
    "src/core/Confidence.cpp"
    "src/core/Provenance.cpp"
    "src/core/Error.cpp"
    "src/core/Log.cpp"
    "src/core/AddressSpace.cpp"

    # db
    "src/db/EntityId.cpp"
    "src/db/FactStore.cpp"
    "src/db/AnnotationStore.cpp"

    # loader
    "src/loader/PeFormat.cpp"
    "src/loader/BinaryLoader.cpp"

    # disasm
    "src/disasm/InstructionInfo.cpp"
    "src/disasm/InstructionStorage.cpp"
    "src/disasm/DecodeQueue.cpp"
    "src/disasm/CodeMap.cpp"
    "src/disasm/Disassembler.cpp"

    # analysis
    "src/analysis/BasicBlock.cpp"
    "src/analysis/CFG.cpp"
    "src/analysis/Function.cpp"
    "src/analysis/FunctionDiscovery.cpp"
    "src/analysis/CFGBuilder.cpp"
    "src/analysis/XrefTable.cpp"
    "src/analysis/CallGraph.cpp"
    "src/analysis/SymbolTable.cpp"
    "src/analysis/StringExtractor.cpp"
    "src/analysis/FunctionSummarizer.cpp"
    "src/analysis/ApiClassifier.cpp"
    "src/analysis/Reachability.cpp"
    "src/analysis/LoopAnalysis.cpp"

    # lift
    "src/lift/StructuralAnalysis.cpp"
    "src/lift/ContextBuilder.cpp"

    # harden - the only part of the engine that writes a binary rather than
    # reading one. LIEF-free, like the loader's PeFormat, for the same reason.
    "src/harden/PeHardener.cpp"

    # serialize
    "src/serialize/JsonExporter.cpp"
    "src/serialize/DotExporter.cpp"

    # orchestration
    "src/Pipeline.cpp"
)

target_include_directories(sp_engine PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_compile_features(sp_engine PUBLIC cxx_std_20)

# LIEF is referenced only by src/loader, Capstone only by src/disasm, but both
# are linked PRIVATE so no consumer of this library inherits either dependency.
target_link_libraries(sp_engine PRIVATE
    LIEF::LIEF
    capstone::capstone
)

if(MSVC)
    target_compile_options(sp_engine PRIVATE /W4 /permissive-)
else()
    target_compile_options(sp_engine PRIVATE -Wall -Wextra -Wpedantic)
endif()

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
add_executable(sp_cli "tools/cli/main.cpp")
target_link_libraries(sp_cli PRIVATE sp_engine)
set_target_properties(sp_cli PROPERTIES OUTPUT_NAME "sp")

# ---------------------------------------------------------------------------
# Legacy prototype
# ---------------------------------------------------------------------------
# The original single-file prototype, kept temporarily as a reference for the
# LIEF and Capstone call sequences while BinaryLoader and Disassembler are
# filled in. Delete both this target and Senior-Project.cpp once that migration
# is done.
option(SP_BUILD_LEGACY_PROTOTYPE "Build the original single-file prototype" ON)

if(SP_BUILD_LEGACY_PROTOTYPE)
    add_executable(Senior-Project "Senior-Project.cpp" "Senior-Project.h")
    target_link_libraries(Senior-Project PRIVATE LIEF::LIEF capstone::capstone)
    target_compile_features(Senior-Project PRIVATE cxx_std_20)
endif()
