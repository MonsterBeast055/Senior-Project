# Senior-Project — Binary Analysis Engine

Static analysis engine for Windows PE executables. Takes a binary and produces
disassembly, per-function control-flow graphs, cross-references and a call
graph, serialised as JSON for a graph frontend and for an AI logic-lifting
layer.

This repository is the analysis backend. The frontend consumes its JSON output.

## Design premise

Most disassemblers were built for a human reading a GUI. Analysis runs once,
commits to its conclusions, and discards the reasoning that produced them. When
the tool guesses wrong about whether bytes are code, the output looks exactly as
confident as when it is right.

That is a poor foundation for a system where a language model is also a consumer
of the analysis. This engine is built around four properties instead:

**1. Provenance on every derived fact.** Each instruction records *why* we
believe it is an instruction — entry point, `.pdata` unwind info, direct call
target, prologue heuristic, or linear-sweep guess. See `core/Provenance.h`.

**2. Graded confidence, not assertion.** Code/data classification is a lattice,
not a boolean. Weaker evidence can never overwrite stronger, so results do not
depend on pass ordering. See `core/Confidence.h`, `disasm/CodeMap.h`.

**3. Facts separated from inference.** `db/FactStore` holds what was read from
the file and is never mutated by analysis. `db/AnnotationStore` holds names,
types, comments and tags, each tagged with its origin (analysis, user, or AI).
Re-analysis discards its own prior output while preserving human and model
contributions.

**4. Revisable analysis.** Because beliefs carry provenance and identity is
stable (`db/EntityId.h`), a later pass can retract a bad decode and rebuild only
what depended on it. `Pipeline::retract_region` is the entry point. This is what
makes an AI feedback loop possible: a model inference lands as an annotation,
propagates through re-analysis, and improves the context the model sees next.

## Layout

```
Senior-Project/
├── CMakeLists.txt              # root: dependencies, standard, targets
├── tests/                      # dependency-free assert-based suite
└── Senior-Project/
    ├── CMakeLists.txt          # sp_engine library + sp_cli executable
    ├── include/sp/
    │   ├── Pipeline.h          # orchestration; owns all analysis state
    │   ├── core/               # Types, AddressSpace, Confidence,
    │   │                       # Provenance, Error, Log
    │   ├── db/                 # EntityId, FactStore, AnnotationStore
    │   ├── loader/             # BinaryLoader — the only LIEF consumer
    │   ├── disasm/             # Disassembler, InstructionInfo/Storage,
    │   │                       # DecodeQueue, CodeMap
    │   ├── analysis/           # FunctionDiscovery, CFG, CFGBuilder,
    │   │                       # CallGraph, XrefTable, SymbolTable,
    │   │                       # ApiClassifier, Reachability,
    │   │                       # StringExtractor, FunctionSummarizer,
    │   │                       # LoopAnalysis
    │   ├── lift/               # StructuralAnalysis, ContextBuilder
    │   └── serialize/          # JsonExporter, DotExporter
    ├── src/                    # mirrors include/sp
    └── tools/cli/main.cpp      # thin CLI wrapper, no analysis logic
```

Dependencies are confined: only `src/loader` includes LIEF, only `src/disasm`
includes Capstone. Both are linked `PRIVATE`, so nothing else in the project —
or anything linking `sp_engine` — inherits them. Adding ELF support later means
adding a loader, not editing the analysis layer.

## Pipeline

```
BinaryLoader      PE → FactStore (sections, imports, exports, .pdata, TLS)
      ↓
Disassembler      recursive descent from trusted entry points,
                  then linear sweep over unclaimed bytes at Low confidence
      ↓
FunctionDiscovery .pdata → exports/entry → call targets → prologue patterns
      ↓
CFGBuilder        per-function basic blocks and edges
      ↓
XrefTable         bidirectional cross-references
CallGraph         function-to-function edges
StringExtractor   literals, and which functions reference them
      ↓
ApiClassifier     which imports are input sources, which are risky sinks
Reachability      call paths from a source to a sink — the findings layer
      ↓
LoopAnalysis      dominators, natural loops, nesting          (stub)
StructuralAnalysis  if/else, while, switch recovery           (stub)
      ↓
ContextBuilder    per-function bundle for the model           (stub)
JsonExporter      one document serving both the UI and the AI layer
```

The three stubbed stages are marked because the pipeline runs without them: they
contribute nothing to the export today rather than blocking it.

Disassembly strategy matters here. Recursive descent alone misses code reachable
only through indirect calls; linear sweep alone misdecodes data embedded in
`.text`. Running descent first from trusted sources, then sweeping the remainder
at explicitly lower confidence, gets the coverage of both while keeping the two
distinguishable in the output.

## Building

Requires CMake 3.20+, a C++20 compiler, LIEF 0.17.x and Capstone.

```
cmake -S . -B out/build/x64-release -DCMAKE_BUILD_TYPE=Release -DLIEF_ROOT=C:/libs/LIEF-0.17.6-win64
cmake --build out/build/x64-release
ctest --test-dir out/build/x64-release
```

`LIEF_ROOT` may also be set as an environment variable. The MSVC runtime must
match the LIEF build — Release uses `/MT`; a Debug build requires a Debug LIEF.

## CLI

```
sp info      <binary>            headers, sections, imports, coverage
sp functions <binary>            discovered function index
sp disasm    <binary> --at VA    disassemble one function
sp cfg       <binary> --at VA    CFG of one function as JSON
sp dot       <binary> --at VA    CFG as Graphviz (development aid)
sp callgraph <binary>            whole-image call graph
sp context   <binary> --at VA    AI context bundle for one function

sp mitigations <binary>          report ASLR/DEP/CFG state, changes nothing
sp harden      <binary> --out F  write a copy with mitigations enabled
```

`harden` never writes in place. The input is the evidence every stored finding
was derived from, and overwriting it would destroy that.

## Status

**Working end to end** (v1 spine complete): PE loading, disassembly with
recursive descent plus linear-sweep fallback, function discovery from four
sources, per-function CFG construction, cross-references, call graph, symbol
resolution, string extraction, reachability-based findings, and JSON/Graphviz
export.

Implemented and unit tested: `core` (all), `db` (all), `PeFormat`,
`InstructionStorage`, `CodeMap`, `DecodeQueue`, `CFG`, `CFGBuilder`,
`SymbolTable`, `XrefTable`, `CallGraph`, `AnnotationStore`, `Reachability`,
`StringExtractor`, `JsonExporter`. 81 tests.

Implemented, verified by build only (require LIEF/Capstone): `BinaryLoader`,
`Disassembler`, `DotExporter`, `Pipeline`.

**Security findings are implemented**, in `analysis/` rather than a `findings/`
directory: `ApiClassifier` labels imports as input sources or risky sinks, and
`Reachability` looks for a call path between them. It is explicitly not taint
analysis — a path proves a necessary condition for exploitability, not a
sufficient one, and the output is worded to say so.

**Deferred, stubbed with the intended approach documented at each site:**
`LoopAnalysis` (dominators, dominance frontiers, natural loops — the accessors
are real but nothing populates them), `StructuralAnalysis::analyze` (if/else and
loop recovery; it returns a single honest `Irreducible` region holding the raw
blocks), `ContextBuilder::build` and `to_prompt_payload` (AI context bundles),
jump-table resolution, and patch proposals.

**Mitigation hardening is implemented** in `harden/PeHardener`, the only part of
the engine that writes a binary rather than reading one. It reports ASLR, DEP,
high-entropy ASLR and CFG, and can enable the first three — refusing ASLR when
there is no relocation data, refusing high-entropy ASLR on a 32-bit image, and
refusing to touch a signed image unless told to. CFG is reported and never set,
because it needs compiler-emitted guard tables; `/GS` is reported as
unrepresentable rather than absent, because stack cookies are code, not a header
bit. This does not repair the defects the analysis found — see the note at the
top of `PeHardener.h` for why that is deliberate rather than unfinished.

Two things inside those stubbed files *are* real and are relied on:
`StructuralAnalysis::cyclomatic_complexity` (E − N + 2, and the number the UI
shows), and `ContextBuilder::recommended_processing_order`, which delegates to
`CallGraph::reverse_topological_order` — implemented with Tarjan's SCC algorithm,
iterative to survive deep call chains, and reporting the cycles it finds. That is
what makes bottom-up lifting work, so a caller's prompt carries summaries of what
it calls.

The original single-file prototype remains as `Senior-Project.cpp`, built via
`-DSP_BUILD_LEGACY_PROTOTYPE=ON`. It can now be deleted - `BinaryLoader` and
`Disassembler` supersede it.

## Output contract

`docs/json-schema.md` documents every JSON document the engine emits, and
`docs/fixtures/` holds hand-written samples. The backend API, n8n workflows and
frontend all build against that contract.
