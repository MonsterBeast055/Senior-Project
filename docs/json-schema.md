# JSON output contract — v1.0

Every document the engine emits carries `"schema_version": "1.0"`. Check it and
fail loudly on a mismatch rather than guessing.

**This is the interface between the C++ engine and everything else.** The backend
API, the n8n workflows and the frontend all read these shapes. Fixture files
under `docs/fixtures/` let you build against the contract before the engine is
finished — see the bottom of this document.

## Conventions that apply everywhere

**Addresses are hex strings, never numbers.** `"va": "0x140001a20"`. A 64-bit
virtual address does not survive a round trip through a JavaScript number
(`Number.MAX_SAFE_INTEGER` is only 53 bits), so treating these as integers will
silently corrupt high addresses. Parse with `BigInt(s)` if you need arithmetic.

**`null` means "not applicable", not "zero".** A `target` of `null` on an
indirect branch means the destination is not statically knowable — it does not
mean address zero.

**`confidence`** is one of `certain`, `high`, `medium`, `low`, `none`. It is
graded on purpose. Anything below `high` is a guess the engine is admitting to,
and the UI should show it differently rather than presenting it as fact.

**`provenance`** records *why* the engine believes something. Useful for
debugging and for showing the user the basis of a conclusion.

## Commands and their outputs

| Command | Output | Document |
|---|---|---|
| `sp info <bin>` | stdout | Image |
| `sp functions <bin>` | stdout | Function list |
| `sp cfg <bin> --at VA` | stdout | Function detail |
| `sp callgraph <bin>` | stdout | Call graph |
| `sp export <bin> --out DIR` | files | All of the above + manifest |

Add `--compact` for minified output, `--verbose` for diagnostics on stderr.
Diagnostics always go to stderr, so stdout is always clean JSON.

## Image (`sp info`, `image.json`)

```json
{
  "schema_version": "1.0",
  "format": "pe",
  "arch": "x86_64",
  "image_base": "0x140000000",
  "entry_point": "0x140001080",
  "image_size": 360448,
  "sections": [
    {
      "name": ".text",
      "va": "0x140001000",
      "rva": 4096,
      "virtual_size": 155648,
      "raw_size": 155648,
      "raw_offset": 1024,
      "executable": true,
      "readable": true,
      "writable": false,
      "entropy": 6.4213
    }
  ],
  "imports": [
    {
      "library": "KERNEL32.dll",
      "name": "CreateFileW",
      "by_ordinal": false,
      "ordinal": 0,
      "iat_slot": "0x140020168"
    }
  ],
  "exports": [
    { "name": "DllMain", "ordinal": 1, "va": "0x140003000", "is_forwarder": false }
  ],
  "coverage": {
    "executable_bytes": 155648,
    "code_fraction": 0.8734,
    "instruction_count": 41208,
    "function_count": 1962,
    "unclaimed_ranges": [
      { "start": "0x140021a00", "end": "0x140021c40", "size": 576 }
    ]
  },
  "strings": [
    {
      "address": "0x14001a2f0",
      "encoding": "utf16",
      "text": "Software\\Microsoft\\Notepad",
      "length": 25,
      "truncated": false,
      "refs": 3,
      "library_only": false
    }
  ]
}
```

`coverage.code_fraction` is the share of executable bytes the engine could
explain. `unclaimed_ranges` is what it could not. Both are reported deliberately:
a tool that hides its blind spots is worse than one that names them. Shade those
ranges in the UI rather than pretending the analysis is complete.

`iat_slot` is the address an indirect call actually reads. It is how
`call qword [rip+0x1234]` gets resolved to `KERNEL32.dll!CreateFileW`.

### `api_xrefs` and `string_xrefs`

The reverse direction of a function's `api_calls` and `referenced_strings`.

```jsonc
"api_xrefs": [
  { "api": "ADVAPI32.dll!RegSetValueExW", "count": 2,
    "functions": [ { "va": "0x1400023a0", "name": "NPInit" },
                   { "va": "0x140002418", "name": "NPSaveSettings" } ] }
],
"string_xrefs": [
  { "address": "0x14001a2f0", "count": 1,
    "functions": [ { "va": "0x1400023a0", "name": "NPInit" } ] }
]
```

`api` is spelled `library!name`, identical to a finding's `api` field and to the
key a UI builds from an `imports` entry — the three must agree or a lookup silently
returns nothing.

These exist because the question worth asking about an import is never "where does
it live" (an IAT slot in `.idata`, holding a pointer, not code) but "who calls it" —
which is the question that leads to a finding. A consumer cannot derive this
itself: `functions.json` emits `api_call_count`, not the list, and fetching all
1700 per-function documents to build an index is not a reasonable alternative.

`string_xrefs` resolves each referring *instruction* address to its containing
function using declared extents. A function whose `extent_end` is unknown absorbs
references after it, so a count can be attributed slightly too generously in that
case — never too narrowly.

### `strings`

Every string the engine recovered, image-wide. The same data appears per function
as `referenced_strings`; this is that data indexed the other way, so a Strings pane
can be populated without loading every function document — on a 1700-function DLL
that is the difference between one request and 1700.

`encoding` is `"ascii"` or `"utf16"`, and `text` is always UTF-8 regardless: UTF-16
sources are transcoded so a consumer never has to care which they came from.
`length` is the length in characters *before* truncation, so a clipped string is
identifiable (`truncated: true`) and its real size still known. `refs` is how many
instructions reference the address — a string referenced from several places is
usually a format string or a registry path, and worth more attention than one
referenced once.

`library_only` is true when every function referencing the string is library code.
These strings are real — `(null)`, `.exe`, `ERROR: Unable to initialize heap` are
MSVC C-runtime literals genuinely present in the binary — but they are identical in
every binary built with MSVC and say nothing about the program under analysis. Fold
them away by default; do not drop them, because "the CRT is present" is occasionally
the fact you want. A string with no resolvable owning function is left `false`:
unclassified, not library.

**UTF-16 plausibility.** `printable_only` accepts any code point from `0xA0` up,
which is far too weak for UTF-16 — any two bytes in `0x4E00`–`0x9FFF` form a
perfectly printable CJK ideograph, so pointer tables and instruction bytes decoded
as fluent Chinese. Four additional tests now apply, all configurable in
`StringExtractionOptions`:

| test | option | rationale |
| --- | --- | --- |
| even start address | `utf16_require_alignment` | compilers align wide literals |
| at most N non-ASCII script groups | `max_script_groups` | real text stays in one script; misread bytes wander |
| all-non-ASCII strings need extra length | `min_length_non_ascii` | short all-CJK runs are the bulk of false positives |
| no private-use, noncharacters or unpaired surrogates | always | never valid in a real literal |

These are heuristics, not proofs, and they are deliberately not "reject CJK" — a
Japanese-language application legitimately contains Japanese. `tests/test_strings.cpp`
asserts both directions: real Japanese, Cyrillic and accented Latin survive; phantom
CJK, scattered scripts, pointer tables and lone surrogates do not.

## Function list (`sp functions`, `functions.json`)

Small enough to load eagerly when a binary is opened.

```json
{
  "schema_version": "1.0",
  "count": 1962,
  "functions": [
    {
      "id": 216172782113783809,
      "va": "0x140001080",
      "name": "sub_140001080",
      "extent_end": "0x1400010f4",
      "block_count": 5,
      "instruction_count": 31,
      "is_thunk": false,
      "is_imported_stub": false,
      "returns": true,
      "indirect_call_count": 1,
      "callee_count": 3,
      "caller_count": 0,
      "confidence": "certain"
    }
  ]
}
```

Filter `is_thunk` and `is_imported_stub` out of the default UI list. An
import-heavy binary has hundreds of one-jump stubs that bury the real functions.

`id` is a stable identifier. **Attach user and AI annotations to `id`, not to
`va`** — addresses shift when the engine re-analyses a region, ids never do.

## Function detail (`sp cfg --at VA`, `functions/func_<va>.json`)

The document the graph view and the lifting agent both read.

```json
{
  "schema_version": "1.0",
  "id": 216172782113783809,
  "va": "0x140001080",
  "name": "sub_140001080",
  "extent_end": "0x1400010f4",
  "convention": "win64",
  "is_thunk": false,
  "is_imported_stub": false,
  "returns": true,
  "instruction_count": 31,
  "indirect_call_count": 1,
  "confidence": "certain",
  "provenance": [
    { "kind": "pe-unwind-info", "confidence": "certain", "source": null },
    { "kind": "direct-call-target", "confidence": "high", "source": "0x1400020a4" }
  ],
  "frame": { "local_size": 40, "saved_regs_size": 1, "uses_frame_pointer": true },
  "block_order": ["0x140001080", "0x14000109a", "0x1400010a8"],
  "blocks": [
    {
      "id": 144115188075855873,
      "start": "0x140001080",
      "end": "0x14000109a",
      "instruction_count": 6,
      "has_unresolved_exit": false,
      "instructions": [
        {
          "va": "0x140001080",
          "size": 4,
          "mnemonic": "sub",
          "operands": "rsp, 0x28",
          "flow": "sequential",
          "bytes": "4883ec28",
          "target": null,
          "target_name": null,
          "indirect": false,
          "confidence": "certain",
          "provenance": [
            { "kind": "fall-through", "confidence": "high", "source": "0x140001080" }
          ]
        },
        {
          "va": "0x140001094",
          "size": 6,
          "mnemonic": "call",
          "operands": "qword ptr [rip + 0x1f0ce]",
          "flow": "call",
          "bytes": "ff15ce f00100",
          "target": null,
          "target_name": null,
          "indirect": true,
          "confidence": "certain",
          "provenance": []
        }
      ],
      "successors": [
        { "target": "0x1400010a8", "kind": "taken",        "confidence": "high" },
        { "target": "0x14000109a", "kind": "fall-through", "confidence": "high" }
      ],
      "predecessors": []
    }
  ],
  "callees": [ { "va": "0x140002100", "name": "sub_140002100" } ],
  "callers": [],
  "unreachable_blocks": []
}
```

### Fields that matter most

**`block_order`** is reverse post-order from the entry. Use it as the vertical
layout order in the graph view — it reads roughly the way execution runs. It is
also the correct visitation order if you ever do dataflow.

**`target_name`** is the resolved symbol for a branch or call destination. This
one field is the difference between `call 0x140001a20` and `call CreateFileW`,
for a human reader and for the model. Show it; put it in the prompt.

**`has_unresolved_exit`** means the engine could not determine where control goes
— almost always an unresolved jump table from a `switch`. The block will have
zero successors, but that is *not* a dead end. **Render this differently** (dashed
border, warning icon) or your graph will look complete while missing most of the
function.

**`successors[].kind`** is one of `fall-through`, `taken`, `jump`,
`indirect-jump`, `call`, `return`. Colour `taken` and `fall-through` differently
in the graph — that is what makes a conditional readable.

**`unreachable_blocks`** lists blocks not reachable from the entry. Usually a bad
decode or an unresolved indirect branch. Surfaced rather than hidden.

**`flow`** on an instruction is one of `sequential`, `conditional-jump`,
`unconditional-jump`, `call`, `return`, `interrupt`, `halt`, `unknown`. Note that
a `call` does *not* end a basic block — it returns, so the block continues.

## Call graph (`sp callgraph`, `callgraph.json`)

```json
{
  "schema_version": "1.0",
  "function_count": 1962,
  "nodes": [
    { "va": "0x140001080", "name": "sub_140001080", "is_thunk": false,
      "has_indirect_calls": true }
  ],
  "edges": [ { "from": "0x140001080", "to": "0x140002100" } ],
  "processing_order": ["0x140002100", "0x140001080"]
}
```

**`processing_order` is for the n8n loop.** It is bottom-up: leaves first, then
their callers. Process functions in this order and by the time the lifting agent
reaches a caller, its callees already have summaries that can go in the prompt.
Processing in address order instead throws that away.

`has_indirect_calls` means this node's outgoing edges are incomplete.

## Batch export (`sp export --out DIR`)

```
DIR/
├── manifest.json          function index in processing order
├── image.json
├── functions.json
├── callgraph.json
└── functions/
    ├── func_140001080.json
    └── func_140002100.json
```

`manifest.json`:

```json
{
  "schema_version": "1.0",
  "functions": [
    { "va": "0x140002100", "name": "sub_140002100",
      "file": "functions/func_140002100.json",
      "instruction_count": 12, "block_count": 2 }
  ],
  "count": 1874
}
```

The manifest lists functions in bottom-up processing order with thunks already
filtered out (pass `--keep-thunks` to include them). n8n should iterate this
array in order and read each `file`.

**Why batch rather than one invocation per function:** analysis takes seconds on
a real PE. Calling `sp cfg --at ...` per function would re-analyse the entire
image every time. Run `sp export` once per upload; serve the files from the API.

## Notes for the n8n workflow

**Render, don't dump.** Turn the function JSON into compact assembly text plus a
short CFG description before prompting. Pasting raw JSON into the prompt spends
most of the context window on field names and punctuation.

**Never regex the assembly back out.** The structure is already in the JSON.

**Require a mapping in the model's response.** The lifting agent must return,
alongside the C, which block each C line came from — e.g.
`{"line": 12, "block": "0x14000109a"}`. Without this the side-by-side view cannot
highlight, which is the entire point of the Ghidra-style pane. This has to be in
the prompt contract from day one; it is nearly impossible to retrofit.

**Tell the model what is uncertain.** Pass through `confidence` and
`has_unresolved_exit` so it can hedge instead of confidently describing a bad
decode.

## Fields for the AI layer

These live on both the function summary and the function detail document, and
they exist specifically so the n8n layer does not have to reimplement analysis in
JavaScript.

**`content_hash`** (integer) — hash of the function's instruction sequence.
**Use this as your cache key.** It is computed from mnemonics and instruction
lengths rather than raw bytes, so the same library function compiled into two
different binaries hashes identically. CRT and library code is a large fraction
of any binary, so caching on this is the single biggest cost reduction available.

**`information_score`** (0–100) — how much there is here worth explaining.
Derived from API calls, referenced strings, size, branching and caller count.
Returns 0 for thunks, import stubs, and tiny featureless functions. **Threshold on
this to decide what gets a model call at all.**

**`cyclomatic_complexity`** — edges − nodes + 2. Route low values to a cheaper
model.

**`api_calls`** (array of strings) — imported APIs this function calls, e.g.
`"kernel32!CreateFileW"`. **Resolved through IAT slots**, so indirect calls are
included — which matters, because nearly every Windows API call compiles to
`call qword [rip+N]` rather than a direct call. Usually the most informative
single field about what a function does.

**`referenced_strings`** (array of strings) — read-only string literals this
function references, decoded from ASCII or UTF-16 and always returned as UTF-8.
Often more decisive about purpose than the whole instruction listing. A function
referencing `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` is identifiable at a
glance.

**`is_library_code`** (bool) — matched a known library signature. Currently always
`false`; signature matching is not implemented yet.

Also new at the instruction level:

**`memory_ref`** (hex string or null) — absolute address of a statically-known
memory operand. Set for rip-relative and absolute displacements, null when the
address is computed from registers at runtime. This is what string references and
IAT-slot resolution are built on.

**`target_name`** now resolves indirect calls too. For `call qword [rip+0x1f0ce]`
it returns the imported symbol behind that IAT slot rather than null.

## Suggested n8n pipeline

Ordered so the cheap deterministic steps run before anything expensive:

```
1. Cache lookup        by content_hash            skip if seen
2. Triage              information_score, size    skip / cheap / expensive
3. Prompt build        render the bundle to text  Code node, not an LLM
4. Lifting agent       LLM
5. Deterministic check api_calls present?         free, catches most errors
                       every line_mapping block exists?
6. Validator agent     LLM, only for survivors
7. Store
```

Steps 1, 2, 3 and 5 need no model at all. Getting those right is worth more than
any prompt tuning.

## Findings (`sp findings`, `findings.json`)

Risky operations and whether untrusted input can reach them.

```json
{
  "schema_version": "1.0",
  "methodology": {
    "analysis": "call-graph reachability",
    "value_level_dataflow": false,
    "proves_exploitability": false,
    "note": "Findings identify risky operations and whether a call path exists..."
  },
  "input_sources": [
    { "function": "0x140001080", "function_name": "sub_140001080",
      "api": "api-ms-win-core-file-l1-1-0.dll!ReadFile", "source": "file" }
  ],
  "findings": [
    {
      "function": "0x140003000",
      "function_name": "sub_140003000",
      "api": "msvcrt.dll!strcpy",
      "kind": "unbounded-copy",
      "reachable_from_input": true,
      "base_severity": "high",
      "severity": "high",
      "sources": ["file"],
      "call_path": [
        { "va": "0x140001080", "name": "sub_140001080" },
        { "va": "0x140002000", "name": "sub_140002000" },
        { "va": "0x140003000", "name": "sub_140003000" }
      ],
      "limitation": "A call path exists from a function that reads untrusted input..."
    }
  ],
  "summary": { "risky_operations": 34, "input_sources": 12, "impactful": 3 }
}
```

### Read the methodology block before rendering severity

This analysis establishes that a **call path exists** between a function that
reads untrusted input and a function performing a risky operation. It does **not**
perform value-level dataflow, so it does not establish that attacker-controlled
bytes reach the affected argument, nor that intervening length checks are absent.

Reachability is a *necessary* condition for exploitability, not a sufficient one.

**Do not render these as confirmed vulnerabilities.** Show `severity` alongside
`limitation`, and label the section something like "requires review" rather than
"vulnerabilities found". A security tool that overstates its confidence is worse
than no tool, because someone will act on it.

### How severity is derived

`severity` is **composed**, never asserted — from the sink kind *and* whether it
is reachable:

| `kind` | reachable | not reachable |
|---|---|---|
| `unbounded-copy` (`strcpy`, `strcat`) | high | low |
| `format-string`, `remote-write`, `process-launch` | medium | low |
| `bounded-copy`, `library-load`, `memory-protect` | low | informational |
| `registry-write`, `file-write` | informational | informational |

An unbounded copy with no reachable path is a code-quality note, not a High. That
composition is what makes the number defensible when someone asks why.

**`call_path`** is the evidence. Render it — a reachability claim without the path
is unverifiable. Shorter paths are stronger evidence, and `impactful` findings are
already sorted worst-first then shortest-path-first.

**Unreachable findings are still included** so the inventory is complete. Filter
on `reachable_from_input` for a summary view.

## Also new on function documents

**`reachable_from_input`** (bool) and **`input_sources`** (array) — whether
untrusted data can reach this function at all. A risky operation matters far more
when this is true, and it is a good triage signal in its own right.

## Not yet emitted

Planned, not in v1.0. Additive, so they will not break existing consumers:

- `loops`, `regions` — loop and if/else structure recovery
- `notable_constants` — recognisable magic numbers (MD5 init, CRC polynomials)
- `annotations` — names, comments and tags from users and the AI layer
- `mitigations` — NX, ASLR, /GS, CFG flags from the PE headers
- `jump_tables` — resolved targets for indirect jumps (46 unresolved on
  notepad.exe, 902 on kernel32.dll, all currently marked
  `has_unresolved_exit`)

`reachable_from_input`, `findings` and `strings` were on this list and are now
emitted; `xrefs` are available per function as `callers` and `referenced_strings`,
though not yet as a standalone per-address table.

## How this reaches a browser or n8n

Neither the frontend nor n8n reads these files. `backend/` runs the engine and
serves the same documents over HTTP, one route per document — see
`backend/README.md`. The route names mirror the file names, so `image.json` is
`GET /api/runs/{id}/image`. The one exception is `strings`, which the API reshapes
out of `image.json` into `{"strings": [...]}` rather than making the engine write
the same data twice.

## Fixtures

`docs/fixtures/` holds hand-written sample documents matching this schema. They
are not generated output — they exist so the API, n8n and frontend work can start
before the engine is complete. Build against them, then swap in real output.
