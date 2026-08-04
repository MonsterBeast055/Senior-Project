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
  }
}
```

`coverage.code_fraction` is the share of executable bytes the engine could
explain. `unclaimed_ranges` is what it could not. Both are reported deliberately:
a tool that hides its blind spots is worse than one that names them. Shade those
ranges in the UI rather than pretending the analysis is complete.

`iat_slot` is the address an indirect call actually reads. It is how
`call qword [rip+0x1234]` gets resolved to `KERNEL32.dll!CreateFileW`.

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

## Not yet emitted

Planned, not in v1.0. Additive, so they will not break existing consumers:

- `xrefs` — cross-references per address
- `loops`, `regions` — loop and if/else structure recovery
- `strings` — referenced string literals
- `annotations` — names, comments and tags from users and the AI layer
- `findings` — security findings and patch proposals

## Fixtures

`docs/fixtures/` holds hand-written sample documents matching this schema. They
are not generated output — they exist so the API, n8n and frontend work can start
before the engine is complete. Build against them, then swap in real output.
