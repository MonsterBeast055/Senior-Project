# Benchmark corpus

Thirteen functions with **known source code**, for measuring AI lifting accuracy.

## Why this exists rather than using notepad.exe

`notepad.exe` is a good engine test — varied, real, large. It is a bad *lifting*
test, because there is no source to compare against. You can confirm the model
returned something; you cannot confirm it returned the right thing.

Here the original C **is** the ground truth. That turns "the lifting looks
reasonable" into a number you can put in a report.

## Building

From a **x64 Native Tools Command Prompt for VS**:

```
cd benchmark
build.bat
```

Produces in `benchmark\out\`:

| Artifact | Why |
|---|---|
| `benchmark_x64_od.exe` | `/Od` — near one-to-one with source. Start here. |
| `benchmark_x64_o2.exe` | `/O2` — inlined, reordered. **This is the real test.** |
| `benchmark_x64.dll` | Exports path, cleaner function list |

Build the x86 variant from an **x86** Native Tools prompt — it has no `.pdata`,
so it exercises the prologue-matching fallback.

## Running it through the engine

```powershell
$sp = "..\out\build\x64-release\Senior-Project\sp.exe"
& $sp export .\out\benchmark_x64_o2.exe --out .\out\run-o2
```

Because every function is `__declspec(dllexport)`, the engine finds them all as
`Certain` candidates. Function-boundary accuracy is therefore never the variable
under test — only lifting quality is.

## What each function tests

| Function | Shape under test |
|---|---|
| `bm_add_scaled` | Baseline: straight-line, no control flow |
| `bm_sum_to_n` | Single counted loop |
| `bm_matrix_trace` | Nested loops, nesting-depth recovery |
| `bm_classify` | Dense switch → **jump table** (currently `has_unresolved_exit`) |
| `bm_validate` | Early-return cascade, one shared exit |
| `bm_count_char` | Pointer-walking loop over a string |
| `bm_factorial` | Direct recursion — call-graph self-cycle |
| `bm_is_even` / `bm_is_odd` | **Mutual recursion** — call-graph SCC detection |
| `bm_read_first_bytes` | `CreateFileW`/`ReadFile`/`CloseHandle` — API-name signal |
| `bm_set_run_key` | Registry Run key — textbook persistence behaviour |
| `bm_find_record` | Struct array indexing — type inference |
| `bm_unsafe_copy` | Unbounded `strcpy` — Tier-2 vulnerability indicator |
| `bm_md5_init` | MD5 constants — weak-crypto detection |

## Scoring lifted output

Grade each function on three axes rather than pass/fail. Partial credit is more
informative and less arguable.

**Semantics (0–2)** — does the lifted C do the same thing?
2 = equivalent, 1 = right idea with errors, 0 = wrong.

**Naming (0–2)** — is the suggested name meaningful?
`read_file_prefix` = 2, `process_data` = 1, `sub_140001000` = 0.

**Structure (0–2)** — are loops and conditionals recovered?
2 = matches, 1 = present but malformed, 0 = flat.

Max 78 across 13 functions. Report the score for `/Od` and `/O2` separately —
the gap between them is the interesting result, because it tells you how much
compiler optimisation costs you.

## Regression targets

Specific things to re-measure as engine features land:

- **`bm_classify`** — currently produces `has_unresolved_exit`. Jump-table
  resolution should give it a fan-out of 9 edges.
- **`bm_is_even` / `bm_is_odd`** — `callgraph.json` `processing_order` should
  report these as a cycle, and the pair must still appear before their callers.
- **`bm_count_char`, `bm_set_run_key`** — once string extraction lands, their
  `referenced_strings` should be populated. Expect a large jump in naming score
  for `bm_set_run_key` once the model can see the Run key path.
- **`bm_sum_to_n`, `bm_matrix_trace`** — once `LoopAnalysis` lands, loop counts
  should be 1 and 2. Structure scores should rise across the board.

## Note on scope

Nothing here is malicious. `bm_set_run_key` writes a registry value and
`bm_unsafe_copy` has a deliberate overflow, but both are inert examples for
testing detection logic. Do not add real malware samples to this repository.
