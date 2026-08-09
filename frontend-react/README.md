# Frontend (React)

Reverse-engineering UI for the Senior-Project analysis engine. Layout follows IDA
Pro and Ghidra; visual style is Windows XP (Luna). React + TypeScript + React Flow
+ dagre.

There is also `../frontend/` — the same layout in vanilla JS with no build step.
Keep it: it opens by double-clicking `index.html`, which is useful for a demo on a
machine with no Node installed.

## Running it

```
cd frontend-react
npm install
npm run dev
```

Opens on <http://localhost:5173>. Vite proxies `/api` to `http://localhost:3000`,
so the browser sees a same-origin API and nobody has to get CORS right.

Sample data (real engine output) is embedded, so it runs with **no backend**.
Switch **Data** to *Backend API* in the toolbar once the API layer exists.

> **Note:** `npm install` was not completed in the environment this was authored
> in — the sandbox could not reach the full npm registry. The code is
> syntax-checked and its imports/exports are cross-verified, but the first
> `npm run dev` on your machine is the real test. If TypeScript complains, it will
> be a type mismatch rather than a structural problem.

## Why it looks like this

No transitions, no animations, no rounded cards, no generous whitespace. A tool
you read for hours should be dense, static and predictable. Ghidra and IDA look
the way they do for that reason.

React Flow's defaults are explicitly overridden in `styles/xp.css`: animated
edges off, node transitions off, handles hidden, `fitView` duration 0. A graph you
are tracing a branch through must not move under the cursor.

## Views

**Upload** — drop an `.exe`/`.dll`, watch the engine's stages, land in Analysis.
**Analysis** — the three-pane workspace. **Reports** — previous runs, reopenable
without re-analysing.

```
┌──────────────────────────────────────────────────────────────┐
│ Upload | Analysis | Reports                    Data: [ ... ] │
├──────────────────────────────────────────────────────────────┤
│ overview cards (arch, functions, coverage, impactful, entropy)│
├───────────┬──────────────────────────┬───────────────────────┤
│ Functions │ Disassembly | Graph      │ Decompiler  (n8n)     │
├───────────┴──────────────────────────┴───────────────────────┤
│ Findings | Strings | Cross-references | Imports | Sections   │
├──────────────────────────────────────────────────────────────┤
│ status bar                                                   │
└──────────────────────────────────────────────────────────────┘
```

## Responsive

A three-column disassembler needs width. Rather than shrink everything into
unreadability, each breakpoint **drops a column and moves its content into the
centre tab strip** — which is why `useBreakpoint.ts` exists rather than the CSS
handling it alone. Hiding a column without relocating its content is how you make
panes unreachable.

| Width | Layout |
|---|---|
| > 1180px | 3 columns: Functions, Disassembly/Graph, Decompiler |
| 860–1180px | 2 columns; Decompiler becomes a centre tab |
| < 860px | 1 column; Functions and Decompiler both become tabs, and the page scrolls as a document instead of pinning to the viewport |
| < 560px | Menu bar hidden, dock tables scroll horizontally |

The thresholds in `useBreakpoint.ts` **must match** the media queries in
`styles/xp.css`. They are checked against each other by the verification script.

### The scroll bug this replaces

The first version set `overflow: hidden` on `body` alongside `height: 100%` and a
fixed `190px` dock. On any window smaller than the layout's natural size, content
was simply unreachable — no scrollbar, no way to get at it. Now: `min-height`
instead of `height`, real `min-height` floors on every panel and column, and below
860px the app becomes a normal scrolling document.

## Where n8n plugs in

Everything in the Decompiler pane comes from the AI layer, never from the C++
engine. `src/ui/Decompiler.tsx` owns the whole lifecycle:

```
not-run  →  queued  →  running  →  done | failed
                                     ↓
                            accepted / rejected
```

Three backend endpoints, all in `src/api/client.ts`:

| Endpoint | Purpose |
|---|---|
| `GET  /runs/{id}/functions/{va}/lifted` | current result, or 404 |
| `POST /runs/{id}/functions/{va}/lift` | trigger the n8n webhook |
| `POST /runs/{id}/functions/{va}/lifted/review` | accept or reject |

The backend forwards `lift` to n8n's webhook, n8n calls the model, and posts the
result back. The frontend never talks to n8n directly.

**Accept/Reject is the important one.** Model output is provisional until a human
signs off, and an accepted name is meant to land in the engine's
`AnnotationStore` and appear in the next export. That is the feedback loop the
architecture was built around — this pane is where a person closes it.

## The feature that justifies the layout

**Click a line of decompiled C — the matching basic block highlights in both the
disassembly and the graph.** Click a graph node and it works the other way.

`selectedBlock` in `App.tsx` is the single piece of state behind it, and it only
works because the AI returns `line_mapping`:

```json
"line_mapping": [ { "line": 13, "block": "0x1400023e0" } ]
```

**If n8n stops returning that field, this degrades silently to three disconnected
text panes.** It is the one cross-team contract worth a CI check.

Try it: open `sub_1400023a0`, click line 13 (the `wcscpy`).

## Graph layout

`src/ui/CfgGraph.tsx`, React Flow + dagre:

- `rankdir: "TB"` — control flows downward, like every disassembler
- `ranker: "network-simplex"` — best vertical compaction dagre offers
- Nodes are fed in **`block_order`** (reverse post-order) so dagre's within-rank
  tie-break lines up with execution order for free
- `smoothstep` edges with `borderRadius: 0` — sharp orthogonal corners, not curves
- Edge colours follow Ghidra: green taken, grey fall-through, blue jump, dashed
  amber indirect
- Only the taken branch is labelled `T`; marking both sides of every conditional
  doubles the ink for no information
- Selection updates node data **in place** with no relayout, so clicking never
  makes the graph jump
- Above 200 blocks the graph refuses to render and explains why — notepad.exe
  contains a real 1620-block function

## Sample data is real

`src/api/sample.ts` is not invented. The function at `0x140002418` is the actual
CFG the engine produced for `C:\Windows\System32\notepad.exe`: **20 blocks, 34
edges, 106 instructions**, every one as Capstone decoded it. It's the MSVC CRT's
`__isa_available_init` — the `GenuineIntel` vendor check is visible in the `xor`
constants at `0x140002436`.

Using real output was deliberate. A mock built from imagination would have let the
UI quietly assume things the engine doesn't provide.

`sub_1400023a0` is synthetic, because the sample needed one function with resolved
API calls, referenced strings, a reachable finding and lifted C in order to
exercise those paths.

## Three things the UI is careful about

**`has_unresolved_exit`** renders dashed red with an explicit `[unresolved exit]`
label. A block with no successors that isn't a `ret` is an unresolved `switch` —
**not** a dead end. Hide that and the graph looks complete while missing chunks of
the function.

**The findings banner is not decoration.** Severity comes from call-graph
reachability, not taint analysis: it shows a path *exists*, not that
attacker-controlled data reaches the vulnerable argument. Every row carries the
engine's `limitation` text as a tooltip. A security tool that overstates its
confidence is worse than no tool.

**Addresses are strings, never numbers.** 64-bit values don't survive JavaScript's
number type. `content_hash` is a hex string for the same reason — a cache key that
loses its low bits produces wrong cache hits.

## Files

| File | Role |
|---|---|
| `src/api/types.ts` | TypeScript mirror of `docs/json-schema.md`. **Change this first** when the engine adds a field. |
| `src/api/client.ts` | The only file that knows where data comes from. Keep it as the boundary. |
| `src/api/sample.ts` | Real engine output for offline use. |
| `src/ui/CfgGraph.tsx` | React Flow + dagre. |
| `src/ui/Decompiler.tsx` | The n8n seam. |
| `src/ui/Panes.tsx` | Function list, disassembly, dock tables. |
| `src/ui/Chrome.tsx` | XP window furniture. |
| `src/App.tsx` | Layout and selection state. |
| `src/styles/xp.css` | Theme, including React Flow overrides. |
