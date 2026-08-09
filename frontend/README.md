# Frontend

Reverse-engineering UI for the Senior-Project analysis engine. Layout follows
IDA Pro and Ghidra; visual style is Windows XP (Luna).

## Running it

**Double-click `index.html`.** No build step, no npm, no server.

Sample data is embedded in `js/data.js` rather than fetched, precisely so this
works from a `file://` URL — browsers block `fetch()` there, so a fetch-based
sample would need a web server just to look at the layout.

To point it at the real backend: set **Data** to *Backend API* in the toolbar and
adjust the base URL.

## Why it looks like this

No animations, no transitions, no rounded cards, no whitespace-heavy layout. A
reverse-engineering tool is read for hours at a stretch, so it should be dense,
static and predictable. Ghidra and IDA look the way they do for that reason, not
by accident.

Text selection is disabled globally and re-enabled only on the code panes, so
click-navigating doesn't leave stray selections everywhere.

## Layout

```
┌─────────────────────────────────────────────────────────────┐
│ menu / toolbar (filter, thunk + score toggles, data source) │
├───────────┬─────────────────────────┬───────────────────────┤
│ Functions │ Disassembly | Graph     │ Decompiler            │
│  (list)   │  (tabs)                 │  (AI-lifted C)        │
├───────────┴─────────────────────────┴───────────────────────┤
│ Findings | Strings | Cross-references | Imports | Sections  │
├─────────────────────────────────────────────────────────────┤
│ status bar                                                  │
└─────────────────────────────────────────────────────────────┘
```

## The feature that matters

**Click a line of decompiled C — the matching basic block highlights in both the
disassembly and the graph.** Click a graph node, and it works the other way.

That three-way link is the whole reason for the side-by-side layout, and it works
only because the AI layer returns `line_mapping` alongside the C:

```json
"line_mapping": [ { "line": 13, "block": "0x1400023e0" } ]
```

**If n8n stops returning that field, this feature silently degrades to three
disconnected text panes.** It is the one cross-team contract worth checking in CI.

Try it: open `sub_1400023a0`, click line 13 (`wcscpy`) in the Decompiler pane.

## Where the data comes from

| Pane | Source | Endpoint |
|---|---|---|
| Functions, Disassembly, Graph, Xrefs | C++ engine | `GET /runs/{id}/functions[/{va}]` |
| Findings, Strings, Imports, Sections | C++ engine | `GET /runs/{id}/findings`, `/strings`, `/image` |
| Decompiler | n8n → backend | `GET /runs/{id}/functions/{va}/lifted` |

The frontend never talks to the engine or n8n directly — only to the backend API.

## Sample data is real

`js/data.js` is not invented. The function at `0x140002418` is the actual CFG the
engine produced for `C:\Windows\System32\notepad.exe`: 20 blocks, 34 edges, every
instruction as Capstone decoded it. It's the MSVC CRT's `__isa_available_init` —
you can see the `GenuineIntel` vendor check in the `xor` constants.

Using real output was deliberate. A mock built from imagination would have let the
UI quietly assume things the engine doesn't actually provide.

`sub_1400023a0` is synthetic, because the sample needed a function with resolved
API calls, referenced strings, a reachable finding and lifted C in order to
exercise those paths.

## Three things the UI is careful about

**`has_unresolved_exit`** renders with a dashed red border and an explicit
`[unresolved exit]` label. A block with no successors that isn't a `ret` is an
unresolved `switch` — **not** a dead end. Hide that and the graph looks complete
while missing chunks of the function.

**The findings banner is not decoration.** Severity here comes from call-graph
reachability, not taint analysis. It shows that a path *exists*, not that
attacker-controlled data reaches the vulnerable argument. The banner says so, and
every row carries the engine's `limitation` text as a tooltip. Don't remove it —
a security tool that overstates confidence is worse than no tool.

**Large functions refuse to render as a graph.** notepad.exe has a real
1620-block function; above ~200 blocks a layered layout is unreadable at any zoom,
so the Graph tab explains itself and points at the Disassembly tab instead.

## Graph layout

`js/graph.js` implements a small layered (Sugiyama-lite) layout — no dagre, no
ELK, no dependencies. It leans on `block_order` from the engine (reverse
post-order), which already answers the hard question of what goes above what.
Back edges are detected and routed around the left side so loops read correctly
instead of turning the graph inside out.

Edge colours match Ghidra's convention: green = taken, grey = fall-through,
blue = unconditional jump, dashed amber = resolved indirect jump.

## Extending it

Files are plain ES5-ish JavaScript with no framework, so anyone on the team can
edit them.

- `js/data.js` — the only file that knows where data comes from. Change endpoints
  here.
- `js/graph.js` — layout and SVG. Swap for React Flow + dagre if you want
  draggable nodes; the data shape won't change.
- `js/app.js` — panes and selection.
- `css/xp.css` — theme.

If you later move to a framework, keep `data.js` as the boundary — everything
else is replaceable, that file is the contract.
