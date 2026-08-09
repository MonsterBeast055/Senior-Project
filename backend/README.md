# backend — the API between the engine and everything else

The C++ engine is a program that reads a PE file and writes JSON. This turns it
into something a browser and n8n can use. Nothing above this layer ever sees a
file path or a binary.

```
browser  ──HTTP──▶  backend  ──spawn──▶  sp.exe  ──writes──▶  analysis/*.json
                       │                                            │
                       └────────────────── reads ───────────────────┘
                       │
                       └──HTTP──▶  n8n webhook  ──HTTP──▶  back here
```

Plain JavaScript, no build step, two dependencies. That is deliberate: whoever
owns the API can read all of it in one sitting and take it over.

## Who owns what

Worth stating plainly, because this folder sits on a team boundary.

| part | owner | why |
| --- | --- | --- |
| `Senior-Project/` (the C++ engine) | **the engine author** | Only the engine has the call graph, the code map and the provenance. `information_score`, `processing_order`, `call_path` and `content_hash` can be computed nowhere else. |
| `backend/` — upload, storage, run lifecycle, routes | the API teammate | Ordinary web-service work. |
| `backend/aijobs.js` + `buildAiPayload` in `server.js` | the API/n8n teammates — **reference implementation** | Written here so the flow demonstrably works end to end, and so the selection strategy is shown rather than described. Hand it over; do not treat it as finished. |
| n8n workflows | the n8n teammate | Prompt text, model choice, parsing, retries. |

The line worth remembering: **the engine decides what is worth analysing; the
orchestration layer decides when and in what order.** Emitting `processing_order`
is the engine's job. Obeying it is this layer's.

## Setup

```
cd backend
npm install
copy .env.example .env        # macOS/Linux: cp .env.example .env
```

Then edit `.env` and set `SP_BINARY` to the compiled engine. On this machine:

```
SP_BINARY=C:\Users\rozan\Desktop\Senior-Project\out\build\x64-release\Senior-Project\sp.exe
```

Start it:

```
npm start
```

It prints where it is listening, where data goes, and whether it found the
engine. If the engine is missing it says so at startup rather than letting the
first upload fail mysteriously.

Check it:

```
curl http://localhost:3000/api/health
```

## What works without n8n

Almost everything. Upload, live progress, the function index, the disassembly, the
CFG, strings, imports, sections, findings with severity and call paths, the symbol
tree, search, previous reports, the import and string cross-reference lookups, and
the behaviour profile's capability evidence — all of it comes from the engine's own
output and works today.

What needs n8n:

- **Decompiler pane** and `ai/decompile` — decompiled C for a function
- **Finding explanation** — the "why is this severity high" narrative
- `ai/bugs` — model-written defect reports
- Per-function prose inside the behaviour profile

While `N8N_WEBHOOK_URL` is unset, those endpoints return HTTP 200 with
`{"state": "not-run"}` and a message. Not an error: an error would make the UI look
broken when in fact a teammate's part simply is not built yet.

Batch *selection* still runs without n8n, so `POST /ai/bugs` reports which
functions it would have sent and why. That makes the whole flow checkable before the
AI layer exists.

## Where things are stored

One directory per run under `DATA_DIR`. No database — the engine's output *is* the
data, and copying it into a database would only create a second place for it to be
wrong.

```
data/runs/<run_id>/
  input.bin                the uploaded file, byte-for-byte, never executed
  meta.json                name, size, sha256, stage, percent, summary counts
  engine.log               the engine's stderr, verbatim
  analysis/                exactly what `sp.exe export --out` wrote
    image.json  functions.json  findings.json  callgraph.json  manifest.json
    functions/func_<va>.json
  context.json             what the human told us about the binary
  lifted/<va>.json         n8n results
  explanations/<va>_<api>.json
  aijob-<task>.json        batch progress: selection, queue, per-item state
  ai/<task>/<va>.json      one AI result
```

Deleting a run is `rm -rf` on one directory. Backing up the store is copying one
folder.

## How live progress works

No new engine feature and no IPC. The engine already narrates itself — every
analysis pass calls `core::log_info`, and the default sink writes
`[info] <message>` to stderr. `runner.js` reads that stream line by line and maps
messages onto the stages the UI already draws:

| engine says | stage |
| --- | --- |
| `loaded ... arch=...` | loading |
| `disassembled N instructions ...` | disassembling |
| `found N function candidates` | discovering |
| `built N functions, M blocks ...` | building-cfgs |
| `extracted N strings ...` | extracting-strings |
| `reachability: ...` | analysing-reachability |
| `analysis complete in Ns ...` | exporting |
| exit code 0 **and** `image.json` exists | done |

This couples the backend to the wording of log messages, which is worth stating
plainly. If someone rewords one, the progress bar loses a step and nothing else
breaks. The robust alternative — a structured progress channel — means changing
the engine, the CLI, and this file to add a single stage. Not worth it yet.

Exit code 0 is not treated as success on its own. `image.json` has to exist,
because that is the first document the frontend loads; without it the run is
broken regardless of what the engine claimed.

## Routes

Served from engine output — no n8n needed:

| method | path | notes |
| --- | --- | --- |
| GET | `/api/health` | engine path, data dir, n8n status |
| GET | `/api/runs` | newest first |
| POST | `/api/runs` | multipart, field `binary`. Returns `202 {run_id}` |
| GET | `/api/runs/:id/status` | `{stage, percent, message, error}` |
| DELETE | `/api/runs/:id` | removes the directory |
| GET | `/api/runs/:id/image` | |
| GET | `/api/runs/:id/functions` | |
| GET | `/api/runs/:id/functions/:va` | one function; 404 for thunks |
| GET | `/api/runs/:id/findings` | |
| GET | `/api/runs/:id/strings` | reshaped from `image.json` |
| GET | `/api/runs/:id/callgraph` | |
| GET | `/api/runs/:id/log` | the engine's stderr, as text |
| GET, PUT | `/api/runs/:id/context` | human-supplied facts |

Needing n8n:

| method | path |
| --- | --- |
| GET | `/api/runs/:id/functions/:va/lifted` |
| POST | `/api/runs/:id/functions/:va/lift` |
| POST | `/api/runs/:id/functions/:va/lifted/review` |
| GET | `/api/runs/:id/findings/:va/:api/explanation` |
| POST | `/api/runs/:id/findings/:va/:api/explain` |

### AI Analysis

Three tasks — `decompile` (logic lifting), `bugs`, `behaviour` — each runnable on
one function or as a score-ordered batch.

| method | path | notes |
| --- | --- | --- |
| GET | `/api/runs/:id/ai/:task` | batch progress |
| POST | `/api/runs/:id/ai/:task` | start a batch. Body `{limit, only[]}` |
| GET | `/api/runs/:id/ai/:task/:va` | one result, 404 if absent |
| POST | `/api/runs/:id/ai/:task/:va` | run one function now |
| POST | `/api/runs/:id/ai/:task/:va/result` | **n8n delivers here** |
| GET | `/api/runs/:id/ai/behaviour-profile` | capability evidence, no AI needed |

**Selection is the cost lever, and each task selects differently.** "Analyse this
binary" cannot mean all 452 functions — most are CRT helpers, and a model call on
each buys you the news that a function adjusts the stack. Thunks, import stubs and
library code are excluded everywhere. Beyond that:

| task | selects by | picks up |
| --- | --- | --- |
| `decompile` | `information_score >= 20`, sequenced bottom-up by `processing_order` | functions with a recognisable purpose |
| `bugs` | the union of every finding's `call_path`, plus those functions' direct callees | the plumbing where defects live |
| `behaviour` | no selection — the backend scans imports and strings itself | capability evidence, no model needed |

The `bugs` split is the one that matters. `information_score` answers *"does this
function have a recognisable purpose"* — it is computed from API calls and strings.
That is the right question for explaining code and the **wrong** question for
finding bugs, because a tight byte-copying helper has neither APIs nor strings,
scores about 10, and is precisely where an overflow lives. Selecting bugs by
reachability instead means such a function is included whatever it scores.

An explicit `limit` in the request body switches to score-ranked selection with
that ceiling (manual mode). Omitting it means automatic: score >= 20 for
`decompile`, path-driven for `bugs`, capped at `MAX_AUTOMATIC` as a safety rail.

Functions that already have a stored result are counted as done rather than
re-dispatched, so re-running a batch after adding a few does not pay twice.

Dispatch is windowed at 4 concurrent requests: above a handful, a model provider
starts rate-limiting and the failures look like our bug rather than their throttle.

**`behaviour-profile` needs no AI.** Capabilities — persistence, process injection,
anti-analysis, network/C2, credential access, discovery, file and crypto operations
— are matched from imported API names and referenced strings, and every item lists
the evidence behind it. It is labelled `capability-evidence`, never a verdict: the
same APIs appear in installers, updaters and backup tools, and an LLM verdict on a
packed binary is a guess wearing a conclusion's clothes. The AI pass only adds
per-function prose on top.

Every stored AI result has `severity_source` overwritten to `"engine"`. A model may
explain a rating; it can never be the source of one.

`POST` on the two `GET` result paths (`.../lifted`, `.../explanation`) is how n8n
delivers a finished result. The forward to n8n is fire-and-forget on purpose: a
model call takes tens of seconds, and an HTTP request held open that long fails in
ways indistinguishable from a real error. The frontend polls the `GET` route.

**404 is part of the contract.** `client.ts` turns 404 into `null` and the pane
renders empty. A missing `lifted/<va>.json` means "not lifted yet", not "broken".

## For the n8n teammate

`POST .../lift` forwards a JSON payload to `N8N_WEBHOOK_URL`:

```jsonc
{
  "task": "lift",                  // or "explain-finding"
  "run_id": "20260805144601-fe63e0e4",
  "va": "0x140002418",
  "callback": "/api/runs/<id>/functions/0x140002418/lifted",
  "context": { /* context.json, or null */ },
  "image": { /* image.json: arch, imports, sections, coverage, strings */ },
  "function": { /* the full per-function document */ }
}
```

The whole function document travels in the request because n8n has no filesystem
and no way to read the binary. Post the result back to `callback` when done.

For `explain-finding` the payload also carries `finding` — the engine's own record,
including `severity`, `base_severity`, `reachable_from_input`, `call_path` and
`limitation`. **The model explains that rating; it does not set it.** The callback
handler overwrites `severity_source` to `"engine"` on every stored explanation, so
a model that tries to disagree cannot.

## Safety

The uploaded file is never executed. `sp.exe` is the only program spawned, and the
binary is passed to it as a path to read. Run ids are validated against
`^[A-Za-z0-9._-]{1,80}$` before being used to build a path, and addresses are
validated as hex before being used in a file name — both arrive from the network.

Uploads are capped at `MAX_UPLOAD_MB` (default 256) and written straight to disk;
holding a 200 MB DLL in the heap would be a needless way to run out of memory.

## Settings

| variable | default | meaning |
| --- | --- | --- |
| `SP_BINARY` | `sp.exe` (via PATH) | the compiled engine |
| `DATA_DIR` | `./data` | where runs are stored |
| `PORT` | `3000` | |
| `N8N_WEBHOOK_URL` | unset | when unset, AI routes report `not-run` |
| `MAX_UPLOAD_MB` | `256` | |
| `CORS_ORIGIN` | `*` | tighten if this is ever exposed |
