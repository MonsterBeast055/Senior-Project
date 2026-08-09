# Running it end to end

Upload an `.exe`, watch the engine work through it live, and browse the result.
Everything here works today with no AI layer involved.

## Quick start

**Two processes have to be running.** This is the thing that catches people:
starting only the frontend gives you a working-looking UI where every upload
fails, and the only evidence is `ECONNREFUSED` in the Vite terminal.

Double-click **`start-dev.bat`**, then open <http://localhost:5173>. It starts
both.

The top-right corner of the app shows which state you are in — **API up**,
**API down**, or **engine missing** — so you never have to read the terminal to
find out.

That script checks the engine is built, installs dependencies on first run,
writes `backend/.env` pointing at your `sp.exe`, and opens two windows — the API
and the frontend dev server.

Try `C:\Windows\System32\notepad.exe` first. It is a real x64 binary with
`.pdata`, imports and strings, so every pane has something in it.

## Three pieces

| piece | what it is | port |
| --- | --- | --- |
| `Senior-Project/` | the C++ engine. Reads a PE file, writes JSON. | — |
| `backend/` | Node API. Runs the engine, stores and serves its output. | 3000 |
| `frontend-react/` | React UI. Talks only to the API. | 5173 |

The engine has no idea a web app exists, and the web app has no idea a
filesystem exists. The API is the only thing that knows both.

## By hand

```
REM 1. build the engine (Visual Studio, x64-release) so this exists:
REM    out\build\x64-release\Senior-Project\sp.exe

cd backend
npm install
copy .env.example .env
REM edit .env: SP_BINARY must point at your sp.exe
npm start

REM in a second terminal
cd frontend-react
npm install
npm run dev
```

Vite proxies `/api` to port 3000, so the browser only ever talks to one origin
and there is no CORS to get wrong.

## What you should see

Drop a binary on the upload page. The stage list ticks through as the engine
runs, with the engine's own summary line under the bar:

```
✓ Upload received
✓ Parsing PE headers, sections, imports        loaded ... arch=x86_64 ...
✓ Disassembling (recursive descent, then sweep) disassembled 38202 instructions ...
✓ Discovering function boundaries               found 517 function candidates
→ Building control-flow graphs                  built 452 functions, 6424 blocks ...
· Checking input reachability
· Writing JSON
```

Those numbers are the engine's, not a simulated animation. Progress comes from
parsing the engine's stderr as it runs — see `backend/README.md`.

When it reaches `done` the workspace opens:

- **Symbol tree** — functions grouped by triage score, findings, imports by
  library, strings, sections
- **Assembly** — disassembly with Windows API calls resolved by name, including
  indirect `call qword [rip+N]` through IAT slots
- **Graph window** — the CFG for the selected function, movable and resizable, so
  it sits beside the listing rather than replacing it
- **Findings** — risky operations, with the severity the engine derived and the
  call path from an input source as evidence
- **Search** — Ctrl+K, across functions, imports, strings and findings
- **Imports and strings** — click one to see *who uses it*, each caller clickable.
  Executable sections list the functions inside them
- **AI Analysis tab** (between Analysis and Reports) — the same symbol tree on the
  left, and three panes: Decompile, Find bugs, Behaviour profile. The behaviour
  profile's capability evidence is the engine's and works with no AI layer at all
- **Reports** — every previous run, reopenable without re-analysing

## What needs n8n

- **Decompiler pane** and the **AI Analysis** tab's Decompile pane — decompiled C
- **AI Analysis → Find bugs** pane — model-written defect reports
- **Why is this severity high?** — inside a finding window
- Per-function prose in the **AI Analysis → Behaviour** pane

All report `not-run` until `N8N_WEBHOOK_URL` is set in `backend/.env`. Batch
*selection* still runs without it, so you can see which 40 functions would be sent
and why — the queue holds them.

The **behaviour profile's capability evidence** does not need n8n. Persistence,
injection, networking, credential access and anti-analysis signals are matched from
imports and strings by the backend, with the evidence cited for each.

`not-run` is deliberately not an error — an error would make the UI look broken
when in fact a teammate's part simply is not built yet.

The severity rating is always the engine's. The backend overwrites
`severity_source` to `"engine"` on anything the AI posts back, so a model can never
quietly re-rate a finding. And the behaviour profile is labelled
`capability-evidence`, never a verdict: the same APIs appear in installers and
backup tools as in malware, so what holds up is the evidence, not the conclusion.

## When something is wrong

**`API down` in the corner, or `ECONNREFUSED` in the Vite terminal** — the
backend is not running. In a second terminal:

```
cd backend
npm start
```

The indicator turns green within five seconds; there is also a Retry button.

**`engine missing` in the corner** — the API is up but cannot find `sp.exe`. Fix
`SP_BINARY` in `backend/.env` and restart the API. `/api/health` prints the path
it tried.

**"missing MZ/PE signature"** — the file is not a PE image.

**A run fails mid-way** — `GET /api/runs/<id>/log` returns the engine's stderr
verbatim, which usually names the problem.

**The Decompiler pane is empty** — expected. See above.

**Imports show `—` for Callers, or "No cross-reference index in this run"** — the
run was analysed by an engine build predating `api_xrefs`. Rebuild the engine in
Visual Studio and upload the binary again; stored runs are not retro-fitted, because
the indexes come out of the engine, not the API.

## Offline browsing

The menu has **Analysis → Data source: sample**. That switches the whole UI to
real engine output from notepad.exe embedded in the app, so the interface can be
demonstrated with no backend and no binary at hand. Sample mode simulates the
upload rather than performing it, which is why the live API is now the default.

## Verified

- Engine: 79 C++ tests pass; real output checked against notepad.exe x64
  (452 functions, 6424 blocks, 9240 edges, 94.4% coverage, 182 strings),
  32-bit notepad, and kernel32.dll (1693 exports).
- Frontend: `npm run typecheck` clean, production build succeeds.
- Backend: `node test/contract.mjs` checks every field the UI reads is present with
  the right type; `node test/ai-contract.mjs` checks the xref indexes and the AI
  queue, including that `severity_source` is forced back to `"engine"` and that no
  verdict field appears anywhere in a behaviour profile. Also covered:
  404-means-absent, path-traversal rejection, hex-address validation, and 50
  concurrent progress writes with no lost fields.

## Not built yet

Juliet corpus evaluation, jump-table resolution for unresolved indirect jumps
(46 on notepad, 902 on kernel32), loop and structural analysis, and PE mitigation
checks (NX, ASLR, /GS) in the findings layer.
