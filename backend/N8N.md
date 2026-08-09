# Connecting n8n

Handoff document for whoever builds the workflows. Everything described here is
already implemented on the backend side — the only thing missing is the n8n end.

## The shape of it

n8n is a **stateless function**. It receives one function's worth of data, calls a
model, and posts the answer back. It stores nothing, remembers nothing, and never
sees the binary or the filesystem.

```
                 ┌──────────────────────────────────────┐
   Webhook  ◀────┤ backend  POST $N8N_WEBHOOK_URL       │
      │          └──────────────────────────────────────┘
      ▼
   build prompt  ──▶  model  ──▶  parse reply
                                     │
                 ┌───────────────────▼──────────────────┐
                 │ HTTP Request                          │
                 │ POST http://localhost:3000{{callback}}│
                 └───────────────────────────────────────┘
```

The request carries a `callback` field. **Post the result to that URL** — do not
construct one. It already encodes the run, the task and the address, so a result
cannot be filed against the wrong function.

## Step 1 — point the backend at your webhook

In `backend/.env`:

```
N8N_WEBHOOK_URL=http://localhost:5678/webhook/analyse
```

Restart the API. Check it took:

```
curl http://localhost:3000/api/health
```

`"n8n_configured": true` means requests will be forwarded. While it is `false`,
every AI endpoint answers `{"state":"not-run"}` instead of failing — the UI stays
usable, it just says the AI layer is not connected.

## Step 2 — one webhook, three tasks

The same webhook receives all three. Branch on `task`:

| `task` | what to ask the model | what to return |
| --- | --- | --- |
| `decompile` | readable C for this function | `{code, summary}` |
| `bugs` | defects in this function and its call path | `{issues: [...]}` |
| `behaviour` | what capabilities this function shows | `{summary}` |

A **Switch** node on `{{$json.task}}` is the whole of it.

## Step 3 — the payload you receive

This is a real capture, not an illustration — `POST /functions/0x1400023a0/lift`
with the webhook pointed at a listener:

```jsonc
{
  "task": "decompile",
  "run_id": "20260808065600-af9a70d5",
  "va": "0x1400023a0",
  "callback": "/api/runs/20260808065600-af9a70d5/ai/decompile/0x1400023a0/result",

  "context": null,               // what the human said about the binary, if anything
  "image": { "arch": "x86_64", "image_base": "0x140000000",
             "sections": [...], "imports": [...] },

  "function": {
    "va": "0x1400023a0",
    "name": "NPInit",
    "instruction_count": 61,
    "block_count": 9,
    "blocks": [ /* every instruction, with API names resolved */ ],
    "cyclomatic_complexity": 7,
    "information_score": 74,
    "reachable_from_input": true,
    "api_calls": ["ADVAPI32.dll!RegSetValueExW", "KERNEL32.dll!lstrcpyW"],
    "referenced_strings": ["Software\\Microsoft\\Windows\\CurrentVersion\\Run"]
  },

  // One paragraph per callee, NOT their code. This is what makes per-function
  // analysis possible without the whole binary in the prompt.
  "callees": [
    { "va": "0x140002500", "name": "sub_140002500",
      "summary": "Copies a wide string into a caller-supplied buffer.",
      "api_calls": [], "referenced_strings": [] }
  ],

  // Only for task=bugs: the route from input source to sink.
  "call_path_context": [],

  // What the static engine already concluded. Facts, not suggestions.
  "engine_findings": [
    { "function": "0x1400023a0", "api": "KERNEL32.dll!lstrcpyW",
      "kind": "UnboundedCopy", "reachable_from_input": true,
      "base_severity": "high", "severity": "high",
      "sources": ["RegQueryValueExW"],
      "call_path": [ {"va":"0x1400023a0","name":"NPInit"},
                     {"va":"0x140002500","name":"sub_140002500"} ],
      "limitation": "no value-level dataflow" }
  ],

  "rules": {
    "severity_owner": "engine",
    "note": "Severity and reachability are derived by the static engine. Explain
             and contextualise them; do not re-rate them. ..."
  }
}
```

### The two fields that do the real work

**`callees[].summary`** — the mechanism that lets one function be analysed without
the rest of the binary. Decompilation runs bottom-up, so by the time a caller is
processed its callees have already been summarised. A `null` summary means that
callee has not been lifted yet: reason from its `api_calls` and strings rather
than assuming it does nothing.

**`engine_findings`** — the static analysis result. `severity`, `reachable_from_input`
and `call_path` are derived facts. The model's job is to explain them, never to
produce them. The backend enforces this: it overwrites `severity_source` to
`"engine"` on every stored result, so a model that returns a severity is ignored.

## Step 4 — what to post back

To `{{ $json.callback }}`, prefixed with the backend's origin.

**decompile**

```json
{
  "model": "gpt-4o-mini",
  "code": "int NPInit(void) {\n  wchar_t buf[32];\n  ...\n}",
  "summary": "Reads the saved font size from the Notepad settings key and copies it into a fixed stack buffer."
}
```

`summary` is not optional. It becomes the `callees[].summary` in every later
prompt, so omitting it degrades every caller analysed afterwards.

**bugs**

```json
{
  "model": "gpt-4o-mini",
  "issues": [
    {
      "title": "Unbounded copy from a registry value",
      "detail": "lstrcpyW takes no length argument; the source is a registry value the program did not produce.",
      "engine_finding": "KERNEL32.dll!lstrcpyW",
      "confidence": "high"
    }
  ]
}
```

`engine_finding` should be the `api` string of the finding this issue refers to.
Setting it marks the issue **corroborated** — a static finding stands behind it.
Omitting it is legitimate for something the engine missed, and the UI badges that
row **unconfirmed** so a reader knows it is a lead rather than a result.

**behaviour**

```json
{ "model": "gpt-4o-mini", "summary": "Writes a value under the Run key, which causes the program to start at logon." }
```

## Step 5 — check it end to end

You do not need a model to test the plumbing. Curl the callback directly:

```bash
RUN=<run id from the Reports tab>
curl -X POST -H 'Content-Type: application/json' \
  -d '{"model":"manual-test","code":"int f(){return 0;}","summary":"Test."}' \
  http://localhost:3000/api/runs/$RUN/ai/decompile/0x1400023a0/result
```

Open that function on the Analysis tab — the Decompiler pane shows it immediately.
If that works, the only variable left is the model call.

## Things that will bite you

**Post to `callback`, not a URL you build.** The address in the path is how a
result is filed. Get it wrong and the result lands on another function.

**Return valid JSON.** The backend stores the body as-is. An n8n node that returns
the model's raw text with markdown fences around it will store the fences.

**One function per request.** Do not batch inside n8n. The backend already queues,
retries and tracks progress; a second queue inside the workflow means two systems
disagreeing about what is in flight.

**Concurrency is 4.** The backend dispatches at most four at a time. Do not add
parallelism in n8n on top of that — you will hit provider rate limits and the
failures will look like our bug.

**Results are versioned.** Posting a result for a function that already has one
does not destroy the old version; it becomes `current` and the previous moves to
`history`. Findings record which version they were reasoned from and are badged
**stale** when it changes. So re-running is safe.

## Reference implementation

`backend/aijobs.js` and `buildAiPayload` in `backend/server.js` are a working
reference for the orchestration half — selection, ordering, queueing, callbacks.
They belong to the API/n8n side of the project, not the engine. Take them over,
change them, or replace them; they exist so the flow demonstrably works rather
than being described in a spec.
