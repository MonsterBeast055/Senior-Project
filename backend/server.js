/*
 * server.js - The API the frontend talks to.
 *
 * This layer owns the filesystem and the engine process. Nothing above it —
 * neither the React app nor n8n — ever sees a file path or a binary. That is the
 * whole point of the split: the engine is a program that reads a file and writes
 * JSON, and this turns it into something a browser and a workflow tool can use.
 *
 * Every route here exists because frontend-react/src/api/client.ts calls it. The
 * paths are copied from that file rather than invented, because a URL that
 * disagrees by one segment is a 404 the user experiences as "the backend is
 * broken".
 *
 * Routes served from engine output (work today, no n8n needed):
 *   GET    /api/health
 *   GET    /api/runs                          list stored runs
 *   POST   /api/runs                          upload a binary, start analysis
 *   GET    /api/runs/:id/status               live progress
 *   DELETE /api/runs/:id
 *   GET    /api/runs/:id/image
 *   GET    /api/runs/:id/functions
 *   GET    /api/runs/:id/functions/:va
 *   GET    /api/runs/:id/findings
 *   GET    /api/runs/:id/strings
 *   GET    /api/runs/:id/callgraph
 *   GET    /api/runs/:id/log                  the engine's stderr
 *   GET;PUT /api/runs/:id/context             human-supplied facts
 *
 * Routes that need n8n (answer honestly when it is absent):
 *   GET    /api/runs/:id/functions/:va/lifted
 *   POST   /api/runs/:id/functions/:va/lift
 *   POST   /api/runs/:id/functions/:va/lifted/review
 *   GET    /api/runs/:id/findings/:va/:api/explanation
 *   POST   /api/runs/:id/findings/:va/:api/explain
 *
 * And the callback n8n itself uses to deliver results:
 *   POST   /api/runs/:id/functions/:va/lifted
 *   POST   /api/runs/:id/findings/:va/:api/explanation
 */
const express = require("express");
const multer = require("multer");
const fsp = require("fs/promises");
const path = require("path");

const store = require("./store");
const runner = require("./runner");
const aijobs = require("./aijobs");

/* Load .env without a dependency. dotenv would be one more thing to install
 * before the project runs, and this file is eleven lines. */
(function loadEnv() {
    const fs = require("fs");
    const file = path.join(__dirname, ".env");
    if (!fs.existsSync(file)) return;
    for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
        const match = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/.exec(line);
        if (!match || line.trim().startsWith("#")) continue;
        // Real environment wins, so `SP_BINARY=... npm start` overrides the file.
        if (process.env[match[1]] === undefined) {
            process.env[match[1]] = match[2].replace(/^["']|["']$/g, "");
        }
    }
})();

store.ensureDirs();

/* Last resort. Analysis runs in the background after its HTTP request is
 * answered, so a bug in that path has no request to fail — in Node it becomes an
 * unhandled rejection, and the default action is to exit. A dead API is a much
 * worse outcome than one broken run, so log loudly and stay up. This is a safety
 * net, not a licence: the background paths handle their own errors. */
process.on("unhandledRejection", (cause) => {
    console.error("[unhandled rejection]", cause);
});
process.on("uncaughtException", (cause) => {
    console.error("[uncaught exception]", cause);
});

const app = express();
const PORT = Number(process.env.PORT || 3000);
const N8N_WEBHOOK_URL = (process.env.N8N_WEBHOOK_URL || "").trim();

/* The origin n8n should post results back to.
 *
 * Every payload we forward carries a `callback` URL, and n8n POSTs the model's
 * answer there. When n8n runs on this machine, "localhost" resolves correctly
 * and the default below is right. When it runs anywhere else — another laptop,
 * a Docker container, a tunnel — "localhost" means *that* host, so results are
 * posted into the void and the UI waits forever for a reply that was never
 * addressed to us. Nothing errors; the panes simply never fill in.
 *
 * So this is set to a LAN address or public URL whenever n8n is not local.
 * Trailing slashes are stripped because the callback paths already start with
 * one, and `//api/...` is a different route to Express. */
const PUBLIC_BASE_URL =
    (process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`).trim().replace(/\/+$/, "");

/** Absolute URL for a callback route. n8n is told to post to this verbatim. */
const callbackUrl = (pathname) => `${PUBLIC_BASE_URL}${pathname}`;

app.use(express.json({ limit: "8mb" }));

/* Vite proxies /api during development, so same-origin covers the normal case.
 * CORS is here for the times it will not be: the API teammate running the server
 * on a different port, or n8n posting results back from another host. */
app.use((request, response, next) => {
    response.setHeader("Access-Control-Allow-Origin", process.env.CORS_ORIGIN || "*");
    response.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
    response.setHeader("Access-Control-Allow-Headers", "Content-Type");
    if (request.method === "OPTIONS") return response.sendStatus(204);
    next();
});

/* Multer writes straight to disk. Memory storage would hold an entire binary in
 * the heap; a 200 MB DLL is a normal thing to analyse. */
const upload = multer({
    storage: multer.diskStorage({
        destination: (_request, _file, done) => done(null, store.UPLOAD_TMP),
        filename: (_request, file, done) =>
            done(null, `${Date.now()}-${Math.random().toString(16).slice(2)}${path.extname(file.originalname) || ".bin"}`),
    }),
    limits: { fileSize: Number(process.env.MAX_UPLOAD_MB || 256) * 1024 * 1024, files: 1 },
});

/* --- helpers ---------------------------------------------------------- */

/** Wrap an async handler so a rejected promise becomes a 500 rather than an
 *  unhandled rejection that silently kills the response. Express 4 does not do
 *  this itself. */
const wrap = (handler) => (request, response, next) =>
    Promise.resolve(handler(request, response, next)).catch(next);

/** Serve a stored engine document. 404 when absent is the contract the frontend
 *  relies on: client.ts turns 404 into `null` and the pane renders empty rather
 *  than showing an error. */
async function sendStored(response, file, { notFound = "not found" } = {}) {
    const body = await store.readJson(file);
    if (body === null) return response.status(404).json({ error: notFound });
    return response.json(body);
}

/** Addresses arrive as strings from the frontend and are used to build file
 *  names, so they are validated as hex and normalised to the engine's own
 *  spelling: lower case, `0x` prefix, no leading zeros. */
function normaliseVa(text) {
    const match = /^0[xX]([0-9a-fA-F]{1,16})$/.exec(String(text || "").trim());
    if (!match) return null;
    return `0x${match[1].toLowerCase().replace(/^0+(?=.)/, "")}`;
}

/** Turn an API name into something safe to use as a file name.
 *  `KERNEL32.dll!lstrcpyW` becomes `KERNEL32.dll_lstrcpyW`. */
function apiKey(text) {
    return String(text || "").replace(/[^A-Za-z0-9._!-]/g, "_").slice(0, 120);
}

/* --- health ----------------------------------------------------------- */

app.get("/api/health", wrap(async (_request, response) => {
    const engine = await runner.probeEngine();
    response.json({
        ok: true,
        engine,
        data_dir: store.DATA_DIR,
        n8n_configured: N8N_WEBHOOK_URL.length > 0,
        // Both halves of the round trip, so a misconfigured one is visible here
        // rather than only as results that never arrive.
        n8n_webhook_url: N8N_WEBHOOK_URL || null,
        public_base_url: PUBLIC_BASE_URL,
        // Stated plainly, because "why is the Decompiler pane empty" is the
        // first question anyone will ask.
        note: N8N_WEBHOOK_URL
            ? "n8n webhook configured; lifting and explanations are available."
            : "n8n is not configured. Everything except decompiled C and finding "
              + "explanations works; those two report 'not-run'.",
    });
}));

/* --- runs ------------------------------------------------------------- */

app.get("/api/runs", wrap(async (_request, response) => {
    response.json({ runs: await store.listRuns() });
}));

app.post("/api/runs", upload.single("binary"), wrap(async (request, response) => {
    if (!request.file) {
        return response.status(400).json({ error: "expected a file in the 'binary' field" });
    }

    const runId = store.newRunId();
    const p = store.paths(runId);
    await fsp.mkdir(p.analysis, { recursive: true });

    // Move rather than copy where possible; rename across devices fails, so fall
    // back. The temp file is removed either way.
    try {
        await fsp.rename(request.file.path, p.input);
    } catch {
        await fsp.copyFile(request.file.path, p.input);
        await fsp.rm(request.file.path, { force: true });
    }

    const stat = await fsp.stat(p.input);
    // Truncated to 16 characters for display. The full digest is kept because it
    // is the only durable identity a sample has — file names get renamed.
    const digest = await store.sha256OfFile(p.input);

    await store.writeMeta(runId, {
        run_id: runId,
        file_name: request.file.originalname,
        file_size: stat.size,
        sha256: digest.slice(0, 16),
        sha256_full: digest,
        created_at: new Date().toISOString(),
        stage: "uploaded",
        percent: runner.STAGE_PERCENT.uploaded,
        error: null,
    });

    // Answer now, analyse in the background. The client polls /status, which is
    // why it can show per-stage progress instead of a hanging request.
    response.status(202).json({ run_id: runId });

    runner.startAnalysis(runId, {
        noSweep: request.query.no_sweep === "1",
        keepThunks: request.query.keep_thunks === "1",
    });
}));

app.get("/api/runs/:id/status", wrap(async (request, response) => {
    const meta = await store.readMeta(request.params.id);
    if (!meta) return response.status(404).json({ error: "no such run" });
    response.json({
        run_id: meta.run_id,
        stage: meta.stage,
        percent: meta.percent ?? 0,
        message: meta.message ?? null,
        error: meta.error ?? null,
    });
}));

app.delete("/api/runs/:id", wrap(async (request, response) => {
    const meta = await store.readMeta(request.params.id);
    if (!meta) return response.status(404).json({ error: "no such run" });
    await store.deleteRun(request.params.id);
    response.status(204).end();
}));

/* --- engine output ---------------------------------------------------- */

app.get("/api/runs/:id/image", wrap(async (request, response) => {
    const p = store.paths(request.params.id);
    await sendStored(response, path.join(p.analysis, "image.json"), {
        notFound: "image.json not written yet",
    });
}));

app.get("/api/runs/:id/functions", wrap(async (request, response) => {
    const p = store.paths(request.params.id);
    await sendStored(response, path.join(p.analysis, "functions.json"));
}));

app.get("/api/runs/:id/findings", wrap(async (request, response) => {
    const p = store.paths(request.params.id);
    await sendStored(response, path.join(p.analysis, "findings.json"));
}));

app.get("/api/runs/:id/callgraph", wrap(async (request, response) => {
    const p = store.paths(request.params.id);
    await sendStored(response, path.join(p.analysis, "callgraph.json"));
}));

/* The strings pane. The engine emits the global list inside image.json — one
 * document per concern would mean a second full analysis pass or a second file
 * for data already written, so this reshapes rather than re-reads. */
app.get("/api/runs/:id/strings", wrap(async (request, response) => {
    const p = store.paths(request.params.id);
    const image = await store.readJson(path.join(p.analysis, "image.json"));
    if (!image) return response.status(404).json({ error: "image.json not written yet" });
    response.json({ strings: image.strings ?? [] });
}));

/* Per-function detail. `export` writes one file per function named by address,
 * which makes this a lookup rather than a scan — the reason the frontend can
 * open a function out of a 1700-function binary without loading all of them. */
app.get("/api/runs/:id/functions/:va", wrap(async (request, response) => {
    const va = normaliseVa(request.params.va);
    if (!va) return response.status(400).json({ error: "va must be hex, e.g. 0x140001000" });

    const p = store.paths(request.params.id);
    const file = path.join(p.functions, `func_${va.slice(2)}.json`);
    const body = await store.readJson(file);
    if (body === null) {
        // Thunks are skipped by `export` unless --keep-thunks, so a missing file
        // is an ordinary outcome and the message says so.
        return response.status(404).json({
            error: `no exported detail for ${va} — it may be a thunk, or outside the analysed image`,
        });
    }
    response.json(body);
}));

app.get("/api/runs/:id/log", wrap(async (request, response) => {
    const p = store.paths(request.params.id);
    try {
        response.type("text/plain").send(await fsp.readFile(p.log, "utf8"));
    } catch {
        response.status(404).type("text/plain").send("no log for this run");
    }
}));

/* --- binary context (no n8n needed) ----------------------------------- */

app.get("/api/runs/:id/context", wrap(async (request, response) => {
    const p = store.paths(request.params.id);
    await sendStored(response, p.context, { notFound: "no context recorded" });
}));

app.put("/api/runs/:id/context", wrap(async (request, response) => {
    const meta = await store.readMeta(request.params.id);
    if (!meta) return response.status(404).json({ error: "no such run" });
    const p = store.paths(request.params.id);
    await store.writeJson(p.context, {
        ...request.body,
        saved_at: new Date().toISOString(),
    });
    response.json({ ok: true });
}));

/* ======================================================================
 * n8n boundary
 *
 * Two directions. The frontend asks this server to have something explained;
 * this server forwards to the n8n webhook with a run id and an address. n8n does
 * the model work and posts the result back to the callback routes below. The
 * frontend polls the GET routes until the result appears.
 *
 * The forward is fire-and-forget on purpose: a model call takes tens of seconds,
 * and holding an HTTP request open for that long fails in ways that are hard to
 * distinguish from a real error.
 *
 * When N8N_WEBHOOK_URL is unset, the POST routes return 200 with
 * state "not-run" and a message. They do not return an error — an error would
 * make the UI look broken when in fact a teammate's part simply is not built
 * yet.
 * ====================================================================== */

function n8nMissing(response) {
    return response.json({
        state: "not-run",
        message:
            "n8n is not configured on this server. Set N8N_WEBHOOK_URL in backend/.env "
            + "once the workflow exists.",
    });
}

/** Forward to n8n without waiting for the model. Node 18+ has global fetch. */
function forwardToN8n(payload) {
    if (!N8N_WEBHOOK_URL) return;
    const controller = new AbortController();
    // Bounded: if n8n is unreachable we want a logged failure, not a socket that
    // stays half-open until the process restarts.
    const timer = setTimeout(() => controller.abort(), 10_000);
    fetch(N8N_WEBHOOK_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: controller.signal,
    })
        .then((upstream) => {
            if (!upstream.ok) {
                console.error(`[n8n] webhook returned HTTP ${upstream.status}`);
            }
        })
        .catch((cause) => console.error(`[n8n] webhook failed: ${cause.message}`))
        .finally(() => clearTimeout(timer));
}

/* Lift and decompile are ONE operation with one store.
 *
 * They were two, and that was a real bug: `Lift with AI` wrote to
 * `lifted/<va>.json` while the automated decompile pass wrote to
 * `ai/decompile/<va>.json`. The Decompiler pane read only the first, so after a
 * full automated run every function still showed "no lifted output yet" — the
 * work had been done and paid for, and the UI could not see it.
 *
 * Everything now goes through the `decompile` task: same store, same payload
 * builder, same queue accounting. The routes below are kept because `client.ts`
 * and any n8n workflow already point at them, but they are thin adapters now.
 *
 * A side benefit: the manual lift now gets the callee summaries that
 * buildAiPayload assembles, which the old bespoke payload did not include. */

/** Adapt a stored decompile result to the shape the Decompiler pane expects.
 *
 *  The AI task returns `{code, summary}`; the pane renders `c_code: string[]` and
 *  `description`. Reconciling here rather than in the browser keeps one shape in
 *  the frontend contract and means an n8n workflow can return either form.
 *
 *  `c_code` in particular has to be an array — the pane does `c_code.map(...)`, so
 *  a plain string would be a TypeError and a blank screen. */
function asLiftedFunction(result) {
    if (!result) return null;

    // Version metadata travels in both shapes: the pane shows which lift it is
    // looking at, and whether an earlier one was superseded.
    const versionFields = {
        origin: result.origin ?? "automated",
        version_id: result.version_id ?? null,
        superseded: (result.history ?? []).map((v) => ({
            origin: v.origin ?? "automated",
            version_id: v.version_id ?? null,
            received_at: v.received_at ?? null,
        })),
    };

    if (Array.isArray(result.c_code)) return { ...result, ...versionFields };

    const code = typeof result.code === "string" ? result.code : "";
    return {
        ...result,
        ...versionFields,
        state: result.state ?? "done",
        suggested_name: result.suggested_name ?? result.name ?? "",
        description: result.description ?? result.summary ?? "",
        confidence: result.confidence ?? "medium",
        review: result.review ?? "not-reviewed",
        c_code: code.length > 0 ? code.split("\n") : [],
        line_mapping: result.line_mapping ?? [],
    };
}

/**
 * How much of a function the decompilation actually accounts for.
 *
 * The prompt asks the model to translate every basic block and to tag each line
 * of C with the block it came from. Nothing verified that it did. That is the
 * same unchecked assertion this project refuses everywhere else: severity is
 * forced back to the engine's precisely so a model cannot self-report a rating,
 * and completeness deserves the same treatment.
 *
 * Measured here rather than in the workflow, for two reasons. The check must not
 * live in the thing being checked - a workflow that skips blocks would happily
 * report full coverage. And only this side holds `func_<va>.json`, so only this
 * side knows how many blocks the function really has; n8n knows only what it was
 * sent, which may already have been truncated to fit a token budget.
 *
 * Derived from the tags in the generated code, never from a self-reported list.
 * A model can only raise this number by actually emitting a tagged line.
 */
async function decompileCoverage(runId, va, body) {
    const detail = await store.readJson(
        path.join(store.paths(runId).functions, `func_${va.slice(2)}.json`),
    );
    const blocks = (detail?.blocks ?? []).map((b) => b.start).filter(Boolean);
    if (blocks.length === 0) return null;

    const tagged = new Set();
    for (const entry of body?.line_mapping ?? []) {
        if (entry && entry.block) tagged.add(String(entry.block));
    }

    const real = new Set(blocks);
    const missing = blocks.filter((block) => !tagged.has(block));
    const covered = blocks.length - missing.length;

    return {
        blocks_total: blocks.length,
        blocks_covered: covered,
        fraction: Number((covered / blocks.length).toFixed(3)),
        /* Blocks with no line of C attributed to them. A shortfall can mean the
         * model skipped them or that they were truncated out of the prompt
         * before it ever saw them - not distinguishable from here, and the
         * distinction does not change the fact that they are unaccounted for. */
        missing,
        /* Tags naming a block this function does not contain. Should be empty;
         * a non-empty list means the mapping cannot be trusted. */
        unknown: [...tagged].filter((block) => !real.has(block)),
    };
}

app.get("/api/runs/:id/functions/:va/lifted", wrap(async (request, response) => {
    const va = normaliseVa(request.params.va);
    if (!va) return response.status(400).json({ error: "va must be hex" });
    const runId = request.params.id;

    const result = await aijobs.getResult(runId, "decompile", va);
    if (result) return response.json(asLiftedFunction(result));

    // Fallback for runs written before the stores were merged, so existing data
    // is not orphaned by the fix.
    const legacy = await store.readJson(path.join(store.paths(runId).lifted, `${va}.json`));
    if (legacy) return response.json(asLiftedFunction(legacy));

    response.status(404).json({ error: "not lifted yet" });
}));

app.post("/api/runs/:id/functions/:va/lift", wrap(async (request, response) => {
    const va = normaliseVa(request.params.va);
    if (!va) return response.status(400).json({ error: "va must be hex" });
    if (!N8N_WEBHOOK_URL) return n8nMissing(response);

    const runId = request.params.id;
    // Validates the function exists and produces the same payload the automated
    // pass uses - including callee summaries.
    await buildAiPayload(runId, "decompile", va);
    // force: asking for this one function by name means redo it. Without this
    // the batch skip applies and Re-lift silently does nothing.
    const job = await aijobs.startBatch(
        runId, "decompile", { only: [va], force: true }, dispatchAi);
    // Report the job's real state. Answering "queued" unconditionally is what
    // hid the bug: the pane polled for two minutes against a request that was
    // never sent.
    response.json({ state: job.pending.length > 0 ? "queued" : job.state });
}));

/** n8n posts a finished lift here.
 *
 *  Routed into the same recorder as the automated pass, so a result lands in one
 *  place regardless of which callback URL the workflow was pointed at. */
app.post("/api/runs/:id/functions/:va/lifted", wrap(async (request, response) => {
    const va = normaliseVa(request.params.va);
    if (!va) return response.status(400).json({ error: "va must be hex" });
    const runId = request.params.id;
    const body = { ...(request.body || {}) };
    body.coverage = await decompileCoverage(runId, va, body);
    // Origin "manual": this callback belongs to `Lift with AI`, which a user
    // pressed deliberately. It becomes current and pushes the automated version
    // into history rather than erasing it.
    await aijobs.recordResult(runId, "decompile", va, body, dispatchAi, "manual");
    // Keep the Reports table's Lifted column truthful.
    await store.patchMeta(runId, await store.summarise(runId));
    response.json({ ok: true });
}));

app.post("/api/runs/:id/functions/:va/lifted/review", wrap(async (request, response) => {
    const va = normaliseVa(request.params.va);
    if (!va) return response.status(400).json({ error: "va must be hex" });
    const runId = request.params.id;

    const current = await aijobs.getResult(runId, "decompile", va);
    if (!current) return response.status(404).json({ error: "nothing to review" });
    // A human verdict on model output is worth keeping: it is the only signal
    // that says whether the AI layer is actually any good.
    // Reviewing is not a new lift, so it keeps the version's own origin and does
    // not push a duplicate into history.
    const { history, ...withoutHistory } = current;
    void history;
    await aijobs.recordResult(runId, "decompile", va, {
        ...withoutHistory,
        review: request.body?.review ?? "not-reviewed",
        reviewed_at: new Date().toISOString(),
    }, dispatchAi, current.origin ?? "automated");
    response.json({ ok: true });
}));

app.get("/api/runs/:id/findings/:va/:api/explanation", wrap(async (request, response) => {
    const va = normaliseVa(request.params.va);
    if (!va) return response.status(400).json({ error: "va must be hex" });
    const p = store.paths(request.params.id);
    await sendStored(
        response,
        path.join(p.explanations, `${va}_${apiKey(request.params.api)}.json`),
        { notFound: "not explained yet" },
    );
}));

app.post("/api/runs/:id/findings/:va/:api/explain", wrap(async (request, response) => {
    const va = normaliseVa(request.params.va);
    if (!va) return response.status(400).json({ error: "va must be hex" });
    if (!N8N_WEBHOOK_URL) return n8nMissing(response);

    const runId = request.params.id;
    const p = store.paths(runId);
    const findings = await store.readJson(path.join(p.analysis, "findings.json"));
    const api = request.params.api;

    // Find the engine's own record of this finding and send that. The severity
    // and the call path are facts the engine derived; the model explains them
    // and must not be asked to re-decide them.
    //
    // The engine names the address field `function`, not `va` — findings.json is
    // keyed by the function containing the risky call.
    const finding = (findings?.findings ?? []).find(
        (candidate) => candidate.function === va && candidate.api === api,
    );

    forwardToN8n({
        task: "explain-finding",
        run_id: runId,
        va,
        api,
        callback: callbackUrl(`/api/runs/${runId}/findings/${va}/${encodeURIComponent(api)}/explanation`),
        context: await store.readJson(p.context),
        image: await store.readJson(path.join(p.analysis, "image.json")),
        finding: finding ?? null,
        function: await store.readJson(path.join(p.functions, `func_${va.slice(2)}.json`)),
    });
    response.json({ state: "queued" });
}));

/** n8n posts the finished explanation here. */
app.post("/api/runs/:id/findings/:va/:api/explanation", wrap(async (request, response) => {
    const va = normaliseVa(request.params.va);
    if (!va) return response.status(400).json({ error: "va must be hex" });
    const p = store.paths(request.params.id);
    await store.writeJson(
        path.join(p.explanations, `${va}_${apiKey(request.params.api)}.json`),
        {
            ...request.body,
            // Overwritten, not defaulted. The rating is the engine's, and an
            // explanation that claimed otherwise would undermine the one
            // property that makes these findings trustworthy.
            severity_source: "engine",
            received_at: new Date().toISOString(),
        },
    );
    response.json({ ok: true });
}));

/* ======================================================================
 * AI Analysis  (n8n)
 *
 * Three tasks — decompile, bugs, behaviour — each runnable on one function or as
 * a score-ordered batch. See aijobs.js for why selection and queueing live in
 * their own module.
 *
 * Routes:
 *   GET  /api/runs/:id/ai/:task              batch progress
 *   POST /api/runs/:id/ai/:task              start a batch  {limit, only[]}
 *   GET  /api/runs/:id/ai/:task/:va          one result, or 404
 *   POST /api/runs/:id/ai/:task/:va          run one function now
 *   POST /api/runs/:id/ai/:task/:va/result   n8n delivers a result here
 *   GET  /api/runs/:id/ai/behaviour-profile  aggregated capability evidence
 * ====================================================================== */

/** Everything n8n needs for one AI task on one function.
 *
 *  Sent whole because n8n has no filesystem: it cannot open the binary, and it
 *  cannot read a path we hand it. The engine's derived facts travel too, because
 *  a model that has to re-derive them will sometimes re-derive them wrongly. */
async function buildAiPayload(runId, task, va) {
    const p = store.paths(runId);
    const detail = await store.readJson(path.join(p.functions, `func_${va.slice(2)}.json`));
    if (!detail) {
        const error = new Error(`no exported detail for ${va}`);
        error.statusCode = 404;
        throw error;
    }
    const image = await store.readJson(path.join(p.analysis, "image.json"));
    const findings = await store.readJson(path.join(p.analysis, "findings.json"));

    // Only this function's findings. Sending all of them would invite the model to
    // discuss code it was not given.
    const relevant = (findings?.findings ?? []).filter((f) => f.function === va);

    /* Callee context: one paragraph each, not their disassembly.
     *
     * This is what makes per-function analysis work at all. `sub_A` calling
     * `sub_B` is meaningless without knowing what B does — but inlining B's
     * disassembly (and B's callees, and theirs) is how one prompt becomes the whole
     * binary. A summary is roughly a tenth the size and lossy in exactly the right
     * way: it keeps what the function does and discards which register held what.
     *
     * Summaries exist because decompilation runs bottom-up, so by the time a
     * caller is processed its callees have already been done. Where one is missing
     * — an unanalysed callee, or a run that started mid-way — the name and API
     * calls still go, which is far better than nothing. */
    const calleeContext = [];
    for (const callee of detail.callees ?? []) {
        const summary = await aijobs.getResult(runId, "decompile", callee.va);
        const calleeDetail = await store.readJson(
            path.join(p.functions, `func_${String(callee.va).slice(2)}.json`),
        );
        calleeContext.push({
            va: callee.va,
            name: callee.name,
            // Present once that callee has been lifted. Absent is normal, not an
            // error — say so rather than sending an empty string the model has to
            // interpret.
            summary: summary?.summary ?? null,
            // Always available from the engine, and often enough on its own: a
            // callee whose only API calls are RegQueryValueExW and lstrcpyW is
            // legible without any model output at all.
            api_calls: calleeDetail?.api_calls ?? [],
            referenced_strings: (calleeDetail?.referenced_strings ?? []).slice(0, 8),
            is_library_code: calleeDetail?.is_library_code ?? false,
        });
    }

    /* Bug hunting gets the call path, not just the function.
     *
     * A defect frequently spans functions: the allocation is in one, the write in
     * another, the length check in a third — or missing from all of them. Asking
     * about one function in isolation is asking the model to judge a bounds check
     * it cannot see.
     *
     * The engine already computed the exact slice worth sending: the call path from
     * an input source to the risky sink. It is short (seven functions in a typical
     * finding), and it is precisely where the bug lives if there is one. This is
     * the second pass, and it is why bottom-up-per-function is not the whole
     * answer. */
    const pathContext = [];
    if (task === "bugs") {
        const seen = new Set();
        for (const finding of relevant) {
            for (const step of finding.call_path ?? []) {
                if (seen.has(step.va)) continue;
                seen.add(step.va);
                const stepDetail = await store.readJson(
                    path.join(p.functions, `func_${String(step.va).slice(2)}.json`),
                );
                const stepSummary = await aijobs.getResult(runId, "decompile", step.va);
                pathContext.push({
                    va: step.va,
                    name: step.name,
                    summary: stepSummary?.summary ?? null,
                    api_calls: stepDetail?.api_calls ?? [],
                    referenced_strings: (stepDetail?.referenced_strings ?? []).slice(0, 8),
                    // The sink function's code goes in full; the intermediate hops
                    // travel as summaries. Sending seven full disassemblies would
                    // reintroduce the size problem this design exists to avoid.
                    is_sink: step.va === va,
                });
            }
        }
    }

    return {
        task,
        run_id: runId,
        va,
        callback: callbackUrl(`/api/runs/${runId}/ai/${task}/${va}/result`),
        context: await store.readJson(p.context),
        // Image-level facts worth having: architecture, what it imports, whether a
        // section looks packed. Trimmed of the bulky indexes.
        image: image
            ? {
                arch: image.arch,
                image_base: image.image_base,
                entry_point: image.entry_point,
                sections: image.sections,
                coverage: image.coverage,
                imports: image.imports,
            }
            : null,
        function: detail,
        // The interface between levels. See the comment where this is built.
        callees: calleeContext,
        // Only populated for the bugs task. See above.
        call_path_context: pathContext,
        engine_findings: relevant,
        // Stated in the payload, not just in a document nobody reads. The model is
        // asked to explain a rating, never to produce one.
        rules: {
            severity_owner: "engine",
            severity_source: "engine",
            note:
                "Severity and reachability are derived by the static engine. Explain "
                + "and contextualise them; do not re-rate them. For behaviour, cite "
                + "the api_calls and referenced_strings that support each capability, "
                + "and do not assert a malicious verdict.",
            context_note:
                "`callees` carries a summary per callee rather than its code, so this "
                + "function can be understood without the whole binary in the prompt. "
                + "A null summary means that callee has not been lifted yet - reason "
                + "from its api_calls and strings instead of assuming it does nothing. "
                + "For the bugs task, `call_path_context` is the route from an input "
                + "source to this sink; the bounds check you are looking for may be "
                + "in any step of it.",
        },
    };
}

/** Dispatch one item to n8n. Throws when n8n is absent, which the queue records
 *  as a failure with that reason. */
async function dispatchAi(runId, task, va) {
    if (!N8N_WEBHOOK_URL) {
        const error = new Error("n8n is not configured");
        error.statusCode = 503;
        throw error;
    }
    forwardToN8n(await buildAiPayload(runId, task, va));
}

function checkTask(task, response) {
    if (aijobs.TASKS.includes(task)) return true;
    response.status(400).json({
        error: `unknown AI task "${task}". Expected one of: ${aijobs.TASKS.join(", ")}`,
    });
    return false;
}

/* Registered before /ai/:task, and it has to stay that way. Express matches in
 * registration order, so with :task first a GET on /ai/behaviour-profile binds
 * task="behaviour-profile" and gets rejected as an unknown task. A literal path
 * segment that could also match a parameter must be declared earlier. */
/**
 * AI findings, reshaped to look like engine findings.
 *
 * The Findings box shows both in one list with a Source column, because the
 * interesting case is the engine and the model flagging the same function — you
 * want agreement or disagreement visible at a glance, not on two separate pages.
 *
 * That only works if both sides arrive in the same shape, so the mapping happens
 * here rather than in the browser. The model returns prose; the engine's fields it
 * cannot legitimately produce (`severity`, `reachable_from_input`, `call_path`) are
 * either copied from the matching engine finding or left null. A model-invented
 * severity would defeat the one property that makes this list trustworthy.
 *
 * Returns an empty list rather than 404 when nothing has run: the box then renders
 * "no AI findings yet" instead of an error.
 */
app.get("/api/runs/:id/ai-findings", wrap(async (request, response) => {
    const runId = request.params.id;
    const p = store.paths(runId);
    const job = await aijobs.getJob(runId, "bugs");
    const engineFindings =
        (await store.readJson(path.join(p.analysis, "findings.json")))?.findings ?? [];

    const rows = [];
    for (const va of Object.keys(job.items || {})) {
        const result = await aijobs.getResult(runId, "bugs", va);
        if (!result) continue;

        // Was this reasoned from a decompile version that has since been
        // replaced? A user pressing `Lift with AI` after the bug pass ran does not
        // invalidate the finding, but it does mean the text behind it has moved on
        // - and saying so is the difference between a reproducible conclusion and
        // one nobody can check.
        const stale = await aijobs.isStale(runId, va, result.derived_from);

        // Every engine finding in this function. Matching happens per *issue*
        // below, not per function.
        const inFunction = engineFindings.filter((f) => f.function === va);

        for (const issue of result.issues ?? []) {
            // Corroboration is per issue, and this distinction is the whole point
            // of the flag. Matching on the function alone was wrong: a model that
            // returns one real issue and one invented one for the same function had
            // both marked corroborated, so the invented row inherited credibility
            // from its neighbour. An issue is corroborated only when it names an
            // engine finding that actually exists.
            const engineMatch = issue.engine_finding
                ? inFunction.find((f) => f.api === issue.engine_finding) ?? null
                : null;

            rows.push({
                source: "ai",
                function: va,
                function_name: job.items[va]?.name ?? va,
                api: issue.engine_finding || "—",
                kind: issue.title || "issue",
                detail: issue.detail ?? "",
                model_confidence: issue.confidence ?? null,
                // Copied from the matched engine finding, never from the model.
                // Null when there is no match: no rating is the honest answer, and
                // borrowing a sibling finding's severity would be inventing one.
                severity: engineMatch?.severity ?? null,
                base_severity: engineMatch?.base_severity ?? null,
                reachable_from_input: engineMatch?.reachable_from_input ?? null,
                call_path: engineMatch?.call_path ?? [],
                sources: engineMatch?.sources ?? [],
                severity_source: "engine",
                // False when the model raised something with no static finding
                // behind it. Surfaced rather than dropped: it may be a real find the
                // analysis missed, or a hallucination. The reader decides, but they
                // need to know which kind of row they are looking at.
                engine_corroborated: engineMatch !== null,
                model: result.model ?? null,
                received_at: result.received_at ?? null,
                derived_from: result.derived_from ?? null,
                stale,
            });
        }
    }

    response.json({
        run_id: runId,
        findings: rows,
        job_state: job.state,
        n8n_configured: N8N_WEBHOOK_URL.length > 0,
        note:
            "Severity, reachability and call paths on these rows come from the "
            + "engine, matched by function address. The model supplies the title and "
            + "explanation only. A row with engine_corroborated=false has no static "
            + "finding behind it — treat it as a lead, not a result. A row with "
            + "stale=true was reasoned from a decompile version that has since been "
            + "replaced; the finding still stands but its source text has changed.",
    });
}));

/**
 * Behaviour profile: capabilities with the evidence for each.
 *
 * Deliberately not a verdict. "This is malware" from a language model reading
 * disassembly is a guess dressed as a conclusion, and a packed installer looks
 * identical to a dropper by these signals. What holds up is the evidence: this
 * binary writes a Run key, and here are the three functions that do it.
 *
 * The engine-derived half of this needs no AI at all, so it is computed here and
 * returned whether or not n8n has ever run. The AI half adds prose per function.
 */
const CAPABILITY_RULES = [
    {
        id: "persistence",
        label: "Persistence",
        // Substring tests, case-insensitive, against api_calls and strings. Crude
        // and readable on purpose: a capability nobody can audit is a capability
        // nobody should act on.
        apis: ["regsetvalue", "regcreatekey", "createservice", "schedule", "taskservice"],
        strings: ["\\\\run", "currentversion\\\\run", "runonce", "\\\\services\\\\"],
    },
    {
        id: "process-injection",
        label: "Process injection",
        apis: ["writeprocessmemory", "virtualallocex", "createremotethread",
               "openprocess", "queueuserapc", "setthreadcontext", "ntmapviewofsection"],
        strings: [],
    },
    {
        id: "anti-analysis",
        label: "Anti-analysis",
        apis: ["isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
               "outputdebugstring", "queryperformancecounter", "gettickcount"],
        strings: ["ollydbg", "windbg", "x64dbg", "vmware", "virtualbox", "sandbox"],
    },
    {
        id: "network",
        label: "Network / C2",
        apis: ["winhttp", "internetopen", "httpsendrequest", "wsastartup", "connect",
               "send", "recv", "getaddrinfo", "urldownload"],
        strings: ["http://", "https://", "user-agent"],
    },
    {
        id: "credential-access",
        label: "Credential access",
        apis: ["cryptunprotectdata", "lsa", "samr", "credenumerate", "credread"],
        strings: ["login data", "signons", "wallet", "password"],
    },
    {
        id: "discovery",
        label: "Host discovery",
        apis: ["getcomputername", "getusername", "getsysteminfo", "getvolumeinformation",
               "createtoolhelp32snapshot", "process32", "getadaptersinfo"],
        strings: [],
    },
    {
        id: "file-tampering",
        label: "File and crypto operations",
        apis: ["cryptencrypt", "cryptacquirecontext", "cryptgenkey", "movefile",
               "deletefile", "setfileattributes", "findfirstfile"],
        strings: [],
    },
];

app.get("/api/runs/:id/ai/behaviour-profile", wrap(async (request, response) => {
    const runId = request.params.id;
    const p = store.paths(runId);
    const manifest = await store.readJson(path.join(p.analysis, "manifest.json"));
    const image = await store.readJson(path.join(p.analysis, "image.json"));
    if (!manifest) {
        return response.status(404).json({ error: "this run has no exported functions" });
    }

    // Per-function api_calls and referenced_strings live in the per-function
    // documents, so this reads them. Bounded by the manifest, and the files are
    // local — on notepad.exe it is 452 small reads and takes well under a second.
    const capabilities = CAPABILITY_RULES.map((rule) => ({
        ...rule,
        evidence: [],
    }));

    for (const entry of manifest.functions ?? []) {
        const detail = await store.readJson(path.join(p.analysis, entry.file));
        if (!detail) continue;
        const apis = (detail.api_calls ?? []).map((a) => a.toLowerCase());
        const strings = (detail.referenced_strings ?? []).map((s) => s.toLowerCase());

        for (const capability of capabilities) {
            const apiHits = apis.filter(
                (a) => capability.apis.some((needle) => a.includes(needle)));
            const stringHits = strings.filter(
                (s) => capability.strings.some((needle) => s.includes(needle)));
            if (apiHits.length === 0 && stringHits.length === 0) continue;

            capability.evidence.push({
                va: detail.va,
                name: detail.name,
                information_score: detail.information_score ?? 0,
                reachable_from_input: !!detail.reachable_from_input,
                // The original spelling, not the lowercased form used for matching.
                api_calls: (detail.api_calls ?? []).filter(
                    (a) => capability.apis.some((n) => a.toLowerCase().includes(n))),
                strings: (detail.referenced_strings ?? []).filter(
                    (s) => capability.strings.some((n) => s.toLowerCase().includes(n))),
                // Filled in by the AI pass, per function, when it has run.
                //
                // A failed call still stores a result — the queue cannot settle
                // without one — and its summary field holds the failure text.
                // Rendering that here put "The model call did not succeed" into
                // the evidence column beside a real imported API, where it reads
                // as something the analysis found. Absent is the honest value.
                explanation: await (async () => {
                    const stored = await aijobs.getResult(runId, "behaviour", detail.va);
                    if (!stored || stored.parse_error === true) return null;
                    return stored.summary ?? null;
                })(),
            });
        }
    }

    // Packing is an image-level observation, not a per-function one.
    const packedSections = (image?.sections ?? []).filter(
        (s) => s.executable && s.entropy > 7.0);

    response.json({
        run_id: runId,
        // Named so nobody mistakes it for a verdict.
        kind: "capability-evidence",
        disclaimer:
            "Capabilities are matched from imported API names and referenced strings. "
            + "They describe what the binary is able to do, not what it does or "
            + "whether it is malicious — the same APIs appear in installers, "
            + "updaters and backup tools. Every item lists the evidence behind it.",
        capabilities: capabilities
            .filter((c) => c.evidence.length > 0)
            .map((c) => ({
                id: c.id,
                label: c.label,
                function_count: c.evidence.length,
                reachable_count: c.evidence.filter((e) => e.reachable_from_input).length,
                evidence: c.evidence.sort(
                    (a, b) => b.information_score - a.information_score),
            })),
        packed_sections: packedSections.map((s) => ({
            name: s.name, entropy: s.entropy,
            note: "High entropy in an executable section suggests packing or "
                + "encryption, which limits what static analysis can see.",
        })),
        ai_explanations_available: N8N_WEBHOOK_URL.length > 0,
    });
}));

/* --- literal AI routes -------------------------------------------------
 * These must be registered before any `/ai/:task` route. Express matches in
 * order, so a wildcard declared first claims `/ai/coverage` and reports
 * `unknown AI task "coverage"` - an error naming a route nobody requested.
 * Keep literal paths above the wildcards.
 * --------------------------------------------------------------------- */

/** Which functions already have AI results, per task. Drives the symbol tree's
 *  analysed/not-analysed marking. */
app.get("/api/runs/:id/ai/coverage", wrap(async (request, response) => {
    response.json(await aijobs.analysedFunctions(request.params.id));
}));

/**
 * What a hand-picked selection would come to, without starting it.
 *
 * Depth expansion is exponential, so the count has to be knowable before the
 * user commits rather than discovered from a progress bar that will not finish
 * for an hour. Body: {only: [va], depth: 0-7, findings: [{function, api}]}.
 */
app.post("/api/runs/:id/ai/preview", wrap(async (request, response) => {
    const runId = request.params.id;
    const body = request.body || {};

    const roots = Array.isArray(body.only) ? body.only.map(normaliseVa).filter(Boolean) : [];
    const fromFindings = Array.isArray(body.findings) && body.findings.length > 0
        ? await aijobs.selectionForFindings(runId, body.findings)
        : [];

    const expansion = await aijobs.expandSelection(
        runId, [...new Set([...roots, ...fromFindings])], body.depth ?? 0);

    // Names and scores, so the confirmation lists functions rather than addresses.
    const document = await store.readJson(
        path.join(store.paths(runId).analysis, "functions.json"));
    const index = new Map((document?.functions ?? []).map((f) => [f.va, f]));

    response.json({
        ...expansion,
        from_findings: fromFindings.length,
        functions: expansion.selected.map((va) => ({
            va,
            name: index.get(va)?.name ?? va,
            information_score: index.get(va)?.information_score ?? 0,
        })),
    });
}));

app.get("/api/runs/:id/ai/:task", wrap(async (request, response) => {
    if (!checkTask(request.params.task, response)) return;
    // Reclaim any dispatch that never came back before reporting progress. The
    // UI polls this while a run is in flight, so recovery rides on the polling
    // that is already happening rather than needing a timer on the server.
    const job = await aijobs.reapStalled(
        request.params.id, request.params.task, dispatchAi);
    response.json({ ...job, n8n_configured: N8N_WEBHOOK_URL.length > 0 });
}));

/**
 * The exact context that would be sent to the model, without sending it.
 *
 * Everything else in this project can be traced to its evidence; the prompt was
 * the one place a reader had to take it on faith. This closes that: the same
 * builder the dispatcher uses, so what is shown is what would be sent, not a
 * description of it.
 *
 * Deliberately does not require n8n. Being able to inspect what *would* go out
 * is most useful precisely when the AI layer is not configured, and it makes the
 * design inspectable by someone who never runs a model at all.
 */
app.get("/api/runs/:id/ai/:task/:va/payload", wrap(async (request, response) => {
    const { id, task } = request.params;
    if (!checkTask(task, response)) return;
    const va = normaliseVa(request.params.va);
    if (!va) return response.status(400).json({ error: "va must be hex" });

    const payload = await buildAiPayload(id, task, va);

    /* A few counts the raw document does not make obvious. Reading "3 of 7
     * callees have summaries" tells you more about the quality of this prompt
     * than scrolling the JSON does. */
    const callees = payload.callees ?? [];
    response.json({
        ...payload,
        // Not sent to the model; this is for the reader.
        _summary: {
            blocks: payload.function?.blocks?.length ?? 0,
            instructions: payload.function?.instruction_count ?? 0,
            api_calls: payload.function?.api_calls?.length ?? 0,
            referenced_strings: payload.function?.referenced_strings?.length ?? 0,
            callees: callees.length,
            callees_with_summary: callees.filter((c) => c.summary).length,
            engine_findings: (payload.engine_findings ?? []).length,
            call_path_steps: (payload.call_path_context ?? []).length,
            has_user_context: Boolean(payload.context),
        },
    });
}));



/** Stop one task's batch. Already-dispatched work still records if it returns. */
app.post("/api/runs/:id/ai/:task/stop", wrap(async (request, response) => {
    if (!checkTask(request.params.task, response)) return;
    const job = await aijobs.stopBatch(request.params.id, request.params.task);
    response.json(job);
}));

/** Delete every AI result for this run and start from nothing.
 *
 *  All three tasks together: the automated pass is one operation from the
 *  user's point of view, and resetting only the stage they happen to be looking
 *  at would leave the other two holding results from a run that no longer
 *  exists. */
app.post("/api/runs/:id/ai/reset", wrap(async (request, response) => {
    const cleared = [];
    for (const task of aijobs.TASKS) {
        await aijobs.stopBatch(request.params.id, task);
        await aijobs.resetTask(request.params.id, task);
        cleared.push(task);
    }
    // The Reports table counts lifted functions; leaving it stale would show a
    // count for results that have just been deleted.
    await store.patchMeta(request.params.id, await store.summarise(request.params.id));
    response.json({ ok: true, cleared });
}));

app.post("/api/runs/:id/ai/:task", wrap(async (request, response) => {
    const { id, task } = request.params;
    if (!checkTask(task, response)) return;

    // Selection runs even without n8n. Reporting "you would have queued 40
    // functions, here they are, none can run yet" is more useful than refusing —
    // it lets the whole flow be checked before the AI layer exists.
    const job = await aijobs.startBatch(
        id,
        task,
        {
            // null, not DEFAULT_LIMIT. An absent limit is the automated mode's
            // signal to derive scope from the engine's own triage score; forcing a
            // default here would have made "automated" mean "40, silently".
            limit: Number(request.body?.limit) > 0 ? Number(request.body.limit) : null,
            only: Array.isArray(request.body?.only) ? request.body.only : null,
        },
        dispatchAi,
    );

    if (!N8N_WEBHOOK_URL) {
        return response.json({
            ...job,
            state: "not-run",
            n8n_configured: false,
            message:
                `${job.total} function${job.total === 1 ? "" : "s"} selected by `
                + `information score, but n8n is not configured so none were sent. `
                + `Set N8N_WEBHOOK_URL in backend/.env.`,
        });
    }
    response.json({ ...job, n8n_configured: true });
}));

app.get("/api/runs/:id/ai/:task/:va", wrap(async (request, response) => {
    const { id, task } = request.params;
    if (!checkTask(task, response)) return;
    const va = normaliseVa(request.params.va);
    if (!va) return response.status(400).json({ error: "va must be hex" });

    const result = await aijobs.getResult(id, task, va);
    if (!result) return response.status(404).json({ error: `no ${task} result for ${va}` });
    response.json(result);
}));

app.post("/api/runs/:id/ai/:task/:va", wrap(async (request, response) => {
    const { id, task } = request.params;
    if (!checkTask(task, response)) return;
    const va = normaliseVa(request.params.va);
    if (!va) return response.status(400).json({ error: "va must be hex" });

    if (!N8N_WEBHOOK_URL) return n8nMissing(response);
    // Validates that the function exists before claiming the work was queued.
    await buildAiPayload(id, task, va);
    // Same as the lift route: one named function means redo it, and report the
    // state the job actually reached.
    const job = await aijobs.startBatch(
        id, task, { only: [va], force: true }, dispatchAi);
    response.json({ state: job.pending.length > 0 ? "queued" : job.state });
}));

/** n8n delivers one result here. */
app.post("/api/runs/:id/ai/:task/:va/result", wrap(async (request, response) => {
    const { id, task } = request.params;
    if (!checkTask(task, response)) return;
    const va = normaliseVa(request.params.va);
    if (!va) return response.status(400).json({ error: "va must be hex" });

    // Stamp bug results with the decompile version that was in the prompt. That
    // is what makes a finding reproducible: without it, a later re-lift leaves the
    // finding justified by text nobody can retrieve.
    const body = { ...(request.body || {}) };
    if (task === "bugs") {
        body.derived_from = await aijobs.currentVersionId(id, va);
    }
    if (task === "decompile") {
        body.coverage = await decompileCoverage(id, va, body);
    }

    const job = await aijobs.recordResult(id, task, va, body, dispatchAi);
    // Refresh the run summary so the Reports table's Lifted column keeps up. The
    // legacy /functions/:va/lifted callback already did this; results arriving via
    // the automated pass came through here instead and quietly did not, so a
    // finished run still showed "0 lifted".
    await store.patchMeta(id, await store.summarise(id));
    response.json({ ok: true, done: job.done, total: job.total });
}));

/* ======================================================================
 * Mitigations
 *
 * The engine half of this was reachable only from the command line, which in a
 * browser-based tool means it did not exist as far as anyone using it was
 * concerned. These three routes put it in the application.
 *
 * Note what is NOT here: nothing repairs the defective code. The engine has no
 * value-level dataflow, so it cannot know the size of a destination buffer, and
 * a rewrite that guesses one is unverifiable. Raising the loader mitigations is
 * a smaller claim that can be checked - by us, and independently by BinSkim.
 * ====================================================================== */

/** Where a hardened copy of a run's binary is written. */
const hardenedPath = (runId) => path.join(store.paths(runId).root, "hardened.exe");

/** Read-only: the mitigation state of the uploaded binary. */
app.get("/api/runs/:id/mitigations", wrap(async (request, response) => {
    const p = store.paths(request.params.id);
    if (!(await store.readJson(p.meta))) {
        return response.status(404).json({ error: "no such run" });
    }

    const result = await runner.runJsonCommand(["mitigations", p.input]);
    if (!result.ok) return response.status(503).json({ error: result.error });

    /* The CLI wraps the report: {schema_version, mitigations: {...}}. Flatten it
     * here so the frontend sees one shape whichever route it came from - `harden`
     * emits its before/after reports unwrapped, and two shapes for the same thing
     * is how a pane ends up rendering nothing at all. */
    const report = result.document?.mitigations ?? result.document ?? {};

    // Report whether a hardened copy already exists, so the UI can offer the
    // download without a second request.
    let hardened = null;
    try {
        const stats = await fsp.stat(hardenedPath(request.params.id));
        hardened = { available: true, size: stats.size, produced_at: stats.mtime.toISOString() };
    } catch {
        hardened = { available: false };
    }

    response.json({ ...report, hardened });
}));

/** Produce a hardened copy. Never touches the uploaded original. */
app.post("/api/runs/:id/harden", wrap(async (request, response) => {
    const runId = request.params.id;
    const p = store.paths(runId);
    if (!(await store.readJson(p.meta))) {
        return response.status(404).json({ error: "no such run" });
    }

    const args = ["harden", p.input, "--out", hardenedPath(runId)];
    // Editing a signed image invalidates its signature, so the engine refuses
    // unless told otherwise. The decision belongs to the person, not to us.
    if (request.body?.allow_signed === true) args.push("--allow-signed");
    // The one change that can break the program, so it is never implied.
    if (request.body?.fix_wx === true) args.push("--fix-wx");

    const result = await runner.runJsonCommand(args);
    if (!result.ok) return response.status(503).json({ error: result.error });

    // A refusal is a result, not a failure: "this image has no relocation data,
    // so ASLR cannot be enabled" is the useful answer and arrives as 200.
    response.json(result.document);
}));

/** Download the hardened copy. */
app.get("/api/runs/:id/hardened", wrap(async (request, response) => {
    const runId = request.params.id;
    const file = hardenedPath(runId);
    try {
        await fsp.access(file);
    } catch {
        return response.status(404).json({ error: "no hardened build for this run" });
    }
    const meta = await store.readJson(store.paths(runId).meta);
    const base = (meta?.file_name || "binary").replace(/\.[^.]*$/, "");
    response.download(file, `${base}.hardened.exe`);
}));

/* --- errors ----------------------------------------------------------- */

// eslint-disable-next-line no-unused-vars
app.use((error, _request, response, _next) => {
    const status = error.statusCode || (error.code === "LIMIT_FILE_SIZE" ? 413 : 500);
    if (status >= 500) console.error(error);
    response.status(status).json({ error: error.message || "internal error" });
});

/* --- start ------------------------------------------------------------ */

app.listen(PORT, async () => {
    const engine = await runner.probeEngine();
    console.log(`API listening on http://localhost:${PORT}/api`);
    console.log(`data      ${store.DATA_DIR}`);
    console.log(`engine    ${engine.path}${engine.ok ? "" : `  <-- ${engine.reason}`}`);
    if (!engine.ok) {
        console.log("");
        console.log("The engine was not found. Uploads will fail until SP_BINARY in");
        console.log("backend/.env points at the compiled sp.exe.");
    }
    console.log(`n8n       ${N8N_WEBHOOK_URL || "not configured (AI panes will show 'not-run')"}`);
    console.log(`callback  ${PUBLIC_BASE_URL}  (n8n posts results here)`);

    /* A remote n8n told to reply to "localhost" replies to itself. That failure
     * is silent — the forward succeeds, the model runs, and the result is
     * delivered to the wrong machine — so it is worth naming at startup rather
     * than leaving someone to discover it by watching a pane stay empty. */
    const remoteN8n = N8N_WEBHOOK_URL && !/^https?:\/\/(localhost|127\.0\.0\.1)\b/i.test(N8N_WEBHOOK_URL);
    const localCallback = /^https?:\/\/(localhost|127\.0\.0\.1)\b/i.test(PUBLIC_BASE_URL);
    if (remoteN8n && localCallback) {
        console.log("");
        console.log("WARNING: n8n is remote but the callback URL is localhost, which for");
        console.log("n8n means its own machine. Results will never arrive. Set");
        console.log("PUBLIC_BASE_URL in backend/.env to this machine's LAN address.");
    }
});
