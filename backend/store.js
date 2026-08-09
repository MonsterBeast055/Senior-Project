/*
 * store.js - Where runs live on disk, and what a run is.
 *
 * One directory per run. Everything about a run is a file inside it, so the
 * whole store is inspectable with a file browser and survives a restart of the
 * server. There is no database, deliberately: the engine's output *is* the data,
 * and copying it into a database would only create a second place for it to be
 * wrong.
 *
 *   data/runs/<run_id>/
 *     input.bin                 the uploaded file, byte-for-byte
 *     meta.json                 file name, size, sha256, timestamps, stage
 *     analysis/                 exactly what `sp.exe export --out` wrote
 *       image.json
 *       functions.json
 *       findings.json
 *       callgraph.json
 *       manifest.json
 *       functions/func_<va>.json
 *     engine.log                the engine's stderr, kept for diagnosis
 *     context.json              human-supplied facts (optional)
 *     lifted/<va>.json          n8n results (optional, arrives later)
 *     explanations/<key>.json   n8n finding explanations (optional)
 *
 * The uploaded binary is never executed. It is opened for reading by the engine
 * and by the hash function, and nothing else.
 */
const crypto = require("crypto");
const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");

const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, "data"));
const RUNS_DIR = path.join(DATA_DIR, "runs");
const UPLOAD_TMP = path.join(DATA_DIR, "tmp");

function ensureDirs() {
    for (const dir of [DATA_DIR, RUNS_DIR, UPLOAD_TMP]) {
        fs.mkdirSync(dir, { recursive: true });
    }
}

/* A run id must be safe to paste into a filesystem path without further
 * thought, because it arrives from the network and is used to build one. Random
 * hex plus a date prefix: sortable by eye, and unguessable enough that one user
 * cannot enumerate another's uploads. */
function newRunId() {
    const now = new Date();
    const stamp = now.toISOString().slice(0, 19).replace(/[-:T]/g, "");
    return `${stamp}-${crypto.randomBytes(4).toString("hex")}`;
}

/* The only guard against path traversal in this file, and the reason every
 * public function funnels through it. `../../etc/passwd` as a run id must not
 * escape RUNS_DIR. */
const SAFE_ID = /^[A-Za-z0-9._-]{1,80}$/;

function runDir(runId) {
    if (!SAFE_ID.test(runId)) {
        const error = new Error(`invalid run id: ${runId}`);
        error.statusCode = 400;
        throw error;
    }
    return path.join(RUNS_DIR, runId);
}

function paths(runId) {
    const root = runDir(runId);
    return {
        root,
        input: path.join(root, "input.bin"),
        meta: path.join(root, "meta.json"),
        analysis: path.join(root, "analysis"),
        functions: path.join(root, "analysis", "functions"),
        log: path.join(root, "engine.log"),
        context: path.join(root, "context.json"),
        lifted: path.join(root, "lifted"),
        explanations: path.join(root, "explanations"),
    };
}

async function readJson(file, fallback = null) {
    try {
        return JSON.parse(await fsp.readFile(file, "utf8"));
    } catch (cause) {
        if (cause.code === "ENOENT") return fallback;
        // A truncated or corrupt file is worth distinguishing from a missing
        // one: the first means a crashed write, the second means "not yet".
        if (cause instanceof SyntaxError) {
            const error = new Error(`corrupt JSON in ${path.basename(file)}`);
            error.statusCode = 500;
            throw error;
        }
        throw cause;
    }
}

/* Per-file write queue.
 *
 * Two problems, both observed rather than imagined. The engine's stderr arrives
 * in bursts, so several meta patches can be in flight at once:
 *
 *   1. Two writes sharing a temp file name race — the first rename consumes it
 *      and the second gets ENOENT. That crashed the server, because the callers
 *      are fire-and-forget.
 *   2. Even with unique temp names, two read-modify-write cycles interleave and
 *      the later write silently drops the earlier one's fields.
 *
 * Chaining writes per file fixes both: the temp name is unique, and only one
 * read-modify-write for a given file runs at a time.
 */
const writeQueues = new Map();
let writeCounter = 0;

function enqueue(file, work) {
    const previous = writeQueues.get(file) || Promise.resolve();
    // `.then(work, work)` runs the next job whether the previous one resolved or
    // rejected, so one failed write does not stall every later write to the same
    // file.
    const next = previous.then(work, work);
    // The stored tail must never reject, or an unhandled rejection escapes.
    const tail = next.catch(() => {});
    writeQueues.set(file, tail);
    // Release the map entry when this job is the last one, so a long-lived server
    // does not accumulate one promise per file forever.
    void tail.then(() => {
        if (writeQueues.get(file) === tail) writeQueues.delete(file);
    });
    return next;
}

/* The actual write, assumed already serialised by its caller. */
async function writeJsonUnlocked(file, value) {
    await fsp.mkdir(path.dirname(file), { recursive: true });
    // Write-then-rename, so a reader never sees a half-written document. The
    // status endpoint is polled roughly once a second while the engine runs, so a
    // torn read is not theoretical.
    const temporary = `${file}.tmp-${process.pid}-${++writeCounter}`;
    try {
        await fsp.writeFile(temporary, JSON.stringify(value, null, 2));
        await fsp.rename(temporary, file);
    } catch (cause) {
        await fsp.rm(temporary, { force: true });
        throw cause;
    }
}

async function writeJson(file, value) {
    return enqueue(file, () => writeJsonUnlocked(file, value));
}

/** Read-modify-write as one queued unit. The read has to be inside the queue:
 *  doing it outside is what lets two patches each start from the same old
 *  document and the second one drop the first one's fields. */
async function patchJson(file, patch) {
    return enqueue(file, async () => {
        const current = (await readJson(file)) || {};
        const merged = { ...current, ...patch, updated_at: new Date().toISOString() };
        await writeJsonUnlocked(file, merged);
        return merged;
    });
}

async function sha256OfFile(file) {
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash("sha256");
        const stream = fs.createReadStream(file);
        stream.on("error", reject);
        stream.on("data", (chunk) => hash.update(chunk));
        stream.on("end", () => resolve(hash.digest("hex")));
    });
}

async function readMeta(runId) {
    return readJson(paths(runId).meta);
}

async function writeMeta(runId, meta) {
    await writeJson(paths(runId).meta, meta);
    return meta;
}

/** Merge and persist. Serialised per run by patchJson, because progress patches
 *  arrive in bursts as the engine's stderr does. */
async function patchMeta(runId, patch) {
    return patchJson(paths(runId).meta, patch);
}

async function listRuns() {
    ensureDirs();
    let entries;
    try {
        entries = await fsp.readdir(RUNS_DIR, { withFileTypes: true });
    } catch (cause) {
        if (cause.code === "ENOENT") return [];
        throw cause;
    }

    const runs = [];
    for (const entry of entries) {
        if (!entry.isDirectory() || !SAFE_ID.test(entry.name)) continue;
        const meta = await readMeta(entry.name);
        if (meta) runs.push(meta);
    }
    // Newest first: the run someone just made is the one they want.
    runs.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
    return runs;
}

async function deleteRun(runId) {
    await fsp.rm(runDir(runId), { recursive: true, force: true });
}

/* Summary fields shown in the Reports table. Derived from the engine's own
 * output rather than recomputed here — if these numbers disagreed with the
 * analysis view, the table would be actively misleading. */
async function summarise(runId) {
    const p = paths(runId);
    const image = await readJson(path.join(p.analysis, "image.json"));
    const findings = await readJson(path.join(p.analysis, "findings.json"));
    const functions = await readJson(path.join(p.analysis, "functions.json"));

    // Lifting and the automated decompile pass share one store now, so this
    // counts that one. The old `lifted/` directory is still added for runs made
    // before the merge, which would otherwise appear to have lost their results.
    let liftedCount = 0;
    for (const dir of [path.join(p.root, "ai", "decompile"), p.lifted]) {
        try {
            liftedCount += (await fsp.readdir(dir)).filter((f) => f.endsWith(".json")).length;
        } catch { /* directory absent; contributes zero */ }
    }

    return {
        arch: image?.arch ?? null,
        image_base: image?.image_base ?? null,
        function_count: image?.coverage?.function_count ?? functions?.functions?.length ?? null,
        code_fraction: image?.coverage?.code_fraction ?? null,
        instruction_count: image?.coverage?.instruction_count ?? null,
        risky_operations: findings?.summary?.risky_operations ?? null,
        impactful_findings: findings?.summary?.impactful ?? null,
        lifted_count: liftedCount,
    };
}

module.exports = {
    DATA_DIR, RUNS_DIR, UPLOAD_TMP,
    ensureDirs, newRunId, paths, runDir,
    readJson, writeJson, patchJson, sha256OfFile,
    readMeta, writeMeta, patchMeta,
    listRuns, deleteRun, summarise,
};
