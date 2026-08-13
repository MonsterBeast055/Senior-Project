/*
 * runner.js - Spawn the C++ engine and turn its stderr into progress.
 *
 * The engine already narrates what it is doing. Every analysis pass calls
 * core::log_info, and the default sink writes "[info] <message>" to stderr. So
 * real-time progress needs no new engine feature and no IPC: read stderr line by
 * line and map the messages the engine already emits onto the stages the UI
 * already knows about.
 *
 * This is why the mapping below quotes literal engine strings. It is a coupling,
 * and an honest one — if someone rewords a log message the progress bar loses a
 * step and nothing else breaks. The alternative (a structured progress channel)
 * would be more robust and would require changing the engine, the CLI, and this
 * file to add one stage. Not worth it yet.
 *
 * Nothing here executes the uploaded file. `sp.exe` is the only program spawned,
 * and the binary is passed to it as a path argument to be read.
 */
const { spawn } = require("child_process");
const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");

const store = require("./store");

/* Fire-and-forget progress updates.
 *
 * These happen while an HTTP request that started the run has already been
 * answered, so there is nobody to return an error to. An unhandled rejection
 * here would take the whole server down with it — which is exactly what a
 * temp-file race did during testing. Log and carry on: a run whose progress
 * stopped updating is far better than an API that stopped answering.
 */
function patch(runId, fields) {
    store.patchMeta(runId, fields).catch((cause) => {
        console.error(`[run ${runId}] could not record progress: ${cause.message}`);
    });
}

/* Ordered, because the UI draws them as a checklist and percent is derived from
 * the index. Keys match RunStage in frontend-react/src/api/types.ts exactly; a
 * typo here shows up as a step that never lights. */
const STAGES = [
    "uploaded",
    "loading",
    "disassembling",
    "discovering",
    "building-cfgs",
    "extracting-strings",
    "analysing-reachability",
    "exporting",
];

/* Longest-running passes get the widest bands, so the bar moves at a roughly
 * even rate instead of sitting at 30% for most of the run. */
const STAGE_PERCENT = {
    uploaded: 5,
    loading: 12,
    disassembling: 45,
    discovering: 58,
    "building-cfgs": 74,
    "extracting-strings": 82,
    "analysing-reachability": 90,
    exporting: 96,
    done: 100,
};

/** Recognise a stage from one line of engine output.
 *
 *  Order matters: "built N functions" and "found N function candidates" both
 *  contain "function", so the more specific test has to come first. */
function stageFromLine(line) {
    if (line.includes("loaded ") && line.includes("arch=")) return "loading";
    if (line.includes("disassembled ")) return "disassembling";
    if (line.includes("function candidates")) return "discovering";
    if (line.includes("built ") && line.includes(" functions,")) return "building-cfgs";
    if (line.includes("extracted ") && line.includes("strings")) return "extracting-strings";
    if (line.startsWith("reachability:") || line.includes("reachability:")) {
        return "analysing-reachability";
    }
    if (line.includes("analysis complete")) return "exporting";
    return null;
}

/* Strip the "[info] " prefix for display. The level is kept separately because a
 * warning is worth surfacing and an info line is just narration. */
function parseLogLine(raw) {
    const match = /^\[(trace|debug|info|warn|error)\]\s*(.*)$/i.exec(raw.trim());
    if (!match) return { level: "info", message: raw.trim() };
    return { level: match[1].toLowerCase(), message: match[2] };
}

/* A line worth showing the user under the progress bar. The engine's summaries
 * are genuinely informative — "disassembled 38202 instructions (descent=... )"
 * tells you more than any spinner — so they are passed through verbatim. */
function isInteresting(message) {
    return message.length > 0 && message.length < 300;
}

function enginePath() {
    const configured = process.env.SP_BINARY;
    if (configured && configured.trim().length > 0) return configured.trim();
    return process.platform === "win32" ? "sp.exe" : "sp";
}

/**
 * Analyse one stored run. Returns immediately; progress is written into
 * meta.json as it happens, and the status endpoint reads it from there.
 *
 * Errors are recorded on the run rather than thrown, because the HTTP request
 * that started this has already been answered. A run that fails is a run in
 * stage "failed" with an `error` field — never a crashed server.
 */
function startAnalysis(runId, { noSweep = false, keepThunks = false } = {}) {
    const p = store.paths(runId);
    const binary = enginePath();

    const args = ["export", p.input, "--out", p.analysis];
    if (noSweep) args.push("--no-sweep");
    if (keepThunks) args.push("--keep-thunks");

    const logStream = fs.createWriteStream(p.log, { flags: "a" });
    logStream.write(`\n=== ${new Date().toISOString()} ${binary} ${args.join(" ")}\n`);

    let child;
    try {
        child = spawn(binary, args, {
            // The engine writes only to the --out directory and stderr.
            cwd: p.root,
            windowsHide: true,
        });
    } catch (cause) {
        patch(runId, {
            stage: "failed",
            percent: 0,
            error: `could not start the engine (${binary}): ${cause.message}`,
        });
        logStream.end();
        return;
    }

    // Set by the 'error' handler so 'close' knows not to overwrite its message.
    //
    // A failed spawn fires BOTH events: 'error' with a useful ENOENT, then 'close'
    // with an exit code of -2. Without this flag the close handler wins and the
    // user is told "the engine exited with code -2", which names the symptom
    // instead of the cause. Observed, not hypothetical.
    let startupFailed = false;

    // ENOENT arrives as an event, not a throw, so the same failure needs
    // handling twice. Getting this wrong is how "nothing happens" bugs are made.
    child.on("error", (cause) => {
        startupFailed = true;
        patch(runId, {
            stage: "failed",
            percent: 0,
            error:
                cause.code === "ENOENT"
                    ? `the engine was not found at "${binary}". Set SP_BINARY in ` +
                      `backend/.env to the full path of sp.exe, then restart the API.`
                    : `the engine failed to start: ${cause.message}`,
        });
        logStream.end();
    });

    patch(runId, { stage: "loading", percent: STAGE_PERCENT.loading, error: null });

    let stageIndex = STAGES.indexOf("loading");
    let pending = "";
    let lastWarning = null;

    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => {
        logStream.write(chunk);
        pending += chunk;

        // Hold the trailing partial line: chunk boundaries fall mid-message and
        // a half-line would never match any stage pattern.
        const lines = pending.split(/\r?\n/);
        pending = lines.pop() ?? "";

        for (const raw of lines) {
            if (raw.trim().length === 0) continue;
            const { level, message } = parseLogLine(raw);

            if (level === "warn" || level === "error") lastWarning = message;

            const stage = stageFromLine(message);
            const next = stage ? STAGES.indexOf(stage) : -1;

            // Never move backwards. Passes can log out of order (a warning from
            // the loader can arrive after disassembly starts), and a progress bar
            // that jumps back reads as a bug even when the analysis is fine.
            if (next > stageIndex) {
                stageIndex = next;
                patch(runId, {
                    stage: STAGES[stageIndex],
                    percent: STAGE_PERCENT[STAGES[stageIndex]] ?? 50,
                    message: isInteresting(message) ? message : undefined,
                });
            } else if (isInteresting(message)) {
                patch(runId, { message });
            }
        }
    });

    // stdout carries the "exported N functions" line from run_export.
    let stdout = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; logStream.write(chunk); });

    child.on("close", async (code) => {
        logStream.end();
        // The 'error' handler already recorded a better diagnosis. Anything this
        // handler writes now would replace a cause with a symptom.
        if (startupFailed) return;
        try {
            if (code !== 0) {
                await store.patchMeta(runId, {
                    stage: "failed",
                    percent: 0,
                    error:
                        `the engine exited with code ${code}. ` +
                        (lastWarning
                            ? `Last message: ${lastWarning}`
                            : `See GET /api/runs/${runId}/log for its output.`),
                });
                return;
            }

            // Exit code 0 is not proof of a usable result. The frontend loads
            // image.json first, so if that file is missing the run is broken
            // regardless of what the engine claimed.
            const image = await store.readJson(path.join(p.analysis, "image.json"));
            if (!image) {
                await store.patchMeta(runId, {
                    stage: "failed",
                    percent: 0,
                    error: "the engine finished but wrote no image.json",
                });
                return;
            }

            const summary = await store.summarise(runId);
            await store.patchMeta(runId, {
                ...summary,
                stage: "done",
                percent: 100,
                error: null,
                message: stdout.trim() || "analysis complete",
                finished_at: new Date().toISOString(),
            });
        } catch (cause) {
            await store.patchMeta(runId, {
                stage: "failed",
                percent: 0,
                error: `post-processing failed: ${cause.message}`,
            });
        }
    });
}

/** Is the engine actually where we think it is? Checked once at startup so the
 *  operator finds out then, rather than after their first upload fails. */
async function probeEngine() {
    const binary = enginePath();
    // A bare command name is resolved through PATH by spawn, so only an explicit
    // path can be checked on the filesystem.
    if (binary.includes("/") || binary.includes("\\")) {
        try {
            await fsp.access(binary, fs.constants.X_OK);
            return { ok: true, path: binary };
        } catch {
            return { ok: false, path: binary, reason: "not found or not executable" };
        }
    }
    return { ok: true, path: binary, reason: "resolved through PATH at run time" };
}

/**
 * Run one engine command that prints a JSON document and exits.
 *
 * `mitigations` and `harden` are not analyses: they read and write header bytes
 * and produce a single document, with no stages to report and no long-running
 * child to supervise. startAnalysis exists to stream progress out of a process
 * that runs for seconds; forcing these through it would mean inventing progress
 * for work that has none.
 *
 * A non-zero exit is not automatically an error here. `harden` exits 1 when it
 * refuses - a signed image, or one that cannot be rebased - and the refusal IS
 * the answer, printed as JSON on stdout. So the document is parsed first and the
 * exit code consulted only when there is nothing to read.
 */
function runJsonCommand(args, { timeoutMs = 120_000 } = {}) {
    return new Promise((resolve) => {
        const binary = enginePath();
        let child;
        try {
            child = spawn(binary, args, { windowsHide: true });
        } catch (cause) {
            resolve({ ok: false, error: `cannot start ${binary}: ${cause.message}` });
            return;
        }

        let out = "";
        let err = "";
        let settled = false;

        const timer = setTimeout(() => {
            if (settled) return;
            settled = true;
            child.kill();
            resolve({ ok: false, error: `${args[0]} timed out` });
        }, timeoutMs);

        child.stdout.on("data", (chunk) => { out += chunk; });
        child.stderr.on("data", (chunk) => { err += chunk; });

        child.on("error", (cause) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            resolve({
                ok: false,
                error: cause.code === "ENOENT"
                    ? `engine not found at ${binary}. Check SP_BINARY in backend/.env, `
                      + `and that the engine has been rebuilt since the ${args[0]} `
                      + `command was added.`
                    : cause.message,
            });
        });

        child.on("close", (code) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            try {
                resolve({ ok: true, document: JSON.parse(out), exit_code: code });
            } catch {
                resolve({
                    ok: false,
                    error: err.trim() || out.trim() || `${args[0]} exited ${code} with no output`,
                    exit_code: code,
                });
            }
        });
    });
}

module.exports = {
    startAnalysis, probeEngine, enginePath, runJsonCommand, STAGES, STAGE_PERCENT,
};
