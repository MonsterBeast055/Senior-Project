/*
 * aijobs.js - Batch AI work: pick the functions, queue them, track progress.
 *
 * Three tasks, all following the same shape:
 *
 *   decompile   logic lifting - readable C for one function
 *   bugs        defect hunting, grounded in the engine's findings
 *   behaviour   capability profile: persistence, injection, anti-debug, C2, ...
 *
 * Two things make this worth having as its own module rather than three more
 * routes in server.js.
 *
 * First, selection. "Analyse this binary" cannot mean "all 452 functions": most
 * are CRT helpers, and a model call on each is money spent to be told a function
 * adjusts the stack. The engine already computes information_score for exactly
 * this decision, so the queue is score-ordered and capped. That is the cost lever
 * the score was built for, finally being pulled.
 *
 * Second, a queue is not the same as a loop. Results arrive asynchronously from
 * n8n, minutes after dispatch. Progress has to survive a page reload, so it lives
 * on disk with the run rather than in memory.
 *
 * While N8N_WEBHOOK_URL is unset, a batch still enqueues and reports honestly -
 * every item sits in "not-run". The UI shows real counts instead of pretending
 * nothing was asked.
 */
const path = require("path");

const store = require("./store");

const TASKS = ["decompile", "bugs", "behaviour"];

/* Concurrency towards n8n. Above a handful, a model provider starts rate-limiting
 * and the failures look like our bug rather than their throttle. */
const DISPATCH_WINDOW = 4;

/* Default ceiling when the caller names one. Manual mode does; automated mode
 * does not, and asking a user "how many functions?" is exactly the decision
 * "automated" is supposed to make for them. */
const DEFAULT_LIMIT = 40;

/* The threshold the engine itself uses to mean "worth a human's attention", and
 * the same one the symbol tree draws its "Worth review" folder from. Automated
 * scope is defined by this rather than by a count, so it adapts to the binary:
 * a small utility might yield 12 functions and a browser 400. */
const WORTH_REVIEW_SCORE = 20;

/* Hard ceiling on an automatic run. Not a tuning knob - a safety rail.
 * kernel32.dll has 1693 exports, and an unbounded automated pass over it would
 * be thousands of model calls started by one click. If a binary exceeds this,
 * the highest-scoring functions win and the job says how many were left out. */
const MAX_AUTOMATIC = 200;

function jobFile(runId, task) {
    return path.join(store.paths(runId).root, `aijob-${task}.json`);
}

/** Result file for one function and task. Kept separate from the job so a
 *  completed result survives re-running the batch. */
function resultFile(runId, task, va) {
    return path.join(store.paths(runId).root, "ai", task, `${va}.json`);
}

/**
 * Which functions to spend model calls on, best first.
 *
 * Filters before it sorts, because the filters encode "there is nothing here to
 * explain" and no amount of score should override that. Thunks are one jump.
 * Library code is MSVC's, already documented, and identical across every binary
 * you will ever analyse.
 */
async function selectFunctions(runId, task, { limit = null, only = null } = {}) {
    const p = store.paths(runId);
    const document = await store.readJson(path.join(p.analysis, "functions.json"));
    const all = document?.functions ?? [];

    // An explicit list wins over selection entirely - that is the per-function
    // path, and second-guessing a direct request would be wrong.
    if (Array.isArray(only) && only.length > 0) {
        const wanted = new Set(only);
        return all.filter((f) => wanted.has(f.va));
    }

    let candidates = all.filter((f) => !f.is_thunk && !f.is_imported_stub && !f.is_library_code);

    /* No limit means automated: derive the scope instead of asking for a number.
     *
     * "Automated" that opens with "how many functions?" has not automated the
     * decision, only moved it. The engine already answers this: information_score
     * is exactly a judgement about whether a function is worth explaining, and 20
     * is the same threshold the symbol tree uses for "Worth review". Using it here
     * means scope follows the binary - a small utility yields a dozen functions, a
     * browser yields hundreds - rather than a number someone guessed.
     *
     * MAX_AUTOMATIC is a rail, not a preference: one click should not be able to
     * start four thousand model calls on kernel32. */
    const automatic = limit === null;
    if (automatic) {
        const worthwhile = candidates.filter(
            (f) => (f.information_score ?? 0) >= WORTH_REVIEW_SCORE,
        );
        // If nothing clears the bar - heavily stripped or tiny binaries - fall
        // back to the best of what there is rather than analysing nothing.
        candidates = worthwhile.length > 0 ? worthwhile : candidates;
        limit = MAX_AUTOMATIC;
    }

    /* Decompilation is ordered bottom-up, not by score.
     *
     * This is the answer to a problem that has no good solution otherwise. A
     * function cannot be understood alone - `sub_A` calls `sub_B`, and without
     * knowing what B does, a model guesses. But the whole binary cannot go in one
     * prompt either: 1300 functions is roughly a million tokens, attention
     * degrades badly over that span, and you pay for all of it every time.
     *
     * The resolution is to process leaves first and use *summaries* as the
     * interface between levels. When a caller's turn comes, its callees have
     * already been summarised, so the prompt carries one paragraph per callee
     * instead of a thousand tokens of their disassembly. The model never sees more
     * than one function's code at a time, yet always knows what its callees do.
     *
     * Nothing has to be remembered across calls: the summaries live on disk, and
     * each request is stateless. That is more reliable than a long conversation,
     * not less - there is no context to drift.
     *
     * The engine already computes this order (reverse topological, via Tarjan SCC
     * so recursion condenses into one unit). It has been emitted in
     * callgraph.json and consumed by nothing until now. */
    if (task === "decompile") {
        const callgraph = await store.readJson(path.join(p.analysis, "callgraph.json"));
        const order = callgraph?.processing_order ?? [];
        if (order.length > 0) {
            const rank = new Map(order.map((va, index) => [va, index]));
            const byVa = new Map(candidates.map((f) => [f.va, f]));

            // Walk the engine's order and keep the candidates, so leaves come
            // first. Anything the order does not mention (unreachable in the call
            // graph) is appended by score - better than dropping it.
            const ordered = [];
            for (const va of order) {
                const fn = byVa.get(va);
                if (fn) { ordered.push(fn); byVa.delete(va); }
            }
            const leftover = [...byVa.values()]
                .sort((a, b) => (b.information_score ?? 0) - (a.information_score ?? 0));

            // Score still decides *which* functions are worth paying for; the
            // topological order decides the sequence among those. Taking the first
            // N of a pure bottom-up order would spend the whole budget on leaf
            // helpers and never reach anything interesting.
            const worthwhile = new Set(
                [...ordered, ...leftover]
                    .slice()
                    .sort((a, b) => (b.information_score ?? 0) - (a.information_score ?? 0))
                    .slice(0, limit)
                    .map((f) => f.va),
            );
            void rank;
            return [...ordered, ...leftover].filter((f) => worthwhile.has(f.va));
        }
    }

    /* Bug hunting selects by reachability, not by score.
     *
     * This is the important distinction in the whole file, and the earlier version
     * of it was wrong. information_score measures "does this function have a
     * recognisable purpose" - it is computed from imported API calls and
     * referenced strings. That is the right question for "explain what this does".
     * It is the wrong question for "could this contain a bug".
     *
     * Bugs live in plumbing. Consider:
     *
     *     sub_A   calls ReadFile, uses "config.txt"     score 45
     *       └─ sub_B   copies bytes in a loop           score 10   <- the defect
     *            └─ sub_C   calls lstrcpyW              score 25
     *
     * sub_B has no API calls and no strings, so it scores 10 and a score-ranked
     * selection drops it - while being exactly the function with the missing
     * length check. Sorting by score with reachability as a tiebreak, which is
     * what this used to do, still loses sub_B whenever the budget runs out.
     *
     * So: take the union of every finding's call_path. Those are the functions
     * attacker-controlled data actually flows through, whatever they score. Then
     * add each path function's direct callees, because a bounds check is often one
     * level deeper than the path itself.
     *
     * The result is usually a small fraction of the binary - but it is the
     * fraction that matters, which is a better trade than sending everything.
     */
    if (task === "bugs") {
        const findings = await store.readJson(path.join(p.analysis, "findings.json"));
        const all_findings = findings?.findings ?? [];

        const onPath = new Set();
        const sinks = new Set();
        for (const finding of all_findings) {
            sinks.add(finding.function);
            onPath.add(finding.function);
            for (const step of finding.call_path ?? []) onPath.add(step.va);
        }

        if (onPath.size > 0) {
            // One level deeper. Reads the per-function documents, which are local
            // files - on notepad.exe this is a few dozen small reads.
            const neighbours = new Set();
            for (const va of onPath) {
                const detail = await store.readJson(
                    path.join(p.functions, `func_${String(va).slice(2)}.json`),
                );
                for (const callee of detail?.callees ?? []) neighbours.add(callee.va);
            }

            const byVa = new Map(all.map((f) => [f.va, f]));
            const selected = [];
            const seen = new Set();
            // Sinks first, then the rest of the paths, then the neighbours: if the
            // ceiling truncates, it should truncate the least relevant end.
            for (const group of [sinks, onPath, neighbours]) {
                for (const va of group) {
                    if (seen.has(va)) continue;
                    const fn = byVa.get(va);
                    // Library code stays excluded even on a path. A bug inside the
                    // CRT is Microsoft's, not this program's, and reporting it
                    // would bury the findings that are actionable.
                    if (!fn || fn.is_thunk || fn.is_imported_stub || fn.is_library_code) {
                        continue;
                    }
                    seen.add(va);
                    selected.push(fn);
                }
            }
            return selected.slice(0, limit);
        }
        // No findings at all: nothing is known to be reachable, so fall through to
        // the score-ranked selection below rather than analysing nothing.
    }

    candidates.sort((a, b) => (b.information_score ?? 0) - (a.information_score ?? 0));
    return candidates.slice(0, limit);
}

function emptyJob(task) {
    return {
        task,
        state: "not-started",
        total: 0,
        done: 0,
        failed: 0,
        pending: [],
        items: {},
        message: null,
    };
}

/** Read a job, or a well-formed empty one.
 *
 *  The shape is validated, not just checked for null. A file that exists but has
 *  no `items` map is worse than a missing one: every caller does `job.items[va]`,
 *  so a malformed job turns into a TypeError deep inside a callback route. That
 *  happened — a stray patch wrote `{updated_at}` and nothing else. */
async function getJob(runId, task) {
    const existing = await store.readJson(jobFile(runId, task));
    if (existing && existing.items && typeof existing.items === "object") {
        return { ...emptyJob(task), ...existing };
    }
    return emptyJob(task);
}

/**
 * Start (or restart) a batch.
 *
 * Functions that already have a result are counted as done rather than
 * re-dispatched. Re-running a batch after adding a few functions should not pay
 * for the ones already explained.
 */
async function startBatch(runId, task, options, dispatch) {
    if (!TASKS.includes(task)) {
        const error = new Error(`unknown AI task: ${task}`);
        error.statusCode = 400;
        throw error;
    }

    const selected = await selectFunctions(runId, task, options);
    if (selected.length === 0) {
        return {
            task,
            state: "empty",
            total: 0, done: 0, failed: 0, pending: [], items: {},
            message:
                "Nothing was selected. Every function is a thunk, an import stub, or "
                + "library code — there is nothing here worth a model call.",
        };
    }

    const items = {};
    const pending = [];
    let done = 0;

    for (const fn of selected) {
        const existing = await store.readJson(resultFile(runId, task, fn.va));
        if (existing) {
            items[fn.va] = { state: "done", name: fn.name, score: fn.information_score ?? 0 };
            done++;
        } else {
            items[fn.va] = { state: "queued", name: fn.name, score: fn.information_score ?? 0 };
            pending.push(fn.va);
        }
    }

    const job = {
        task,
        state: pending.length === 0 ? "done" : "running",
        total: selected.length,
        done,
        failed: 0,
        pending,
        items,
        started_at: new Date().toISOString(),
        message:
            pending.length === 0
                ? "Every selected function already had a result."
                : `${pending.length} queued, ${done} already done.`,
    };

    await store.writeJson(jobFile(runId, task), job);
    if (pending.length > 0) void pump(runId, task, dispatch);
    return job;
}

/**
 * Dispatch up to DISPATCH_WINDOW pending items.
 *
 * Called after starting a batch and again whenever a result lands, so the window
 * stays full without a timer. `dispatch` is injected rather than imported to keep
 * this module free of any knowledge of n8n or HTTP.
 */
async function pump(runId, task, dispatch) {
    const job = await getJob(runId, task);
    if (job.state !== "running") return;

    const inFlight = Object.values(job.items).filter((i) => i.state === "sent").length;
    const room = DISPATCH_WINDOW - inFlight;
    if (room <= 0) return;

    const going = job.pending.slice(0, room);
    if (going.length === 0) return;

    // Mark before dispatching. If the process dies between the two, an item stuck
    // in "sent" is recoverable by re-running the batch; an item still "queued"
    // that was in fact dispatched would be paid for twice.
    for (const va of going) {
        if (job.items[va]) job.items[va].state = "sent";
    }
    job.pending = job.pending.slice(going.length);
    await store.writeJson(jobFile(runId, task), job);

    for (const va of going) {
        try {
            await dispatch(runId, task, va);
        } catch (cause) {
            await recordFailure(runId, task, va, cause.message, dispatch);
        }
    }
}

/** A short, stable id for one version of one result. Used by findings to record
 *  exactly which text they were derived from. */
function versionId(origin, at) {
    return `${origin}@${at}`;
}

/**
 * Store a result and advance the queue. Called from the n8n callback routes.
 *
 * Results are versioned rather than overwritten, and this matters more than it
 * looks. A decompile summary is not only displayed - it is fed back into later
 * prompts as callee context, and bug hunting reads it for every step of a call
 * path. So a finding on record was justified by a specific piece of text.
 *
 * If a user presses `Lift with AI` on a function the automated pass already did,
 * they should see their new result - but silently replacing the old one would
 * leave every finding derived from it pointing at text that no longer exists
 * anywhere. Nobody could reproduce how the conclusion was reached, which for a
 * tool whose whole claim is "every conclusion shows its evidence" is the wrong
 * failure.
 *
 * So: newest becomes `current`, the previous one moves to `history`, and each
 * carries its origin. `origin` defaults to "automated" because that is where
 * batch callbacks come from; the manual route passes "manual" explicitly.
 */
async function recordResult(runId, task, va, payload, dispatch, origin = "automated") {
    const file = resultFile(runId, task, va);
    const previous = await store.readJson(file);
    const at = new Date().toISOString();

    const version = {
        ...payload,
        task,
        va,
        origin,
        version_id: versionId(origin, at),
        // The engine owns severity. An AI result may describe and explain a
        // finding's rating but must never be the source of it, so this is
        // overwritten rather than defaulted - the same rule the explanation
        // route enforces.
        severity_source: "engine",
        received_at: at,
    };

    // Keep the previous versions, newest first, capped. A function re-lifted
    // twenty times does not need twenty copies on disk, but the one it replaced
    // is exactly what a stale finding needs to point at.
    const history = [];
    if (previous) {
        const { history: oldHistory, ...priorVersion } = previous;
        history.push(priorVersion);
        for (const entry of oldHistory ?? []) history.push(entry);
    }

    await store.writeJson(file, { ...version, history: history.slice(0, 5) });

    const job = await getJob(runId, task);

    // A result can arrive for a function no job is tracking: n8n delivering after
    // a server restart, or a webhook retried long after the batch finished. The
    // result is already stored above, which is the part that matters, so record an
    // item for it rather than dropping the accounting on the floor.
    if (!job.items[va]) {
        job.items[va] = { state: "done", name: va, score: 0, unsolicited: true };
        job.total = Math.max(job.total, Object.keys(job.items).length);
    }
    job.items[va].state = "done";
    job.done = Object.values(job.items).filter((i) => i.state === "done").length;
    job.failed = Object.values(job.items).filter((i) => i.state === "failed").length;
    if (job.pending.length === 0
        && !Object.values(job.items).some((i) => i.state === "sent")) {
        job.state = "done";
        job.finished_at = new Date().toISOString();
        job.message = `${job.done} of ${job.total} complete`
                    + (job.failed ? `, ${job.failed} failed` : "");
    }
    await store.writeJson(jobFile(runId, task), job);

    if (job.state === "running") void pump(runId, task, dispatch);
    return job;
}

async function recordFailure(runId, task, va, message, dispatch) {
    const job = await getJob(runId, task);
    if (job.items[va]) {
        job.items[va].state = "failed";
        job.items[va].error = message;
    }
    job.failed = Object.values(job.items).filter((i) => i.state === "failed").length;
    if (job.pending.length === 0
        && !Object.values(job.items).some((i) => i.state === "sent")) {
        job.state = "done";
        job.message = `${job.done} of ${job.total} complete, ${job.failed} failed`;
    }
    await store.writeJson(jobFile(runId, task), job);
    if (job.state === "running") void pump(runId, task, dispatch);
}

/** One function's current result, or null. History travels with it. */
async function getResult(runId, task, va) {
    return store.readJson(resultFile(runId, task, va));
}

/** The version id of the decompile result a prompt would use right now.
 *
 *  Recorded on every bug result so a finding can say which text it was reasoned
 *  from, and so the UI can tell when that text has since been replaced. */
async function currentVersionId(runId, va) {
    const result = await store.readJson(resultFile(runId, "decompile", va));
    return result?.version_id ?? null;
}

/** True when a bug result was derived from a decompile version that is no longer
 *  current — i.e. someone re-lifted the function after the bug pass ran. */
async function isStale(runId, va, derivedFrom) {
    if (!derivedFrom) return false;
    const current = await currentVersionId(runId, va);
    // No decompile result at all means nothing has superseded it.
    return current !== null && current !== derivedFrom;
}

module.exports = {
    TASKS, DEFAULT_LIMIT, DISPATCH_WINDOW,
    selectFunctions, startBatch, getJob, emptyJob, getResult,
    recordResult, recordFailure, currentVersionId, isStale, versionId,
};
