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
const fs = require("fs/promises");
const path = require("path");

const store = require("./store");

const TASKS = ["decompile", "bugs", "behaviour"];

/* Concurrency towards n8n. Above a handful, a model provider starts rate-limiting
 * and the failures look like our bug rather than their throttle.
 *
 * Four was too many in practice. Free and low tiers meter by requests per
 * minute, not by concurrency, so a burst of four every time a result lands
 * walks straight into a 429 even though only four are ever in flight. Lower the
 * window AND space the requests out: the window bounds how many are open at
 * once, the gap bounds how fast they leave. Both are needed - a window of one
 * with no gap still fires as fast as the model can answer. */
const DISPATCH_WINDOW = Math.max(1, Number(process.env.AI_CONCURRENCY || 2));
const MIN_DISPATCH_GAP_MS = Math.max(0, Number(process.env.AI_MIN_GAP_MS || 1500));

/* How long a dispatched item may sit without a callback before it is counted as
 * failed. Long enough to cover a slow model plus the workflow's own retries,
 * short enough that a lost reply does not hang the run for the afternoon. */
const SEND_TIMEOUT_MS = Math.max(30_000, Number(process.env.AI_SEND_TIMEOUT_MS || 300_000));

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/* Best-effort spacing, module-wide rather than per job: the provider's quota is
 * shared across every task and run, so pacing each job separately would let
 * three concurrent batches triple the rate. */
let lastDispatchAt = 0;
async function paceDispatch() {
    const wait = lastDispatchAt + MIN_DISPATCH_GAP_MS - Date.now();
    if (wait > 0) await sleep(wait);
    lastDispatchAt = Date.now();
}

/* Default ceiling when the caller names one. Manual mode does; automated mode
 * does not, and asking a user "how many functions?" is exactly the decision
 * "automated" is supposed to make for them. */
const DEFAULT_LIMIT = 40;

/* The threshold the engine itself uses to mean "worth a human's attention", and
 * the same one the symbol tree draws its "Worth review" folder from. Automated
 * scope is defined by this rather than by a count, so it adapts to the binary:
 * a small utility might yield 12 functions and a browser 400. */
const WORTH_REVIEW_SCORE = 20;

/* Ceiling on an automatic run. If a binary exceeds it, the highest-scoring
 * functions win and the job says how many were left out.
 *
 * It began as a pure safety rail at 200 - kernel32.dll has 1693 exports, and an
 * unbounded pass over it would be thousands of model calls from one click. In
 * practice 200 is far past what a free model tier will serve: 200 functions
 * across three stages is 600 requests, which throttles long before it finishes.
 *
 * Now configurable, and defaulted low enough to complete reliably. Raise it
 * once a paid tier or a local model removes the constraint. */
const MAX_AUTOMATIC = Math.max(1, Number(process.env.AI_MAX_FUNCTIONS || 10));

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

    /* An explicit list wins over selection entirely - that is the per-function
     * path, and second-guessing a direct request would be wrong.
     *
     * It does NOT skip the ordering below. This used to return here, which was
     * harmless while `only` always held one function: the moment a user selects
     * twenty, address order means callers are decompiled before their callees,
     * every prompt carries an empty summary for what it calls, and the output
     * quietly gets worse with nothing to indicate why. Narrow the candidates and
     * let the same ordering run. */
    let candidates = all.filter((f) => !f.is_thunk && !f.is_imported_stub && !f.is_library_code);

    const explicit = Array.isArray(only) && only.length > 0;
    if (explicit) {
        const wanted = new Set(only);
        // Filtered from `all`, not from `candidates`: a user who names a function
        // gets that function. The thunk and library exclusions exist to stop
        // automatic selection wasting money, not to overrule a direct request.
        candidates = all.filter((f) => wanted.has(f.va));
        // A named set is a decision already made; the score filter and the
        // ceiling are both aids to choosing, and neither applies now.
        limit = Math.max(candidates.length, 1);
    }

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
    // Skipped when the caller named a set: reachability selection exists to
    // answer "which functions are worth hunting in", and that question has just
    // been answered by a person.
    if (task === "bugs" && !explicit) {
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
 *
 * `options.force` suppresses that skip, and exists because it made `Re-lift` a
 * no-op: the single-function endpoints route through here too, so pressing
 * Re-lift on a function that had already been lifted queued nothing, the job
 * came back "done" without a request being sent, and the pane redisplayed the
 * old text. Asking for one function by name is an explicit instruction to redo
 * it; skipping is only right when the caller asked for a whole set.
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

    const force = options?.force === true;

    /* Whether a caller named the functions, rather than asking for a selection.
     *
     * `selectFunctions` computes the same thing from the same input, and reading
     * its copy from here is a ReferenceError - the two are separate scopes. It
     * has to be recomputed, not shared. */
    const explicit = Array.isArray(options?.only) && options.only.length > 0;

    /* How this work was asked for, recorded so the run can be read back later.
     *
     * Nothing on disk distinguished a function the engine picked from one a
     * person picked, or told either apart from a single re-lift - every result
     * looked the same afterwards, and "what have I actually run" had no answer.
     * The distinction only exists at this moment, so it is written down here.
     *
     * The id is supplied by the caller when one user action spans several tasks:
     * a hand-picked run of lift-then-bugs is one batch the person will look for,
     * not two. Absent that, each call is its own. */
    const batch = {
        id: options?.batch || `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
        kind: !explicit ? "automated" : (options.only.length === 1 ? "single" : "batch"),
        at: new Date().toISOString(),
        size: selected.length,
    };

    for (const fn of selected) {
        const stored = force
            ? null
            : await store.readJson(resultFile(runId, task, fn.va));
        /* A result that records its own failure does not count as done.
         *
         * When the provider rate-limits, the workflow still posts back - it has
         * to, or the batch would never complete - but it marks the body with
         * parse_error. Counting that as done would mean the one action a user
         * would naturally take, pressing Start again, skipped precisely the
         * functions that failed and reported instant success. */
        const existing = stored && stored.parse_error === true ? null : stored;
        const base = {
            name: fn.name,
            score: fn.information_score ?? 0,
            batch: batch.id,
        };
        if (existing) {
            items[fn.va] = { ...base, state: "done" };
            done++;
        } else {
            items[fn.va] = { ...base, state: "queued" };
            pending.push(fn.va);
        }
    }

    /* A named set joins the existing job; it does not replace it.
     *
     * `Lift with AI` on one function routes through here with only:[va], and
     * this used to overwrite the job file. After a ten-function pass, one
     * re-lift left a job of total 1 - so the progress bar read "1 of 1" and the
     * record of the batch was gone. Worse, doing it while a pass was running
     * discarded that pass's pending list and stopped it, with nothing on screen
     * to say why.
     *
     * Whole-set runs still replace, because "start the automated analysis" means
     * exactly that. */
    const previous = explicit ? await getJob(runId, task) : null;
    const merging = previous
        && previous.items
        && Object.keys(previous.items).length > 0;

    let job;
    if (merging) {
        const mergedItems = { ...previous.items, ...items };
        // Re-queue what was named, and keep anything already pending.
        const mergedPending = [...new Set([...(previous.pending || []), ...pending])];
        const values = Object.values(mergedItems);
        job = {
            ...previous,
            task,
            /* Batches accumulate. The merge exists so a single re-lift does not
             * erase a ten-function pass; dropping that pass's batch record would
             * erase it from the history instead, which is the same loss one
             * level down. */
            batches: { ...(previous.batches || {}), [batch.id]: batch },
            items: mergedItems,
            pending: mergedPending,
            total: Object.keys(mergedItems).length,
            done: values.filter((i) => i.state === "done").length,
            failed: values.filter((i) => i.state === "failed").length,
            state: mergedPending.length > 0 || values.some((i) => i.state === "sent")
                ? "running"
                : "done",
            message: `${mergedPending.length} queued of ${Object.keys(mergedItems).length}.`,
        };
    } else {
        job = {
            task,
            state: pending.length === 0 ? "done" : "running",
            total: selected.length,
            done,
            failed: 0,
            pending,
            items,
            /* A whole-set run replaces the job, and with it the batch register.
             * That is intended: "start the automated analysis" means this is the
             * run now. Earlier batches survive on the results themselves. */
            batches: { [batch.id]: batch },
            started_at: new Date().toISOString(),
            message:
                pending.length === 0
                    ? "Every selected function already had a result."
                    : `${pending.length} queued, ${done} already done.`,
        };
    }

    await store.writeJson(jobFile(runId, task), job);
    // Keyed off the job's own pending list, not the local one: after a merge the
    // job may carry work this call did not add, and the dispatcher should pick
    // that up too.
    if (job.pending.length > 0) void pump(runId, task, dispatch);
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
        if (job.items[va]) {
            job.items[va].state = "sent";
            // Stamped so a request that never comes back can be reclaimed. See
            // reapStalled: without this an item sits in "sent" forever and the
            // job can never settle.
            job.items[va].sent_at = Date.now();
        }
    }
    job.pending = job.pending.slice(going.length);
    await store.writeJson(jobFile(runId, task), job);

    for (const va of going) {
        try {
            await paceDispatch();
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

/**
 * Reclaim dispatches that never came back.
 *
 * A batch settles when done + failed reaches total. An item marked "sent" is
 * neither, so a single request that produces no callback stalls the stage
 * permanently: `pending` empties, the count freezes one short — 199 of 200 —
 * and because the automated run advances stage by stage on completion, bug
 * hunting and behaviour never start either. The whole pass hangs on one lost
 * reply, with nothing on screen to say so.
 *
 * The workflow is supposed to always post back, even on failure. This exists
 * because "supposed to" is not a guarantee across a network, a container and a
 * third-party model: n8n can be restarted mid-execution, a container can be
 * killed, a callback can be refused. Something has to bound the wait.
 *
 * Called from the job-status route, so the UI's own polling drives recovery
 * without needing a timer on the server.
 */
async function reapStalled(runId, task, dispatch) {
    const job = await getJob(runId, task);
    if (job.state !== "running") return job;

    const now = Date.now();
    let changed = false;
    let reaped = 0;

    for (const [va, item] of Object.entries(job.items)) {
        if (item.state !== "sent") continue;
        if (!item.sent_at) {
            // Dispatched before stamping existed, or by an older build. Give it
            // one full window rather than failing it on sight.
            item.sent_at = now;
            changed = true;
            continue;
        }
        if (now - item.sent_at < SEND_TIMEOUT_MS) continue;
        item.state = "failed";
        item.error = `no result within ${Math.round(SEND_TIMEOUT_MS / 1000)}s`;
        changed = true;
        reaped++;
    }

    if (!changed) return job;

    job.failed = Object.values(job.items).filter((i) => i.state === "failed").length;
    if (job.pending.length === 0
        && !Object.values(job.items).some((i) => i.state === "sent")) {
        job.state = "done";
        job.message =
            `${job.done} of ${job.total} complete, ${job.failed} failed`
            + (reaped > 0 ? ` (${reaped} timed out)` : "");
    }
    await store.writeJson(jobFile(runId, task), job);
    if (job.state === "running" && job.pending.length > 0) void pump(runId, task, dispatch);
    return job;
}

/** Ceiling on one hand-picked selection after depth expansion.
 *
 *  Expansion is exponential in the worst case: seven levels of a function with
 *  ten callees each is ten million. The cap is what makes the depth control safe
 *  to expose, and the caller is told what was cut rather than silently given a
 *  truncated set. */
const MAX_EXPANDED = Math.max(1, Number(process.env.AI_MAX_SELECTION || 120));

/**
 * Grow a chosen set of functions through their callees, `depth` levels down.
 *
 * depth 0  the chosen functions alone
 * depth 1  those plus everything they call
 * depth 2  and everything those call, and so on
 *
 * Three things make this safe rather than a foot-gun:
 *
 *   - a visited set, because binaries recurse and a plain walk would not
 *     terminate on mutual recursion;
 *   - breadth-first, so if the ceiling truncates it keeps the levels nearest
 *     the chosen functions, which are the ones the user actually cared about;
 *   - thunks, import stubs and library code are not followed. Expanding into the
 *     CRT would spend the whole budget explaining Microsoft's code.
 *
 * Returns what was selected AND what it had to leave out, so the caller can say
 * so before spending anything.
 */
async function expandSelection(runId, roots, depth) {
    const p = store.paths(runId);
    const document = await store.readJson(path.join(p.analysis, "functions.json"));
    const index = new Map((document?.functions ?? []).map((f) => [f.va, f]));

    const worthFollowing = (fn) =>
        fn && !fn.is_thunk && !fn.is_imported_stub && !fn.is_library_code;

    const selected = [];
    const seen = new Set();
    let frontier = [];

    for (const va of roots) {
        if (seen.has(va) || !index.has(va)) continue;
        seen.add(va);
        selected.push(va);
        frontier.push(va);
    }

    const levels = Math.max(0, Math.min(Number(depth) || 0, 7));
    let truncated = false;

    for (let level = 0; level < levels && frontier.length > 0; level++) {
        const next = [];
        for (const va of frontier) {
            const detail = await store.readJson(
                path.join(p.functions, `func_${String(va).slice(2)}.json`),
            );
            for (const callee of detail?.callees ?? []) {
                if (seen.has(callee.va)) continue;
                seen.add(callee.va);
                if (!worthFollowing(index.get(callee.va))) continue;
                if (selected.length >= MAX_EXPANDED) { truncated = true; continue; }
                selected.push(callee.va);
                next.push(callee.va);
            }
        }
        frontier = next;
    }

    return { selected, truncated, ceiling: MAX_EXPANDED, depth: levels };
}

/**
 * The functions on the call paths of specific findings, plus their sinks.
 *
 * The automated bugs pass does this for every finding at once. Hunting one
 * finding is the same question asked narrowly, and the call path is already
 * derived, so the selection is a lookup rather than an analysis.
 */
async function selectionForFindings(runId, wanted) {
    const p = store.paths(runId);
    const document = await store.readJson(path.join(p.analysis, "findings.json"));
    const all = document?.findings ?? [];

    const keyed = new Set(wanted.map((w) => `${w.function}|${w.api}`));
    const selected = [];
    const seen = new Set();

    for (const finding of all) {
        if (!keyed.has(`${finding.function}|${finding.api}`)) continue;
        for (const va of [finding.function, ...(finding.call_path ?? []).map((s) => s.va)]) {
            if (seen.has(va)) continue;
            seen.add(va);
            selected.push(va);
        }
    }
    return selected;
}

/**
 * Stop a running batch.
 *
 * Drops the queue rather than trying to recall what is already in flight: a
 * request sitting with the model cannot be withdrawn, and pretending otherwise
 * would mean discarding a result that has been paid for. Anything already sent
 * is still recorded when it comes back; `pump` will not start anything new
 * because it refuses to run unless the job is "running".
 */
async function stopBatch(runId, task) {
    const job = await getJob(runId, task);
    if (job.state !== "running") return job;

    for (const va of job.pending) {
        if (job.items[va]) job.items[va].state = "stopped";
    }
    const inFlight = Object.values(job.items).filter((i) => i.state === "sent").length;
    job.pending = [];
    job.state = "stopped";
    job.message =
        `Stopped at ${job.done} of ${job.total}.`
        + (inFlight > 0
            ? ` ${inFlight} already sent will still be recorded if they return.`
            : "");
    await store.writeJson(jobFile(runId, task), job);
    return job;
}

/**
 * Delete everything an AI task has produced for this run: the job and every
 * stored result, so the next start begins from nothing.
 *
 * Results are removed, not just the job, because the job is rebuilt from what
 * is on disk — clearing only the job would have the next run count all the old
 * results as done and finish instantly, which is the opposite of a reset.
 */
async function resetTask(runId, task) {
    const dir = path.join(store.paths(runId).root, "ai", task);
    await fs.rm(dir, { recursive: true, force: true });
    await fs.rm(jobFile(runId, task), { force: true });
    return emptyJob(task);
}

/**
 * Which functions already have a result, per task.
 *
 * Read from the result directory rather than from the job, because the job only
 * knows about its own batch: a function lifted individually months of clicking
 * ago is just as analysed, and the symbol tree needs to say so. A result marked
 * `parse_error` does not count as analysed - it records a failure, not an
 * analysis - but it is not nothing either, so it is reported separately under
 * `failed`. "Asked and it went wrong" and "never asked" need different marks;
 * folding them together is what made a failed lift look like an idle function.
 */
async function analysedFunctions(runId) {
    const out = {};
    const failed = {};
    for (const task of TASKS) {
        const dir = path.join(store.paths(runId).root, "ai", task);
        const found = [];
        const broke = [];
        out[task] = found;
        failed[task] = broke;
        let entries = [];
        try {
            entries = await fs.readdir(dir);
        } catch {
            continue;
        }
        for (const entry of entries) {
            if (!entry.endsWith(".json")) continue;
            const va = entry.slice(0, -5);
            const stored = await store.readJson(path.join(dir, entry));
            if (!stored) continue;
            if (stored.parse_error === true) broke.push(va);
            else found.push(va);
        }
    }
    out.failed = failed;
    return out;
}

/**
 * Per-function outcome for every task: what happened, and when nothing did, why.
 *
 * The counters on a job say "3 failed" and stop there, which is the wrong place
 * to stop - a failure you cannot name is a failure you cannot retry deliberately.
 * Neither the job nor the results directory can answer this alone:
 *
 *   the job      knows a request was dispatched and never came back, which is
 *                invisible on disk because no result was ever written
 *   the result   knows why a reply was unusable, which the job never sees
 *
 * So they are merged. `state` is what to show the reader:
 *
 *   issues    the model reported something
 *   clean     the model answered and reported nothing - a result, not a silence
 *   failed    a reply arrived and could not be used; `error` says how
 *   waiting   dispatched, still outstanding
 *   queued    accepted, not yet sent
 *   skipped   not part of this run
 */
async function outcomes(runId) {
    const out = {};
    for (const task of TASKS) {
        const job = await getJob(runId, task);
        const rows = [];
        const seen = new Set();

        for (const [va, item] of Object.entries(job.items || {})) {
            seen.add(va);
            rows.push(await outcomeRow(runId, task, va, item));
        }

        /* Results with no job entry are not noise: a function lifted on its own
         * weeks ago has no place in today's job and is still analysed. Leaving
         * it out would make this list disagree with the tree's marks. */
        const dir = path.join(store.paths(runId).root, "ai", task);
        let entries = [];
        try {
            entries = await fs.readdir(dir);
        } catch { /* nothing has run for this task */ }
        for (const entry of entries) {
            if (!entry.endsWith(".json")) continue;
            const va = entry.slice(0, -5);
            if (seen.has(va)) continue;
            rows.push(await outcomeRow(runId, task, va, null));
        }

        rows.sort((a, b) => a.va.localeCompare(b.va));
        out[task] = rows;
    }
    return out;
}

/** One row of {@link outcomes}. `item` is the job's entry, or null when the
 *  result outlived the job that produced it. */
async function outcomeRow(runId, task, va, item) {
    const result = await getResult(runId, task, va);
    const row = {
        va,
        name: item?.name ?? result?.function_name ?? va,
        state: "skipped",
        issues: null,
        error: null,
        /* The behaviour pass's prose, carried here so the tracking table can
         * show it. The capability profile groups these under engine-matched
         * rules, which means a function matching no rule has its description
         * stored and nowhere to appear - the pass ran, produced something
         * useful, and the interface had no place to put it. */
        narrative: null,
        finish_reason: result?.finish_reason ?? null,
        received_at: result?.received_at ?? null,
    };

    if (result?.parse_error === true) {
        row.state = "failed";
        // The workflow puts its diagnosis in `summary` for the tasks that have
        // one, and in `error` otherwise. Either way the reader wants the text,
        // not the word "failed".
        row.error = result.error || result.summary || "The reply could not be used.";
        return row;
    }

    if (result) {
        /* Only the bug pass can report "nothing found", because only it is
         * looking for something. A lift produces C and a behaviour pass produces
         * a description; neither has an `issues` array, and reading its absence
         * as an empty one labelled every successful lift as the model having
         * found nothing - which reads as a failure of exactly the kind this view
         * exists to rule out. */
        if (task !== "bugs") {
            row.state = "done";
            if (task === "behaviour") {
                const text = typeof result.summary === "string"
                    ? result.summary.trim() : "";
                row.narrative = text || null;
            }
            return row;
        }
        const issues = Array.isArray(result.issues) ? result.issues.length : 0;
        row.issues = issues;
        row.state = issues > 0 ? "issues" : "clean";
        return row;
    }

    // No result on disk. Only the job knows whether one is still coming.
    if (item?.state === "sent") row.state = "waiting";
    else if (item?.state === "queued") row.state = "queued";
    else if (item?.state === "failed") {
        row.state = "failed";
        row.error = item.error || "Dispatch failed before a reply was received.";
    }
    return row;
}

/**
 * The process-tracking view: every analysable function, what each task did for
 * it, and how it came to be run.
 *
 * Built from the function list rather than from the jobs, so the table exists
 * before anything has been run. A tracking view that is empty until you use it
 * cannot tell you what is left to do, which is most of what it is for.
 *
 * `stages` carries the live job state alongside it. The alternative was three
 * more requests from the client and three chances for them to disagree with
 * each other about which stage is running.
 */
async function summary(runId) {
    const p = store.paths(runId);
    const document = await store.readJson(path.join(p.analysis, "functions.json"));
    const all = document?.functions ?? [];

    const cells = await outcomes(runId);
    const byTaskVa = new Map();
    for (const task of TASKS) {
        for (const row of cells[task]) byTaskVa.set(`${task}:${row.va}`, row);
    }

    /* How each function came to be run, and when.
     *
     * A function can belong to several batches over time - picked up by the
     * automated pass, then re-run alone when its result looked wrong. The most
     * recent one is what the table reports, because that is the run whose result
     * is on disk now. */
    const origin = new Map();
    const stages = [];
    for (const task of TASKS) {
        const job = await getJob(runId, task);
        const register = job.batches || {};
        for (const [va, item] of Object.entries(job.items || {})) {
            const batch = register[item.batch] || null;
            const at = batch?.at ?? null;
            const previous = origin.get(va);
            if (!previous || (at && (!previous.at || at > previous.at))) {
                origin.set(va, { kind: batch?.kind ?? "unknown", at });
            }
        }
        const items = Object.values(job.items || {});
        stages.push({
            task,
            state: job.state ?? "idle",
            total: job.total ?? 0,
            done: job.done ?? 0,
            failed: job.failed ?? 0,
            /* Outstanding work, not the stored state: a job whose file says
             * "running" after a restart has nothing in flight, and bolding it
             * would point at a stage that is not happening. */
            active: (job.pending?.length ?? 0) > 0
                || items.some((i) => i.state === "sent"),
        });
    }

    /* Excluded functions are left out - they are never sent, so three dashes
     * each is noise - unless something was actually run on one, which means a
     * person asked for it by name and deserves to see the result. */
    const touched = new Set([...origin.keys()]);
    for (const task of TASKS) {
        for (const row of cells[task]) touched.add(row.va);
    }

    const rows = all
        .filter((f) => touched.has(f.va)
            || (!f.is_thunk && !f.is_imported_stub && !f.is_library_code))
        .map((f) => {
            const tasks = {};
            for (const task of TASKS) {
                const cell = byTaskVa.get(`${task}:${f.va}`);
                tasks[task] = cell
                    ? { state: cell.state, issues: cell.issues, error: cell.error }
                    : { state: "none", issues: null, error: null };
            }
            const from = origin.get(f.va) ?? null;
            return {
                va: f.va,
                name: f.name,
                score: f.information_score ?? 0,
                /* Lifted to the row rather than left on the behaviour cell: it
                 * is a fact about the function, and the table shows it whether
                 * or not the function matched a capability rule. */
                narrative: byTaskVa.get(`behaviour:${f.va}`)?.narrative ?? null,
                excluded: !!(f.is_thunk || f.is_imported_stub || f.is_library_code),
                kind: from?.kind ?? null,
                at: from?.at ?? null,
                tasks,
            };
        });

    // Highest triage score first: the same order the automated pass would pick
    // them in, so the top of the table is the part that matters most.
    rows.sort((a, b) => b.score - a.score);
    return { stages, rows };
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
    selectFunctions, startBatch, getJob, emptyJob, getResult, reapStalled,
    stopBatch, resetTask, expandSelection, selectionForFindings, analysedFunctions,
    outcomes, summary,
    recordResult, recordFailure, currentVersionId, isStale, versionId,
};
