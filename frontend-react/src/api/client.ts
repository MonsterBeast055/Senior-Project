/*
 * client.ts - The only file that knows where data comes from.
 *
 * Two modes:
 *   "sample"  embedded real engine output, so the UI runs with no backend
 *   "api"     the backend, which runs the C++ engine and stores n8n's results
 *
 * Both return identical shapes, so nothing else in the app knows which is live.
 * Keep this file as the boundary: everything else here is replaceable, this is
 * the contract.
 */
import type {
    AiPayload, BinaryContext, CallGraphDocument, CallGraphEdge, FindingExplanation,
    FindingsDocument, ExtractedString, FunctionDetail, FunctionSummary,
    HardenResponse, Hex, ImageInfo, LiftedFunction, LiftState, MitigationsResponse,
    RunStatus, RunSummary, Severity,
} from "./types";
import {
    sampleDetails, sampleFindings, sampleFunctions, sampleImage,
    sampleLifted, sampleStrings,
} from "./sample";

export type DataMode = "sample" | "api";

let mode: DataMode = "sample";
let base = "/api";
let runId = "current";

export function configure(next: DataMode, apiBase?: string, run?: string) {
    mode = next;
    if (apiBase) base = apiBase.replace(/\/+$/, "");
    if (run) runId = run;
}

export function currentMode(): DataMode {
    return mode;
}

/* ======================================================================
 * Health
 *
 * Worth its own call. Without it, a backend that is simply not running looks
 * identical to a broken one: the browser reports a generic network failure, the
 * Vite dev server logs ECONNREFUSED, and neither says "you forgot to start the
 * API". This lets the UI say that itself.
 * ====================================================================== */

export interface HealthReport {
    reachable: boolean;
    engine_ok?: boolean;
    engine_path?: string;
    n8n_configured?: boolean;
    detail?: string;
}

export async function getHealth(): Promise<HealthReport> {
    if (mode === "sample") {
        return { reachable: true, detail: "sample data — no backend involved" };
    }
    try {
        // Short timeout: a connection refused is instant, but a wrong host can
        // hang for the OS default, and an indicator that takes 75 seconds to say
        // "down" is worse than none.
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 3000);
        const response = await fetch(`${base}/health`, {
            headers: { Accept: "application/json" },
            signal: controller.signal,
        });
        clearTimeout(timer);
        if (!response.ok) {
            return { reachable: false, detail: `the API answered HTTP ${response.status}` };
        }
        const body = await response.json();
        return {
            reachable: true,
            engine_ok: body.engine?.ok !== false,
            engine_path: body.engine?.path,
            n8n_configured: !!body.n8n_configured,
        };
    } catch {
        // Deliberately actionable rather than accurate-and-useless. "Failed to
        // fetch" is what the browser says; it is never what the person needs.
        return {
            reachable: false,
            detail:
                "the backend is not answering. Start it with `npm start` in the "
                + "backend folder, then click Retry.",
        };
    }
}

async function fetchJson<T>(path: string): Promise<T> {
    const response = await fetch(`${base}/runs/${runId}${path}`, {
        headers: { Accept: "application/json" },
    });
    if (response.status === 404) return null as unknown as T;
    if (!response.ok) throw new Error(`${path} → HTTP ${response.status}`);
    return (await response.json()) as T;
}

async function get<T>(path: string, fallback: T): Promise<T> {
    if (mode === "sample") return fallback;
    return fetchJson<T>(path);
}

/* ======================================================================
 * Engine output
 * ====================================================================== */

export const getImage = () => get<ImageInfo>("/image", sampleImage);

export const getFindings = () => get<FindingsDocument>("/findings", sampleFindings);

export async function getFunctions(): Promise<FunctionSummary[]> {
    const document = await get<{ functions: FunctionSummary[] }>(
        "/functions",
        { functions: sampleFunctions },
    );
    return document?.functions ?? [];
}

export async function getStrings(): Promise<ExtractedString[]> {
    const document = await get<{ strings: ExtractedString[] }>(
        "/strings",
        { strings: sampleStrings },
    );
    return document?.strings ?? [];
}

export const getFunction = (va: string) =>
    get<FunctionDetail | null>(`/functions/${va}`, sampleDetails[va] ?? null);

/** Whole-image call graph. Needed to answer "what is this function in service
 *  of", which per-function `callers`/`callees` cannot — that is one hop, and the
 *  question spans the whole descent.
 *
 *  Sample mode synthesises it from the embedded function details rather than
 *  shipping a second fixture, so offline browsing behaves the same. */
export async function getCallGraph(): Promise<CallGraphDocument> {
    if (mode === "sample") {
        const edges: CallGraphEdge[] = [];
        for (const detail of Object.values(sampleDetails)) {
            for (const callee of detail.callees ?? []) {
                edges.push({ from: detail.va, to: callee.va });
            }
        }
        return {
            nodes: sampleFunctions.map((f) => ({
                va: f.va,
                name: f.name,
                is_thunk: f.is_thunk ?? false,
                // Unknown offline, and claiming false would understate how
                // incomplete a synthesised graph is.
                has_indirect_calls: (f.indirect_call_count ?? 0) > 0,
            })),
            edges,
        };
    }
    return fetchJson<CallGraphDocument>("/callgraph");
}

/* ======================================================================
 * n8n boundary
 *
 * The engine never produces any of this. The backend forwards a lift request to
 * the n8n webhook, n8n calls the model, and posts the result back. The frontend
 * only ever talks to the backend.
 *
 * Backend endpoints these assume:
 *   GET  /runs/{id}/functions/{va}/lifted        current result, or 404
 *   POST /runs/{id}/functions/{va}/lift          trigger the n8n workflow
 *   POST /runs/{id}/functions/{va}/lifted/review { review: "accepted" | ... }
 * ====================================================================== */

export const getLifted = (va: string) =>
    get<LiftedFunction | null>(`/functions/${va}/lifted`, sampleLifted[va] ?? null);

/** Ask the backend to run the n8n lifting workflow for one function.
 *
 *  In sample mode this is a no-op that reports back what is already embedded,
 *  so the button is still exercisable without a backend. */
export async function requestLift(va: string): Promise<LiftState> {
    if (mode === "sample") {
        return sampleLifted[va] ? "done" : "not-run";
    }
    const response = await fetch(`${base}/runs/${runId}/functions/${va}/lift`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
    });
    if (!response.ok) throw new Error(`lift → HTTP ${response.status}`);
    const body = (await response.json()) as { state?: LiftState };
    return body.state ?? "queued";
}

/** Accept or reject the model's output.
 *
 *  This is the write side of the feedback loop. An accepted name is meant to
 *  land in the engine's AnnotationStore and appear in the next export, which is
 *  why review is an explicit action rather than something inferred. */
export async function reviewLift(
    va: string,
    review: "accepted" | "rejected",
): Promise<void> {
    if (mode === "sample") return;
    const response = await fetch(
        `${base}/runs/${runId}/functions/${va}/lifted/review`,
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ review }),
        },
    );
    if (!response.ok) throw new Error(`review → HTTP ${response.status}`);
}

/* ======================================================================
 * Runs: upload, status, history
 * ====================================================================== */

/** Which run the getters above read from. */
export function setRun(id: string) {
    runId = id;
}

export function currentRun(): string {
    return runId;
}

const SAMPLE_RUNS: RunSummary[] = [
    {
        run_id: "sample-notepad",
        file_name: "notepad.exe",
        file_size: 360448,
        sha256: "3a1f…c9d2",
        created_at: "2026-08-05T09:14:22Z",
        arch: "x86_64",
        stage: "done",
        function_count: 452,
        instruction_count: 38202,
        code_fraction: 0.944,
        impactful_findings: 1,
        risky_operations: 3,
        lifted_count: 2,
    },
    {
        run_id: "sample-kernel32",
        file_name: "kernel32.dll",
        file_size: 774144,
        sha256: "77bd…41ae",
        created_at: "2026-08-04T16:02:10Z",
        arch: "x86_64",
        stage: "done",
        function_count: 2712,
        instruction_count: 128954,
        code_fraction: 0.923,
        impactful_findings: 0,
        risky_operations: 41,
        lifted_count: 0,
    },
    {
        run_id: "sample-notepad32",
        file_name: "notepad.exe (SysWOW64)",
        file_size: 201216,
        created_at: "2026-08-04T11:47:55Z",
        arch: "x86",
        stage: "done",
        function_count: 2195,
        instruction_count: 46594,
        code_fraction: 0.907,
        impactful_findings: 0,
        risky_operations: 12,
        lifted_count: 0,
    },
];

export async function listRuns(): Promise<RunSummary[]> {
    if (mode === "sample") return SAMPLE_RUNS;
    const response = await fetch(`${base}/runs`, { headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error(`/runs → HTTP ${response.status}`);
    const body = (await response.json()) as { runs?: RunSummary[] };
    return body.runs ?? [];
}

export async function deleteRun(id: string): Promise<void> {
    if (mode === "sample") return;
    const response = await fetch(`${base}/runs/${id}`, { method: "DELETE" });
    if (!response.ok) throw new Error(`delete → HTTP ${response.status}`);
}

export async function getRunStatus(id: string): Promise<RunStatus> {
    if (mode === "sample") {
        return { run_id: id, stage: "done", percent: 100 };
    }
    const response = await fetch(`${base}/runs/${id}/status`, {
        headers: { Accept: "application/json" },
    });
    if (!response.ok) throw new Error(`status → HTTP ${response.status}`);
    return (await response.json()) as RunStatus;
}

/** Upload a binary and start analysis. Returns the new run id.
 *
 *  The backend saves the file, runs `sp export`, and stores the resulting JSON.
 *  XMLHttpRequest rather than fetch because fetch still has no upload progress
 *  event, and a multi-megabyte binary on a slow link needs one. */
export function uploadBinary(
    file: File,
    onProgress?: (percent: number) => void,
): Promise<string> {
    if (mode === "sample") {
        // Simulated so the whole flow is exercisable with no backend.
        return new Promise((resolve) => {
            let percent = 0;
            const timer = window.setInterval(() => {
                percent += 20;
                onProgress?.(Math.min(percent, 100));
                if (percent >= 100) {
                    window.clearInterval(timer);
                    resolve("sample-notepad");
                }
            }, 180);
        });
    }

    return new Promise((resolve, reject) => {
        const form = new FormData();
        form.append("binary", file, file.name);

        const request = new XMLHttpRequest();
        request.open("POST", `${base}/runs`);
        request.upload.onprogress = (event) => {
            if (event.lengthComputable) {
                onProgress?.(Math.round((event.loaded / event.total) * 100));
            }
        };
        request.onload = () => {
            if (request.status < 200 || request.status >= 300) {
                reject(new Error(`upload → HTTP ${request.status}`));
                return;
            }
            try {
                const body = JSON.parse(request.responseText) as { run_id?: string };
                if (!body.run_id) throw new Error("response had no run_id");
                resolve(body.run_id);
            } catch (cause) {
                reject(cause as Error);
            }
        };
        // XHR gives no detail on a network failure by design, so guessing is the
        // only option — and a connection refused is far and away the likeliest
        // cause. Naming it beats reporting "network error" and leaving the person
        // to find the ECONNREFUSED lines in the Vite console.
        request.onerror = () =>
            reject(new Error(
                `could not reach the backend at ${base}. Is it running? `
                + `Start it with \`npm start\` in the backend folder.`,
            ));
        request.ontimeout = () => reject(new Error("the upload timed out"));
        request.send(form);
    });
}

/* ======================================================================
 * Finding explanations  (n8n)
 * ====================================================================== */

const SAMPLE_EXPLANATIONS: Record<string, FindingExplanation> = {
    "0x1400023a0:wcscpy": {
        model: "sample",
        summary:
            "The function reads a value out of the Notepad settings key and copies it " +
            "into a fixed 32-character stack buffer using wcscpy, which takes no length " +
            "argument.",
        why_severity:
            "wcscpy has no bounded form — there is no length parameter to get right, so " +
            "the only thing preventing an overflow is the source data being short " +
            "enough. The source here is a registry value, which is data the program did " +
            "not produce itself, and the engine found a call path from the read to the " +
            "copy. That combination is what promotes this above a style complaint.",
        impact:
            "A registry value longer than 31 characters would write past the end of a " +
            "stack buffer. Whether that is exploitable depends on what follows the " +
            "buffer in the frame and whether the binary was built with stack cookies; " +
            "at minimum it is a crash, and at worst a stack-based overflow.",
        remediation:
            "Use wcscpy_s or StringCchCopyW with the destination size, and treat the " +
            "value returned by RegQueryValueExW as untrusted regardless of who is " +
            "expected to have written it.",
        preconditions: [
            "The attacker must be able to write to HKCU for the target user.",
            "Exploitability beyond a crash depends on frame layout and whether /GS is enabled.",
        ],
        confidence: "medium",
        severity_source: "engine",
        review: "not-reviewed",
    },
};

function explanationKey(va: string, api: string): string {
    return `${va}:${api.split("!").pop()}`;
}

export const getFindingExplanation = (va: string, api: string) =>
    get<FindingExplanation | null>(
        `/findings/${va}/${encodeURIComponent(api)}/explanation`,
        SAMPLE_EXPLANATIONS[explanationKey(va, api)] ?? null,
    );

/** Ask the backend to have n8n explain one finding. */
export async function requestFindingExplanation(
    va: string,
    api: string,
): Promise<LiftState> {
    if (mode === "sample") {
        return SAMPLE_EXPLANATIONS[explanationKey(va, api)] ? "done" : "not-run";
    }
    const response = await fetch(
        `${base}/runs/${runId}/findings/${va}/${encodeURIComponent(api)}/explain`,
        { method: "POST", headers: { "Content-Type": "application/json" } },
    );
    if (!response.ok) throw new Error(`explain → HTTP ${response.status}`);
    const body = (await response.json()) as { state?: LiftState };
    return body.state ?? "queued";
}

/* ======================================================================
 * AI Analysis  (n8n)
 *
 * Three tasks. Each runs on one function, or as a batch the backend selects by
 * information_score — the triage number the engine computes precisely so this
 * layer does not have to spend a model call on all 452 functions.
 * ====================================================================== */

export type AiTask = "decompile" | "bugs" | "behaviour";

export interface AiJobItem {
    /** "stopped" is set on queued items when a run is halted: the request was
     *  never sent, so it is neither done nor failed. */
    state: "queued" | "sent" | "done" | "failed" | "stopped";
    name: string;
    score: number;
    error?: string;
    /** When the request went out. Used to reclaim a dispatch that never came
     *  back, so one lost reply cannot stall a stage indefinitely. */
    sent_at?: number;
}

export interface AiJob {
    task: AiTask;
    /* "stopped" was missing here while the backend was already sending it, so
     * the check that ends a halted run compared against a value TypeScript
     * believed impossible. It compiled as dead code and Stop would have let the
     * run advance to the next stage instead of ending. */
    state: "not-started" | "running" | "done" | "empty" | "not-run" | "stopped";
    total: number;
    done: number;
    failed: number;
    pending: string[];
    items: Record<string, AiJobItem>;
    message: string | null;
    n8n_configured?: boolean;
}

export interface AiResult {
    task: AiTask;
    va: Hex;
    model?: string;
    summary?: string;
    /** decompile */
    code?: string;
    /** bugs */
    issues?: {
        title: string;
        detail: string;
        engine_finding?: string;
        confidence?: string;
    }[];
    /** behaviour */
    capabilities?: { label: string; evidence: string }[];
    /** Always "engine" — the backend overwrites it. Never a model's rating. */
    severity_source?: "engine";
    received_at?: string;
}

const EMPTY_JOB = (task: AiTask): AiJob => ({
    task, state: "not-started", total: 0, done: 0, failed: 0,
    pending: [], items: {},
    message: "Sample mode — AI Analysis needs the backend and an n8n workflow.",
    n8n_configured: false,
});

export async function getAiJob(task: AiTask): Promise<AiJob> {
    if (mode === "sample") return EMPTY_JOB(task);
    const response = await fetch(`${base}/runs/${runId}/ai/${task}`, {
        headers: { Accept: "application/json" },
    });
    if (!response.ok) throw new Error(`ai/${task} → HTTP ${response.status}`);
    return (await response.json()) as AiJob;
}

/** Start a batch. `only` overrides selection entirely, for the one-function case. */
export async function startAiBatch(
    task: AiTask,
    options: { limit?: number; only?: string[]; batch?: string } = {},
): Promise<AiJob> {
    if (mode === "sample") return EMPTY_JOB(task);
    const response = await fetch(`${base}/runs/${runId}/ai/${task}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(options),
    });
    if (!response.ok) throw new Error(`ai/${task} → HTTP ${response.status}`);
    return (await response.json()) as AiJob;
}

/* ======================================================================
 * Mitigations
 * ====================================================================== */

/** Read-only inspection of the uploaded binary's mitigation state. */
export async function getMitigations(): Promise<MitigationsResponse | null> {
    if (mode === "sample") return null;
    const response = await fetch(`${base}/runs/${runId}/mitigations`);
    if (response.status === 404) return null;
    if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.error || `mitigations → HTTP ${response.status}`);
    }
    return (await response.json()) as MitigationsResponse;
}

/** Produce a hardened copy. The uploaded original is never modified. */
export async function hardenBinary(
    options: { allowSigned?: boolean; fixWx?: boolean } = {},
): Promise<HardenResponse> {
    const response = await fetch(`${base}/runs/${runId}/harden`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            allow_signed: options.allowSigned === true,
            fix_wx: options.fixWx === true,
        }),
    });
    if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.error || `harden → HTTP ${response.status}`);
    }
    return (await response.json()) as HardenResponse;
}

/** Direct link, so the browser downloads it rather than the app buffering it. */
export function hardenedDownloadUrl(): string {
    return `${base}/runs/${runId}/hardened`;
}

/** What would be sent to the model for one function, without sending it. */
export async function getAiPayload(task: AiTask, va: string): Promise<AiPayload> {
    const response = await fetch(`${base}/runs/${runId}/ai/${task}/${va}/payload`);
    if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.error || `payload → HTTP ${response.status}`);
    }
    return (await response.json()) as AiPayload;
}

/** Which functions already have AI results, per task. */
export interface AiCoverage {
    decompile: string[];
    bugs: string[];
    behaviour: string[];
    /** Addresses whose stored result records a failure rather than an analysis.
     *  Kept apart from the lists above so the tree can say "this was tried and
     *  it went wrong" instead of showing it as untouched. */
    failed: Record<AiTask, string[]>;
}

export async function getAiCoverage(): Promise<AiCoverage> {
    const empty: AiCoverage = {
        decompile: [], bugs: [], behaviour: [],
        failed: { decompile: [], bugs: [], behaviour: [] },
    };
    if (mode === "sample") return empty;
    const response = await fetch(`${base}/runs/${runId}/ai/coverage`);
    if (!response.ok) return empty;
    const body = (await response.json()) as Partial<AiCoverage>;
    // A backend that predates `failed` answers without it. Missing is empty,
    // not undefined, so no caller has to guard.
    return { ...empty, ...body, failed: { ...empty.failed, ...(body.failed ?? {}) } };
}

/* What became of one function in one pass.
 *
 * `done` is a usable result for a task with nothing to count - a lift or a
 * behaviour description. `clean` is bugs-only: the model looked for defects and
 * reported none, which is an answer rather than a silence. `none` means the
 * pass was never asked about this function at all.
 *
 * There was a second view over this - a per-task outcome window - reading the
 * same backend call the Summary tab reads. Two renderings of one dataset is how
 * they drift, so it was removed and the one thing it had that Summary lacked
 * (the failure reason as readable text, not a tooltip) moved into Summary.
 */
export type AiOutcomeState =
    | "done" | "issues" | "clean" | "failed" | "waiting" | "queued"
    | "skipped" | "none";

/** What one task did for one function. `none` means it was never asked. */
export interface SummaryCell {
    state: AiOutcomeState;
    issues: number | null;
    error: string | null;
}

/** One function's row in the process-tracking table. */
export interface SummaryRow {
    va: string;
    name: string;
    score: number;
    /** The behaviour pass's description of this function, when it has run. */
    narrative: string | null;
    /** Thunk, imported stub or library code — never selected automatically. */
    excluded: boolean;
    /** How it was most recently run, or null if it never has been. */
    kind: "automated" | "batch" | "single" | "unknown" | null;
    at: string | null;
    tasks: Record<AiTask, SummaryCell>;
}

/** Live state of one pass, for the stage strip. */
export interface SummaryStage {
    task: AiTask;
    state: string;
    total: number;
    done: number;
    failed: number;
    /** Has work in flight right now. Drives the bold marker. */
    active: boolean;
}

export interface RunSummary {
    stages: SummaryStage[];
    rows: SummaryRow[];
}

/** A shared id for one user action that spans several tasks, so the run log
 *  groups them as the person experienced them rather than as three requests. */
export function newBatchId(): string {
    return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

export async function getRunSummary(): Promise<RunSummary> {
    const empty: RunSummary = { stages: [], rows: [] };
    if (mode === "sample") return empty;
    const response = await fetch(`${base}/runs/${runId}/ai/summary`);
    if (!response.ok) {
        /* The server's own words, not just the number.
         *
         * `HTTP 400` alone is unreadable here, because the one thing that
         * returns 400 on this path is the wildcard route binding task="summary"
         * - which only happens when the running server predates this route.
         * That body says so in as many words; discarding it turned a one-line
         * diagnosis into a guess. */
        const body = await response.json().catch(() => ({} as { error?: string }));
        const detail = body.error ? `: ${body.error}` : "";
        const hint = response.status === 400 || response.status === 404
            ? " — this route is new, so restart the backend if it is still running"
            + " an older copy."
            : "";
        throw new Error(`summary → HTTP ${response.status}${detail}${hint}`);
    }
    return { ...empty, ...((await response.json()) as RunSummary) };
}

export interface SelectionPreview {
    selected: string[];
    /** True when the ceiling cut the expansion short. */
    truncated: boolean;
    ceiling: number;
    depth: number;
    from_findings: number;
    functions: { va: string; name: string; information_score: number }[];
}

/** What a hand-picked selection would come to, without starting it. */
export async function previewSelection(request: {
    only?: string[];
    depth?: number;
    findings?: { function: string; api: string }[];
}): Promise<SelectionPreview> {
    const response = await fetch(`${base}/runs/${runId}/ai/preview`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(request),
    });
    if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.error || `preview → HTTP ${response.status}`);
    }
    return (await response.json()) as SelectionPreview;
}

/** Stop a batch. Work already sent to the model still records if it returns. */
export async function stopAiBatch(task: AiTask): Promise<AiJob> {
    if (mode === "sample") return EMPTY_JOB(task);
    const response = await fetch(`${base}/runs/${runId}/ai/${task}/stop`, { method: "POST" });
    if (!response.ok) throw new Error(`ai/${task}/stop → HTTP ${response.status}`);
    return (await response.json()) as AiJob;
}

/** Delete every AI result for this run, across all three tasks. */
export async function resetAi(): Promise<void> {
    if (mode === "sample") return;
    const response = await fetch(`${base}/runs/${runId}/ai/reset`, { method: "POST" });
    if (!response.ok) throw new Error(`ai/reset → HTTP ${response.status}`);
}

export const getAiResult = (task: AiTask, va: string) =>
    get<AiResult | null>(`/ai/${task}/${va}`, null);

/* ======================================================================
 * AI findings
 *
 * Reshaped by the backend to match engine findings, so the Findings box can show
 * both in one list. Severity on these rows is copied from the matching engine
 * finding — the model supplies the title and explanation, never the rating.
 * ====================================================================== */

export interface AiFinding {
    source: "ai";
    function: Hex;
    function_name: string;
    api: string;
    kind: string;
    detail: string;
    model_confidence: string | null;
    severity: Severity | null;
    base_severity: Severity | null;
    reachable_from_input: boolean | null;
    call_path: { va: Hex; name: string }[];
    sources: string[];
    severity_source: "engine";
    /** False when the model raised something the engine never flagged. A lead,
     *  not a result — and possibly nothing at all. */
    engine_corroborated: boolean;
    model: string | null;
    received_at: string | null;
    /** The decompile version this was reasoned from. */
    derived_from?: string | null;
    /** True when that version has since been replaced by a newer lift. The
     *  finding still stands; its source text has moved on. */
    stale?: boolean;
}

export interface AiFindingsDocument {
    run_id: string;
    findings: AiFinding[];
    job_state: string;
    n8n_configured: boolean;
    note: string;
}

export async function getAiFindings(): Promise<AiFindingsDocument | null> {
    if (mode === "sample") return null;
    const response = await fetch(`${base}/runs/${runId}/ai-findings`, {
        headers: { Accept: "application/json" },
    });
    if (response.status === 404) return null;
    if (!response.ok) throw new Error(`ai-findings → HTTP ${response.status}`);
    return (await response.json()) as AiFindingsDocument;
}

/* ======================================================================
 * Behaviour profile
 *
 * The engine-derived half needs no AI: capabilities are matched from imported API
 * names and referenced strings, and every item carries the evidence behind it. So
 * this works with no n8n at all, and the AI pass only adds prose.
 * ====================================================================== */

export interface CapabilityEvidence {
    va: Hex;
    name: string;
    information_score: number;
    reachable_from_input: boolean;
    api_calls: string[];
    strings: string[];
    explanation: string | null;
}

export interface BehaviourProfile {
    run_id: string;
    kind: "capability-evidence";
    disclaimer: string;
    capabilities: {
        id: string;
        label: string;
        function_count: number;
        reachable_count: number;
        evidence: CapabilityEvidence[];
    }[];
    packed_sections: { name: string; entropy: number; note: string }[];
    ai_explanations_available: boolean;
}

export async function getBehaviourProfile(): Promise<BehaviourProfile | null> {
    if (mode === "sample") return null;
    const response = await fetch(`${base}/runs/${runId}/ai/behaviour-profile`, {
        headers: { Accept: "application/json" },
    });
    if (response.status === 404) return null;
    if (!response.ok) throw new Error(`behaviour-profile → HTTP ${response.status}`);
    return (await response.json()) as BehaviourProfile;
}

/* ======================================================================
 * Binary context  (user-provided)
 * ====================================================================== */

let sampleContext: BinaryContext | null = null;

export const getBinaryContext = () =>
    get<BinaryContext | null>("/context", sampleContext);

export async function saveBinaryContext(context: BinaryContext): Promise<void> {
    if (mode === "sample") {
        sampleContext = context;
        return;
    }
    const response = await fetch(`${base}/runs/${runId}/context`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(context),
    });
    if (!response.ok) throw new Error(`context → HTTP ${response.status}`);
}
