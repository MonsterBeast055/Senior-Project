/*
 * SummaryView.tsx - Process tracking. What has been run, on what, and how it went.
 *
 * The table is built from the binary's function list, not from the jobs, so it
 * is populated the moment a run is loaded and before anything has been sent to
 * a model. That ordering is the point: a tracking view that stays empty until
 * you use it cannot tell you what is left to do, which is most of what it is
 * for. Every function is a row from the start; the ticks fill in.
 *
 * Three columns, one per pass, and a fourth saying how the function came to be
 * run - on its own, as part of a hand-picked batch, or by the engine's own
 * selection. That last column is the difference between "this was analysed" and
 * "I chose to analyse this", which matters when reading back a session.
 *
 * The stage strip above the table marks the pass with work in flight. It polls
 * only while something is outstanding, and stops on its own when the run
 * settles - a table nobody is watching should not be generating requests.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
    getRunSummary, type AiTask, type RunSummary, type SummaryRow,
} from "../api/client";

const COLUMNS: { task: AiTask; label: string }[] = [
    { task: "decompile", label: "Decompiler" },
    { task: "bugs", label: "Find bugs" },
    { task: "behaviour", label: "Explainability" },
];

const KIND_LABEL: Record<string, string> = {
    automated: "Automated",
    batch: "Batch",
    single: "Single",
    unknown: "Earlier run",
};

/* One glyph per outcome. A tick and a cross are the two the eye reads without
 * thinking, so the states that are neither get their own mark rather than being
 * rounded into one - "still waiting" is not a failure, and "never asked" is not
 * one either. */
const CELL: Record<string, { glyph: string; cls: string; title: string }> = {
    done:    { glyph: "✓", cls: "cell-ok",   title: "Done — the result was produced and stored" },
    issues:  { glyph: "✓", cls: "cell-ok",   title: "Done — the model reported something" },
    clean:   { glyph: "✓", cls: "cell-ok",   title: "Done — the bug pass looked and reported no defects" },
    failed:  { glyph: "✗", cls: "cell-bad",  title: "Failed — the reply could not be used" },
    waiting: { glyph: "…", cls: "cell-wait", title: "Sent, waiting for the reply" },
    queued:  { glyph: "·", cls: "cell-wait", title: "Queued, not yet sent" },
    skipped: { glyph: "—", cls: "cell-none", title: "Not asked for in this run" },
    none:    { glyph: "—", cls: "cell-none", title: "Never run for this function" },
};

const POLL_MS = 2000;

/* This binary has 1,314 analysable functions. Rendering every one is eight
 * thousand table cells re-rendered on every poll, for a list nobody scrolls to
 * the end of. The cap is on what is drawn, never on what is counted - the
 * totals above the table are always over the whole set - and the filter
 * reaches past it. */
const MAX_ROWS = 300;

function Cell({ row, task }: { row: SummaryRow; task: AiTask }) {
    const cell = row.tasks?.[task];
    const mark = CELL[cell?.state ?? "none"] ?? CELL.none;
    return (
        <td
            className={`cell ${mark.cls}`}
            title={cell?.error ? `${mark.title}: ${cell.error}` : mark.title}
        >
            {mark.glyph}
            {cell?.state === "issues" && cell.issues ? (
                <span className="dim">{"  "}{cell.issues}</span>
            ) : null}
        </td>
    );
}

export default function SummaryView({ onMessage, onOpenFunction }: {
    onMessage: (text: string) => void;
    /** Jumping from a row to the function is the point of having the row. */
    onOpenFunction?: (va: string) => void;
}) {
    const [data, setData] = useState<RunSummary | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [filter, setFilter] = useState("");
    const [onlyRun, setOnlyRun] = useState(false);
    /* Which narratives are open. A description is a paragraph, and thirty of
     * them inline would bury the grid the table exists to be. */
    const [open, setOpen] = useState<Set<string>>(new Set());
    /* Kept out of state: it decides whether to schedule the next poll, and
     * putting it in state would make every tick a render. */
    const activeRef = useRef(false);

    const reload = useCallback(async () => {
        try {
            const next = await getRunSummary();
            setData(next);
            activeRef.current = next.stages.some((s) => s.active);
            setError(null);
        } catch (cause) {
            setError((cause as Error).message);
            activeRef.current = false;
        }
    }, []);

    useEffect(() => { void reload(); }, [reload]);

    /* Poll only while a pass has work in flight. The interval is rebuilt on
     * every tick rather than run continuously, so it stops by itself when the
     * run settles instead of polling an idle backend forever. */
    useEffect(() => {
        const timer = window.setInterval(() => {
            if (activeRef.current) void reload();
        }, POLL_MS);
        return () => window.clearInterval(timer);
    }, [reload]);

    const rows = data?.rows ?? [];

    const matching = useMemo(() => {
        const needle = filter.trim().toLowerCase();
        return rows.filter((row) => {
            if (onlyRun && !row.kind) return false;
            if (!needle) return true;
            return row.name.toLowerCase().includes(needle)
                || row.va.toLowerCase().includes(needle);
        });
    }, [rows, filter, onlyRun]);

    /* Anything already run is always drawn, however low it scores: it is the
     * part of the table that is actually reporting something, and burying a
     * result under the cap would defeat the tracking. */
    const shown = useMemo(() => {
        if (matching.length <= MAX_ROWS) return matching;
        const run = matching.filter((r) => r.kind);
        const rest = matching.filter((r) => !r.kind);
        return [...run, ...rest.slice(0, Math.max(0, MAX_ROWS - run.length))];
    }, [matching]);

    const totals = useMemo(() => {
        let done = 0;
        let failed = 0;
        let outstanding = 0;
        let touched = 0;
        for (const row of rows) {
            if (row.kind) touched++;
            for (const column of COLUMNS) {
                const state = row.tasks?.[column.task]?.state;
                if (state === "issues" || state === "clean") done++;
                else if (state === "failed") failed++;
                else if (state === "waiting" || state === "queued") outstanding++;
            }
        }
        return { done, failed, outstanding, touched };
    }, [rows]);

    /* Everything that did not come back cleanly, with the reason in full.
     *
     * This is what the separate outcome window was for. The reason lived only
     * in a tooltip here, which is unreadable and unprintable, so it moved to a
     * list under the table where it can be read without hovering. */
    const problems = useMemo(() => {
        const out: { va: string; name: string; task: AiTask; state: string; error: string | null }[] = [];
        for (const row of rows) {
            for (const column of COLUMNS) {
                const cell = row.tasks?.[column.task];
                if (!cell) continue;
                if (cell.state === "failed" || cell.state === "waiting") {
                    out.push({
                        va: row.va, name: row.name, task: column.task,
                        state: cell.state, error: cell.error,
                    });
                }
            }
        }
        return out;
    }, [rows]);

    function toggle(va: string) {
        setOpen((current) => {
            const next = new Set(current);
            if (next.has(va)) next.delete(va); else next.add(va);
            return next;
        });
    }

    return (
        <div className="summarypage">
            <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
                <h1 style={{ margin: 0 }}>Summary</h1>
                <span style={{ flex: 1 }} />
                <button className="xp" onClick={() => void reload()}>Refresh</button>
            </div>

            <p className="dim" style={{ marginTop: 6 }}>
                Every function the engine found, and what each AI pass has done with
                it. A tick means that pass produced a usable result — including one
                that reported nothing, which is an answer rather than a gap. Where a
                function has a <b>+</b>, the behaviour pass described it: open it to
                read what the model said.
            </p>

            {/* The stage strip. Bold is "work in flight right now", which is why
                it is derived from outstanding requests rather than from the job's
                stored state: a job file still saying "running" after a restart
                has nothing in flight, and bolding it would point at a stage that
                is not happening. */}
            <div className="stagestrip">
                {COLUMNS.map((column) => {
                    const stage = data?.stages.find((s) => s.task === column.task);
                    const active = !!stage?.active;
                    return (
                        <span
                            key={column.task}
                            className={`stage${active ? " running" : ""}`}
                            title={active ? "Running now" : undefined}
                        >
                            {active ? <b>{column.label}</b> : column.label}
                            {stage && stage.total > 0 && (
                                <span className="dim">
                                    {"  "}{stage.done}/{stage.total}
                                    {stage.failed > 0 && (
                                        <span className="sev high"> {stage.failed} failed</span>
                                    )}
                                </span>
                            )}
                        </span>
                    );
                })}
            </div>

            {error && <div className="notice"><b>Could not load.</b> {error}</div>}

            <div className="toolbar">
                <input
                    className="xp"
                    placeholder="Filter by name or address"
                    value={filter}
                    onChange={(event) => setFilter(event.target.value)}
                    style={{ minWidth: 220 }}
                />
                <label className="dim" style={{ display: "flex", alignItems: "center", gap: 4 }}>
                    <input
                        type="checkbox"
                        checked={onlyRun}
                        onChange={() => setOnlyRun((v) => !v)}
                    />
                    only functions that have been run
                </label>
                <span style={{ flex: 1 }} />
                <span className="dim">
                    {totals.touched} of {rows.length} touched · {totals.done} passes done
                    {totals.failed > 0 && (
                        <span className="sev high">{"  "}{totals.failed} failed</span>
                    )}
                    {totals.outstanding > 0 && <>{"  "}· {totals.outstanding} outstanding</>}
                </span>
            </div>

            {/* Rendered even when there is nothing in it. The headings are half
                the information: they say which passes exist and what the table
                will show once something has been run. */}
            <table className="grid runlog">
                <thead>
                    <tr>
                        <th>Function</th>
                        <th>Address</th>
                        {COLUMNS.map((c) => <th key={c.task}>{c.label}</th>)}
                        <th>Run as</th>
                    </tr>
                </thead>
                <tbody>
                    {shown.map((row) => [
                        <tr key={row.va}>
                            <td>
                                {/* Only where there is something to open. A
                                    toggle that expands nothing is a promise the
                                    table cannot keep. */}
                                {row.narrative ? (
                                    <button
                                        className="linkish"
                                        onClick={() => toggle(row.va)}
                                        title={open.has(row.va)
                                            ? "Hide what the model said about this function"
                                            : "Show what the model said about this function"}
                                    >
                                        {open.has(row.va) ? "−" : "+"}
                                    </button>
                                ) : <span className="notoggle" />}
                                <span
                                    className={onOpenFunction ? "crumb" : undefined}
                                    onClick={() => {
                                        if (!onOpenFunction) return;
                                        onOpenFunction(row.va);
                                        onMessage(`Opened ${row.name}.`);
                                    }}
                                    title={onOpenFunction ? "Open this function" : undefined}
                                >
                                    {row.name}
                                </span>
                                {row.excluded && (
                                    <span className="dim" title="A thunk, imported stub or library function — never selected automatically">
                                        {"  "}excluded
                                    </span>
                                )}
                            </td>
                            <td className="mono dim">{row.va}</td>
                            {COLUMNS.map((c) => (
                                <Cell key={c.task} row={row} task={c.task} />
                            ))}
                            <td className={row.kind ? undefined : "dim"}>
                                {row.kind ? (KIND_LABEL[row.kind] ?? row.kind) : "—"}
                            </td>
                        </tr>,
                        /* The behaviour pass's own words, verbatim. Reachable
                           here for every function it ran on, including the ones
                           that match no capability rule and so never appear in
                           the profile. */
                        open.has(row.va) && row.narrative ? (
                            <tr key={`${row.va}-narrative`} className="narrative">
                                <td colSpan={3 + COLUMNS.length}>
                                    <span className="dim">Model description:</span>{" "}
                                    {row.narrative}
                                </td>
                            </tr>
                        ) : null,
                    ])}
                </tbody>
            </table>

            {data && rows.length === 0 && (
                <div className="empty">
                    No functions in this run yet. Upload a binary and analyse it, and
                    every function it finds appears here.
                </div>
            )}
            {data && rows.length > 0 && shown.length === 0 && (
                <div className="empty">
                    Nothing matches that filter.
                </div>
            )}
            {shown.length < matching.length && (
                <p className="dim" style={{ margin: "4px 0 0 0" }}>
                    Showing {shown.length} of {matching.length} — everything already
                    run, then the highest-scoring of the rest. Use the filter to
                    reach a specific function.
                </p>
            )}
            {!data && !error && <div className="empty">Reading&hellip;</div>}

            {/* What did not come back, in words. Replaces the outcome window,
                which read the same data through a second component. */}
            {problems.length > 0 && (
                <>
                    <h2 style={{ marginTop: 14 }}>
                        Needs attention
                        <span className="dim" style={{ fontWeight: "normal" }}>
                            {"  "}{problems.length}
                        </span>
                    </h2>
                    <table className="grid">
                        <thead>
                            <tr>
                                <th>Function</th>
                                <th>Pass</th>
                                <th>What happened</th>
                            </tr>
                        </thead>
                        <tbody>
                            {problems.map((problem) => (
                                <tr key={`${problem.va}-${problem.task}`}>
                                    <td>
                                        <span
                                            className={onOpenFunction ? "crumb" : undefined}
                                            onClick={() => onOpenFunction?.(problem.va)}
                                        >
                                            {problem.name}
                                        </span>
                                        <span className="mono dim">{"  "}{problem.va}</span>
                                    </td>
                                    <td>
                                        {COLUMNS.find((c) => c.task === problem.task)?.label}
                                    </td>
                                    <td>
                                        <span className={problem.state === "failed" ? "sev high" : "sev medium"}>
                                            {problem.state === "failed" ? "failed" : "no reply yet"}
                                        </span>
                                        {"  "}
                                        {/* Verbatim. A paraphrase of a model failure is
                                            one more thing that can be wrong. */}
                                        <span className="dim">
                                            {problem.error
                                                || (problem.state === "waiting"
                                                    ? "Sent to the AI layer, still outstanding. "
                                                      + "Requests are given five minutes before the "
                                                      + "run gives up on them."
                                                    : "No reason was recorded.")}
                                        </span>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </>
            )}

            {/* Spelled out because this table is the part of the tool most likely
                to be printed into the report, where colour says nothing. */}
            <div className="tree-legend" style={{ marginTop: 8 }}>
                <span><span className="cell-ok">✓</span> done</span>
                <span><span className="cell-bad">✗</span> failed</span>
                <span><span className="cell-wait">…</span> sent, no reply</span>
                <span><span className="cell-wait">·</span> queued</span>
                <span><span className="cell-none">—</span> not run</span>
            </div>
        </div>
    );
}
