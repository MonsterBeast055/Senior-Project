/*
 * AutomatedRun.tsx - One click, the whole pipeline.
 *
 * The only mode on the AI Analysis tab. Per-function AI work lives on the Analysis
 * tab as `Lift with AI`, where the function you are asking about is already on
 * screen; duplicating it here as a second dashboard meant two routes to one action.
 *
 * The stage order is not cosmetic. Decompile has to finish before Find bugs,
 * because bug hunting reads the summaries decompilation produced — a callee with
 * no summary makes the model reason from an API list instead of a description.
 * Running them together would waste the first pass entirely. Behaviour is last
 * only because it is the cheapest to refresh and reads best as a conclusion.
 *
 * Stages advance on completion, not on a timer. A stage is done when its job
 * reports every queued item finished or failed; a failure does not stop the run,
 * because one unluckily-timed model refusal should not cost you the other 39.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { getAiJob, startAiBatch, type AiJob, type AiTask } from "../api/client";

interface Stage {
    task: AiTask;
    label: string;
    detail: string;
}

const STAGES: Stage[] = [
    {
        task: "decompile",
        label: "Lift functions to C",
        detail:
            "Bottom-up, leaves first, so each function's prompt carries summaries "
            + "of what it calls rather than their disassembly.",
    },
    {
        task: "bugs",
        label: "Hunt for defects",
        detail:
            "Engine-flagged functions first. Each prompt carries the call path from "
            + "the input source, because the missing bounds check may be in any step.",
    },
    {
        task: "behaviour",
        label: "Describe capabilities",
        detail:
            "Adds narrative to the capability evidence the engine already matched "
            + "from imports and strings.",
    },
];

interface Props {
    onMessage: (text: string) => void;
}

type RunState = "idle" | "running" | "done" | "blocked";

export default function AutomatedRun({ onMessage }: Props) {
    const [state, setState] = useState<RunState>("idle");
    const [stageIndex, setStageIndex] = useState(-1);
    const [jobs, setJobs] = useState<Record<string, AiJob | null>>({});
    const [error, setError] = useState<string | null>(null);

    // Guards against a second run being started by a double click, and against
    // the poll continuing after the component unmounts.
    const runningRef = useRef(false);

    const refresh = useCallback(async () => {
        const next: Record<string, AiJob | null> = {};
        for (const stage of STAGES) {
            try {
                next[stage.task] = await getAiJob(stage.task);
            } catch {
                next[stage.task] = null;
            }
        }
        setJobs(next);
        return next;
    }, []);

    useEffect(() => { void refresh(); }, [refresh]);

    /* Poll while a stage is in flight, and advance when it settles. */
    useEffect(() => {
        if (state !== "running") return;
        const timer = window.setInterval(async () => {
            const current = STAGES[stageIndex];
            if (!current) return;
            const next = await refresh();
            const job = next[current.task];
            if (!job) return;

            const settled = job.state === "done" || job.state === "empty"
                || (job.total > 0 && job.done + job.failed >= job.total);
            if (!settled) return;

            if (stageIndex + 1 < STAGES.length) {
                setStageIndex(stageIndex + 1);
                try {
                    await startAiBatch(STAGES[stageIndex + 1].task, {});
                } catch (cause) {
                    setError((cause as Error).message);
                    setState("done");
                    runningRef.current = false;
                }
            } else {
                setState("done");
                runningRef.current = false;
                onMessage("Automated analysis finished.");
            }
        }, 1500);
        return () => window.clearInterval(timer);
    }, [state, stageIndex, refresh, onMessage]);

    async function start() {
        if (runningRef.current) return;
        runningRef.current = true;
        setError(null);
        setStageIndex(0);
        setState("running");
        try {
            const first = await startAiBatch(STAGES[0].task, {});
            setJobs((current) => ({ ...current, [STAGES[0].task]: first }));

            // Without n8n the batch still selects and queues, but nothing can be
            // sent. Reporting that up front is better than three stages that each
            // sit at zero for a while and then quietly finish.
            if (first.n8n_configured === false) {
                setState("blocked");
                runningRef.current = false;
                return;
            }
            onMessage(`Automated analysis started on ${first.total} functions.`);
        } catch (cause) {
            setError((cause as Error).message);
            setState("idle");
            runningRef.current = false;
        }
    }

    const totalDone = STAGES.reduce((sum, s) => sum + (jobs[s.task]?.done ?? 0), 0);
    const totalWork = STAGES.reduce((sum, s) => sum + (jobs[s.task]?.total ?? 0), 0);
    const overall = totalWork > 0 ? Math.round((totalDone / totalWork) * 100) : 0;

    return (
        <div className="autorun">
            <p className="dim">
                Runs all three passes in order with no further input. Scope is chosen
                by the backend from the engine's own signals — triage score, library
                classification, and which functions the static analysis already
                flagged. Stage order matters: bug hunting reads the summaries that
                lifting produces, so running them together would waste the first pass.
            </p>

            <div className="toolbar" style={{ borderTop: "none" }}>
                <button
                    className="xp"
                    disabled={state === "running"}
                    onClick={() => void start()}
                >
                    {state === "running" ? "Running…"
                     : state === "done" ? "Run again"
                     : "Start automated analysis"}
                </button>
                <span style={{ flex: 1 }} />
                <button className="xp" onClick={() => void refresh()} disabled={state === "running"}>
                    Refresh
                </button>
            </div>

            {state === "blocked" && (
                <div className="notice">
                    <b>Selected, but nothing could be sent.</b> The backend chose the
                    functions and is holding them, but{" "}
                    <span className="mono">N8N_WEBHOOK_URL</span> is not set in{" "}
                    <span className="mono">backend/.env</span>, so there is no AI layer
                    to send them to. Everything below shows what <i>would</i> run.
                </div>
            )}

            {error && (
                <div className="notice"><b>Failed.</b> {error}</div>
            )}

            {totalWork > 0 && (
                <>
                    <div className="progress" style={{ marginTop: 8 }}>
                        <div className="fill" style={{ width: `${overall}%` }} />
                    </div>
                    <p className="dim" style={{ margin: "3px 0 0 0" }}>
                        {totalDone} of {totalWork} across all stages
                    </p>
                </>
            )}

            <ul className="steplist" style={{ marginTop: 10 }}>
                {STAGES.map((stage, index) => {
                    const job = jobs[stage.task];
                    const status =
                        state === "idle" ? "pending"
                        : index < stageIndex ? "done"
                        : index === stageIndex ? (state === "done" ? "done" : "active")
                        : "pending";
                    return (
                        <li key={stage.task} className={status}>
                            <span className="mark">
                                {status === "done" ? "✓" : status === "active" ? "→" : "·"}
                            </span>
                            <b>{stage.label}</b>
                            {job && job.total > 0 && (
                                <span className="dim">
                                    {"  "}{job.done}/{job.total}
                                    {job.failed > 0 && (
                                        <span className="sev high"> {job.failed} failed</span>
                                    )}
                                </span>
                            )}
                            <div className="dim" style={{ marginLeft: 18 }}>
                                {stage.detail}
                            </div>
                        </li>
                    );
                })}
            </ul>

            {state === "done" && (
                <div className="notice" style={{ marginTop: 8 }}>
                    <b>Finished.</b> Results are in the Findings box on the left and in
                    the Decompile and Behaviour panes. Nothing is lost on reload —
                    every result is stored with the run.
                </div>
            )}
        </div>
    );
}
