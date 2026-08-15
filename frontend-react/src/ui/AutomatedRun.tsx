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
import {
    getAiJob, newBatchId, resetAi, startAiBatch, stopAiBatch,
    type AiJob, type AiTask,
} from "../api/client";

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
    /** Opens the hand-picked selection dialog. Owned by the view above. */
    onChooseRun?: () => void;
    /** Opens the payload inspector — what the model is actually given. */
    onShowInput?: () => void;
}

type RunState = "idle" | "running" | "done" | "blocked" | "stopped";

export default function AutomatedRun({
    onMessage, onChooseRun, onShowInput,
}: Props) {
    const [state, setState] = useState<RunState>("idle");
    const [stageIndex, setStageIndex] = useState(-1);
    const [jobs, setJobs] = useState<Record<string, AiJob | null>>({});
    const [error, setError] = useState<string | null>(null);

    // Guards against a second run being started by a double click, and against
    // the poll continuing after the component unmounts.
    const runningRef = useRef(false);

    /* The three stages are one action to the person who pressed the button, so
     * they share an id and the Summary tab shows them as one run. Stage two and
     * three are started from the polling effect, which is why this is a ref: it
     * has to outlive the render that began the run. */
    const batchRef = useRef("");

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

            // A stopped stage is terminal: do not advance to the next one, or
            // Stop would only pause the current stage and start the following.
            if (job.state === "stopped") {
                setState("stopped");
                runningRef.current = false;
                onMessage("Automated analysis stopped.");
                return;
            }

            const settled = job.state === "done" || job.state === "empty"
                || (job.total > 0 && job.done + job.failed >= job.total);
            if (!settled) return;

            if (stageIndex + 1 < STAGES.length) {
                const following = STAGES[stageIndex + 1];
                setStageIndex(stageIndex + 1);
                try {
                    await startAiBatch(following.task, { batch: batchRef.current });
                    // The status bar is the only view of this from another tab,
                    // and the run now continues while you are on one.
                    onMessage(
                        `Automated analysis: ${current.label.toLowerCase()} finished, `
                        + `${following.label.toLowerCase()} started `
                        + `(stage ${stageIndex + 2} of ${STAGES.length}).`,
                    );
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
            batchRef.current = newBatchId();
            const first = await startAiBatch(STAGES[0].task, { batch: batchRef.current });
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

    async function stop() {
        const current = STAGES[stageIndex];
        setState("stopped");
        runningRef.current = false;
        try {
            // Every stage, not just the current one: an earlier stage can still
            // have work in flight if this is a resumed run.
            for (const stage of STAGES) await stopAiBatch(stage.task);
            onMessage(`Automated analysis stopped${current ? ` during ${current.label.toLowerCase()}` : ""}.`);
            await refresh();
        } catch (cause) {
            setError((cause as Error).message);
        }
    }

    async function reset() {
        // Destructive and not obviously so from the label, so it is confirmed.
        const totalStored = STAGES.reduce((sum, s) => sum + (jobs[s.task]?.done ?? 0), 0);
        const confirmed = window.confirm(
            `Delete every AI result for this run?\n\n`
            + `${totalStored} stored result${totalStored === 1 ? "" : "s"} across all three `
            + `stages will be removed, including any you accepted. The engine's own `
            + `analysis — functions, graphs, findings — is not touched.`,
        );
        if (!confirmed) return;

        setError(null);
        try {
            await resetAi();
            setState("idle");
            setStageIndex(-1);
            runningRef.current = false;
            setJobs({});
            await refresh();
            onMessage("AI results cleared. Start automated analysis to run again.");
        } catch (cause) {
            setError((cause as Error).message);
        }
    }

    const totalDone = STAGES.reduce((sum, s) => sum + (jobs[s.task]?.done ?? 0), 0);
    const totalFailed = STAGES.reduce((sum, s) => sum + (jobs[s.task]?.failed ?? 0), 0);
    const totalWork = STAGES.reduce((sum, s) => sum + (jobs[s.task]?.total ?? 0), 0);
    /* Settled, not succeeded.
     *
     * The bar tracked `done` alone, so a run that finished with one failure sat
     * at 20 of 21 with nothing to say why — and it could never reach the end,
     * because the twenty-first function was never going to succeed. A stage is
     * complete when every item has stopped moving; the failures are then
     * reported separately rather than hidden as missing progress. */
    const totalSettled = totalDone + totalFailed;
    const overall = totalWork > 0 ? Math.round((totalSettled / totalWork) * 100) : 0;

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
                     : state === "stopped" ? "Resume"
                     : "Automated analysis by engine"}
                </button>

                {/* The engine's ranking is a default, not a monopoly. Someone who
                    has read the findings usually knows better than the score. */}
                {onChooseRun && (
                    <button
                        className="xp"
                        disabled={state === "running"}
                        onClick={onChooseRun}
                        title="Pick the functions yourself, with a depth for their callees"
                    >
                        By choice…
                    </button>
                )}

                {/* Beside the run buttons because both answer questions about the
                    run itself: what went in, and what came of it. */}
                {onShowInput && (
                    <button
                        className="xp"
                        onClick={onShowInput}
                        title="The exact bundle sent to the model for a function"
                    >
                        What gets sent…
                    </button>
                )}

                {/* Only while there is something to stop. */}
                {state === "running" && (
                    <button
                        className="xp"
                        onClick={() => void stop()}
                        title="Stop dispatching. Requests already sent are still recorded when they return."
                    >
                        Stop
                    </button>
                )}

                <span style={{ flex: 1 }} />

                <button
                    className="xp"
                    onClick={() => void reset()}
                    disabled={state === "running" || totalDone === 0}
                    title={totalDone === 0
                        ? "Nothing to clear"
                        : "Delete every stored AI result for this run and start from zero"}
                >
                    Reset
                </button>
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
                        {totalFailed > 0 && (
                            <span className="sev high">
                                {"  "}{totalFailed} failed
                            </span>
                        )}
                        {totalFailed > 0 && (
                            <span>
                                {"  "}— press <b>Start automated analysis</b> again to
                                retry only those.
                            </span>
                        )}
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

            {state === "stopped" && (
                <div className="notice" style={{ marginTop: 8 }}>
                    <b>Stopped.</b> Everything completed so far is kept. Press{" "}
                    <b>Resume</b> to carry on from here — finished functions are not
                    paid for twice — or <b>Reset</b> to clear the lot and start over.
                </div>
            )}

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
