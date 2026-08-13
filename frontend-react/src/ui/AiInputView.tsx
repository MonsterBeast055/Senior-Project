/*
 * AiInputView.tsx - What we actually send the model.
 *
 * Every other conclusion in this tool can be traced to its evidence. The prompt
 * was the exception: a reader had to take on faith that the model was given
 * something reasonable. This shows it.
 *
 * It is built by the same function the dispatcher uses, so this is not a
 * description of the payload — it is the payload. And it does not require the
 * AI layer to be configured, because being able to inspect what *would* be sent
 * is most useful when nothing is being sent at all.
 */
import { useEffect, useState } from "react";
import { getAiPayload, type AiTask } from "../api/client";
import type { AiPayload } from "../api/types";

const TASK_LABEL: Record<AiTask, string> = {
    decompile: "Decompile",
    bugs: "Find bugs",
    behaviour: "Behaviour",
};

/** The one number worth leading with per task. */
const TASK_NOTE: Record<AiTask, string> = {
    decompile:
        "The function's own disassembly, plus one paragraph per callee rather "
        + "than their code. That substitution is what makes per-function analysis "
        + "possible without the whole binary in the prompt.",
    bugs:
        "The engine's findings as established facts, and the route from an input "
        + "source to the risky call. The defect is often in a hop rather than at "
        + "the sink, so the path travels with it.",
    behaviour:
        "The same function context. The capability evidence itself is matched by "
        + "the engine from imports and strings; the model only adds narrative.",
};

function Row({ label, value }: { label: string; value: React.ReactNode }) {
    return (
        <tr>
            <td style={{ whiteSpace: "nowrap" }} className="dim">{label}</td>
            <td>{value}</td>
        </tr>
    );
}

export default function AiInputView({ va, name }: { va: string; name: string }) {
    const [task, setTask] = useState<AiTask>("decompile");
    const [payload, setPayload] = useState<AiPayload | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [raw, setRaw] = useState(false);

    useEffect(() => {
        let cancelled = false;
        setPayload(null);
        setError(null);
        void getAiPayload(task, va)
            .then((next) => { if (!cancelled) setPayload(next); })
            .catch((cause: Error) => { if (!cancelled) setError(cause.message); });
        return () => { cancelled = true; };
    }, [task, va]);

    const s = payload?._summary;

    return (
        <div className="page-inner" style={{ padding: "6px 8px" }}>
            <div className="toolbar" style={{ borderTop: "none" }}>
                {(Object.keys(TASK_LABEL) as AiTask[]).map((id) => (
                    <button
                        key={id}
                        className="xp"
                        disabled={task === id}
                        onClick={() => setTask(id)}
                    >
                        {TASK_LABEL[id]}
                    </button>
                ))}
                <span style={{ flex: 1 }} />
                <button className="xp" onClick={() => setRaw((on) => !on)}>
                    {raw ? "Readable" : "Raw JSON"}
                </button>
            </div>

            <p className="dim" style={{ margin: "6px 0" }}>
                Exactly what would be sent for <b>{name}</b> on the{" "}
                <b>{TASK_LABEL[task].toLowerCase()}</b> pass. {TASK_NOTE[task]}
            </p>

            {error && <div className="notice"><b>Could not build it.</b> {error}</div>}
            {!payload && !error && <div className="empty">Assembling&hellip;</div>}

            {payload && raw && (
                <div className="code" style={{ maxHeight: 420, overflow: "auto" }}>
                    <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>
                        {JSON.stringify(payload, null, 2)}
                    </pre>
                </div>
            )}

            {payload && !raw && (
                <>
                    <table className="grid">
                        <tbody>
                            <Row label="Function" value={
                                <span className="mono">{payload.va} — {name}</span>} />
                            <Row label="Disassembly" value={
                                `${s?.blocks ?? 0} blocks, ${s?.instructions ?? 0} instructions`} />
                            <Row label="Imported calls" value={
                                payload.function?.api_calls?.join(", ") || "none"} />
                            <Row label="Strings" value={
                                payload.function?.referenced_strings?.slice(0, 6).join(" | ")
                                || "none"} />
                            {/* The single most informative number here. A callee with
                                no summary forces the model to reason from an API list
                                instead of a description, so the ratio is a direct
                                measure of how good this prompt is. */}
                            <Row label="Callee summaries" value={
                                <>
                                    {s?.callees_with_summary ?? 0} of {s?.callees ?? 0}
                                    {(s?.callees ?? 0) > (s?.callees_with_summary ?? 0) && (
                                        <span className="dim">
                                            {"  "}— the rest travel as an import list, because
                                            they have not been lifted yet
                                        </span>
                                    )}
                                </>} />
                            <Row label="Engine findings" value={s?.engine_findings ?? 0} />
                            {task === "bugs" && (
                                <Row label="Call path steps" value={s?.call_path_steps ?? 0} />
                            )}
                            <Row label="Your notes on the binary" value={
                                s?.has_user_context ? "included" : "none given"} />
                        </tbody>
                    </table>

                    {payload.callees.length > 0 && (
                        <>
                            <h2>What it calls, as the model sees it</h2>
                            <table className="grid">
                                <tbody>
                                    {payload.callees.map((callee) => (
                                        <tr key={callee.va}>
                                            <td className="mono" style={{ whiteSpace: "nowrap" }}>
                                                {callee.name || callee.va}
                                            </td>
                                            <td>
                                                {callee.summary ?? (
                                                    <span className="dim">
                                                        not lifted yet — imports{" "}
                                                        {callee.api_calls.join(", ") || "nothing"}
                                                    </span>
                                                )}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </>
                    )}

                    {task === "bugs" && (payload.call_path_context?.length ?? 0) > 0 && (
                        <>
                            <h2>Route from the input source</h2>
                            <table className="grid">
                                <tbody>
                                    {payload.call_path_context!.map((step) => (
                                        <tr key={step.va}>
                                            <td className="mono" style={{ whiteSpace: "nowrap" }}>
                                                {step.name || step.va}
                                                {step.is_sink && (
                                                    <span className="sev high">{"  "}sink</span>
                                                )}
                                            </td>
                                            <td>
                                                {step.summary ?? (
                                                    <span className="dim">
                                                        no summary — imports{" "}
                                                        {step.api_calls.join(", ") || "nothing"}
                                                    </span>
                                                )}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                            <p className="dim">
                                Only the sink's code is sent in full; the hops travel as
                                summaries. Seven full disassemblies would reintroduce the
                                size problem this design exists to avoid.
                            </p>
                        </>
                    )}

                    {payload.rules && (
                        <div className="notice">
                            <b>Rules sent with every request.</b> {payload.rules.note}
                        </div>
                    )}
                </>
            )}
        </div>
    );
}
