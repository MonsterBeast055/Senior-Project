/*
 * FindingWindow.tsx - Why is this finding rated the way it is?
 *
 * Two halves, kept visibly separate:
 *
 *   ENGINE FACTS   deterministic. sink kind, reachability, the call path, and
 *                  the engine's own statement of what it did not establish.
 *                  This is where the severity comes from.
 *
 *   AI EXPLANATION optional narrative from n8n. Explains impact and reasoning.
 *                  It cannot change the severity, and the panel says so.
 *
 * That separation is the point. A reviewer must be able to see which parts of
 * this window are derived from analysis and which are a language model's prose.
 */
import { useEffect, useState } from "react";
import { getFindingExplanation, requestFindingExplanation } from "../api/client";
import type { Finding, FindingExplanation, LiftState } from "../api/types";
import { Severity } from "./Chrome";

interface Props {
    finding: Finding;
    onOpenFunction: (va: string) => void;
}

export default function FindingWindow({ finding, onOpenFunction }: Props) {
    const [explanation, setExplanation] = useState<FindingExplanation | null>(null);
    const [state, setState] = useState<LiftState>("not-run");
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);

    useEffect(() => {
        let cancelled = false;
        setError(null);
        getFindingExplanation(finding.function, finding.api)
            .then((result) => {
                if (cancelled) return;
                setExplanation(result);
                setState(result ? (result.state ?? "done") : "not-run");
            })
            .catch((cause: Error) => !cancelled && setError(cause.message));
        return () => { cancelled = true; };
    }, [finding.function, finding.api]);

    async function onExplain() {
        setBusy(true);
        setError(null);
        try {
            const next = await requestFindingExplanation(finding.function, finding.api);
            setState(next);
            if (next === "queued" || next === "running") {
                const timer = window.setInterval(async () => {
                    const result = await getFindingExplanation(finding.function, finding.api);
                    if (result) {
                        setExplanation(result);
                        setState(result.state ?? "done");
                        window.clearInterval(timer);
                    }
                }, 2000);
                window.setTimeout(() => window.clearInterval(timer), 120000);
            } else {
                setExplanation(await getFindingExplanation(finding.function, finding.api));
            }
        } catch (cause) {
            setError((cause as Error).message);
            setState("failed");
        } finally {
            setBusy(false);
        }
    }

    return (
        <div style={{ height: "100%", overflow: "auto" }}>
            {/* --- Engine facts ------------------------------------------- */}
            <table className="grid" style={{ width: "100%" }}>
                <tbody>
                    <tr>
                        <td style={{ width: 120 }} className="dim">Severity</td>
                        <td>
                            <Severity level={finding.severity} />
                            <span className="dim" style={{ marginLeft: 8 }}>
                                derived by the engine from sink kind
                                {finding.reachable_from_input
                                    ? " + reachability"
                                    : " (not reachable, so downgraded from " +
                                      `${finding.base_severity})`}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <td className="dim">Operation</td>
                        <td className="mono">{finding.api}</td>
                    </tr>
                    <tr>
                        <td className="dim">Kind</td>
                        <td>{finding.kind}</td>
                    </tr>
                    <tr>
                        <td className="dim">Function</td>
                        <td>
                            <span className="mono">{finding.function}</span>{" "}
                            <button
                                className="xp"
                                style={{ height: 17 }}
                                onClick={() => onOpenFunction(finding.function)}
                            >
                                open
                            </button>
                        </td>
                    </tr>
                    <tr>
                        <td className="dim">Reachable from</td>
                        <td>
                            {finding.sources.length > 0
                                ? finding.sources.join(", ")
                                : <span className="dim">no known input source</span>}
                        </td>
                    </tr>
                </tbody>
            </table>

            {/* The call path is the evidence for the reachability claim. Without
                it the rating is unverifiable, so it is shown, not hidden. */}
            {finding.call_path.length > 0 && (
                <>
                    <div className="blockhdr">Call path (evidence)</div>
                    <div className="code">
                        {finding.call_path.map((step, index) => (
                            <div
                                key={step.va}
                                className="row"
                                onClick={() => onOpenFunction(step.va)}
                            >
                                {"  ".repeat(index)}
                                {index > 0 ? "└─ " : ""}
                                <span className="asm-addr">{step.va}</span>{"  "}
                                {step.name}
                                {index === 0 && (
                                    <span className="asm-api">  ; reads untrusted input</span>
                                )}
                                {index === finding.call_path.length - 1 && (
                                    <span className="asm-str">  ; performs the operation</span>
                                )}
                            </div>
                        ))}
                    </div>
                </>
            )}

            <div className="notice">
                <b>What this does not establish.</b> {finding.limitation}
            </div>

            {/* --- AI explanation ----------------------------------------- */}
            <div className="lift-bar">
                <button className="xp" onClick={onExplain} disabled={busy || state === "running"}>
                    {explanation ? "Re-explain" : "Explain with AI"}
                </button>
                <span className={`lift-state ${state}`}>{state}</span>
                <span style={{ flex: 1 }} />
                <span className="dim">explains impact — cannot change severity</span>
            </div>

            {error && (
                <div className="notice">
                    <b>Request failed.</b> {error}
                </div>
            )}

            {!explanation && !error && (
                <div className="notice">
                    No AI explanation yet. The facts above come from the engine and are
                    enough to triage; an explanation adds impact and remediation prose for
                    a report.
                </div>
            )}

            {explanation && (
                <div style={{ padding: "4px 6px" }}>
                    <div className="dim" style={{ marginBottom: 6 }}>
                        AI-generated, confidence <b>{explanation.confidence}</b>
                        {explanation.model ? ` · ${explanation.model}` : ""} · severity source:{" "}
                        <b>{explanation.severity_source}</b>
                    </div>

                    <div className="blockhdr">Summary</div>
                    <p style={{ margin: "4px 6px 10px 6px", lineHeight: 1.5 }}>
                        {explanation.summary}
                    </p>

                    <div className="blockhdr">Why this severity</div>
                    <p style={{ margin: "4px 6px 10px 6px", lineHeight: 1.5 }}>
                        {explanation.why_severity}
                    </p>

                    <div className="blockhdr">Impact</div>
                    <p style={{ margin: "4px 6px 10px 6px", lineHeight: 1.5 }}>
                        {explanation.impact}
                    </p>

                    {explanation.preconditions && explanation.preconditions.length > 0 && (
                        <>
                            <div className="blockhdr">
                                Preconditions an attacker still needs
                            </div>
                            <ul style={{ margin: "4px 6px 10px 22px", lineHeight: 1.5 }}>
                                {explanation.preconditions.map((item, index) => (
                                    <li key={index}>{item}</li>
                                ))}
                            </ul>
                        </>
                    )}

                    <div className="blockhdr">Remediation</div>
                    <p style={{ margin: "4px 6px 10px 6px", lineHeight: 1.5 }}>
                        {explanation.remediation}
                    </p>
                </div>
            )}
        </div>
    );
}
