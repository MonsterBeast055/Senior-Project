/*
 * Decompiler.tsx - The n8n seam.
 *
 * Everything in this pane comes from the AI layer, not the C++ engine. The
 * backend forwards a lift request to the n8n webhook, n8n calls the model, and
 * posts the result back. This component owns the whole lifecycle:
 *
 *     not-run  ->  queued  ->  running  ->  done | failed
 *                                             |
 *                                    accepted / rejected
 *
 * The accept/reject step matters more than it looks. Model output is provisional
 * until a human signs off, and an accepted name is meant to flow back into the
 * engine's AnnotationStore and appear in the next export. That is the feedback
 * loop the whole architecture was designed around, and this is where a person
 * closes it.
 */
import { useEffect, useState } from "react";
import { getLifted, requestLift, reviewLift } from "../api/client";
import type { FunctionDetail, LiftState, LiftedFunction } from "../api/types";

interface Props {
    detail: FunctionDetail;
    selectedBlock: string | null;
    onSelectBlock: (va: string) => void;
}

export default function Decompiler({ detail, selectedBlock, onSelectBlock }: Props) {
    const [lifted, setLifted] = useState<LiftedFunction | null>(null);
    const [state, setState] = useState<LiftState>("not-run");
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);

    useEffect(() => {
        let cancelled = false;
        setError(null);
        getLifted(detail.va)
            .then((result) => {
                if (cancelled) return;
                setLifted(result);
                setState(result ? (result.state ?? "done") : "not-run");
            })
            .catch((cause: Error) => !cancelled && setError(cause.message));
        return () => { cancelled = true; };
    }, [detail.va]);

    async function onLift() {
        setBusy(true);
        setError(null);
        try {
            const next = await requestLift(detail.va);
            setState(next);
            // The workflow is asynchronous, so poll rather than assume. A real
            // deployment would prefer a websocket or SSE; polling keeps the
            // backend contract to plain REST.
            if (next === "queued" || next === "running") {
                const timer = window.setInterval(async () => {
                    const result = await getLifted(detail.va);
                    if (result) {
                        setLifted(result);
                        setState(result.state ?? "done");
                        window.clearInterval(timer);
                    }
                }, 2000);
                window.setTimeout(() => window.clearInterval(timer), 120000);
            } else {
                setLifted(await getLifted(detail.va));
            }
        } catch (cause) {
            setError((cause as Error).message);
            setState("failed");
        } finally {
            setBusy(false);
        }
    }

    async function onReview(review: "accepted" | "rejected") {
        setBusy(true);
        try {
            await reviewLift(detail.va, review);
            setLifted((current) => (current ? { ...current, review } : current));
        } catch (cause) {
            setError((cause as Error).message);
        } finally {
            setBusy(false);
        }
    }

    const mapping = new Map<number, string>();
    (lifted?.line_mapping ?? []).forEach((entry) => mapping.set(entry.line, entry.block));

    return (
        <>
            <div className="lift-bar">
                <button className="xp" onClick={onLift} disabled={busy || state === "running"}>
                    {lifted ? "Re-lift" : "Lift with AI"}
                </button>
                <span className={`lift-state ${state}`}>{state}</span>

                {lifted && (
                    <>
                        <div className="sep" />
                        <button
                            className="xp"
                            disabled={busy || lifted.review === "accepted"}
                            onClick={() => onReview("accepted")}
                            title="Accept this name and description into the annotation store"
                        >
                            Accept
                        </button>
                        <button
                            className="xp"
                            disabled={busy || lifted.review === "rejected"}
                            onClick={() => onReview("rejected")}
                        >
                            Reject
                        </button>
                        <span className="dim">{lifted.review}</span>
                    </>
                )}

                <span className="spacer" style={{ flex: 1 }} />
                <span className="dim">
                    {mapping.size > 0 ? "click a line to locate it" : "no line mapping"}
                </span>
            </div>

            {error && (
                <div className="notice">
                    <b>Request failed.</b> {error}
                    <br />
                    Is the backend running? Switch Data to <i>Sample</i> to browse offline.
                </div>
            )}

            {!lifted && !error && (
                <div className="notice">
                    No lifted output for this function yet.
                    <br />
                    <br />
                    Decompiled C is produced by the n8n workflow and stored by the backend.
                    Press <b>Lift with AI</b> to request it, or wait for the batch pass.
                </div>
            )}

            {lifted && (
                <>
                    <div className="notice">
                        <b>{lifted.suggested_name}</b> — AI-generated, confidence{" "}
                        <b>{lifted.confidence}</b>
                        {lifted.model ? `, ${lifted.model}` : ""}.
                        {/* Which lift produced this. A function can be lifted by
                            the automated pass and then again by hand; the newest
                            wins here, and saying which one it is stops "why did
                            this change" being a mystery. */}
                        {lifted.origin && (
                            <span className={`fbsrc ${lifted.origin === "manual" ? "ai" : "engine"}`}
                                  style={{ marginLeft: 5 }}
                                  title={lifted.origin === "manual"
                                      ? "Produced by Lift with AI on this tab"
                                      : "Produced by the automated pass on the AI Analysis tab"}>
                                {lifted.origin}
                            </span>
                        )}
                        <br />
                        {lifted.description}

                        {/* Superseded versions are kept, not deleted: findings were
                            reasoned from specific text, and destroying it would
                            leave them unverifiable. */}
                        {lifted.superseded && lifted.superseded.length > 0 && (
                            <>
                                <br />
                                <span className="dim">
                                    Replaced {lifted.superseded.length} earlier lift
                                    {lifted.superseded.length === 1 ? "" : "s"} (
                                    {lifted.superseded.map((v) => v.origin).join(", ")}
                                    ). Findings made from those still point at them.
                                </span>
                            </>
                        )}
                        {lifted.warnings && lifted.warnings.length > 0 && (
                            <>
                                <br />
                                <br />
                                <b>Validator notes:</b>
                                <ul style={{ margin: "3px 0 0 16px" }}>
                                    {lifted.warnings.map((warning, index) => (
                                        <li key={index}>{warning}</li>
                                    ))}
                                </ul>
                            </>
                        )}
                    </div>

                    <div className="code">
                        {(lifted.c_code ?? []).map((text, index) => {
                            const line = index + 1;
                            const block = mapping.get(line);
                            const highlighted = block != null && block === selectedBlock;
                            return (
                                <div
                                    key={line}
                                    className={`row${highlighted ? " highlight" : ""}`}
                                    onClick={() => block && onSelectBlock(block)}
                                    title={block ? `block ${block}` : undefined}
                                >
                                    <span className="asm-addr">
                                        {String(line).padStart(3, " ")}
                                    </span>
                                    {"  "}
                                    {text}
                                </div>
                            );
                        })}
                    </div>
                </>
            )}
        </>
    );
}
