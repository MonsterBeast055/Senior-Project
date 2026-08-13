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
import { useCallback, useEffect, useRef, useState } from "react";
import { getLifted, requestLift, reviewLift } from "../api/client";
import type { FunctionDetail, LiftState, LiftedFunction } from "../api/types";
import CCodeView from "./CCodeView";
import { forgetBlurb } from "./useFunctionBlurb";

interface Props {
    detail: FunctionDetail;
    selectedBlock: string | null;
    onSelectBlock: (va: string) => void;
    /** Opens the window showing what would be sent to the model. Owned by the
     *  view, because it is a floating window like the graph and the xrefs. */
    onShowInput?: () => void;
}

export default function Decompiler({
    detail, selectedBlock, onSelectBlock, onShowInput,
}: Props) {
    const [lifted, setLifted] = useState<LiftedFunction | null>(null);
    const [state, setState] = useState<LiftState>("not-run");
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);
    /** Open expansion points, as `<ownerVa>#<line>`. */
    const [expanded, setExpanded] = useState<Set<string>>(new Set());
    const codeRef = useRef<HTMLDivElement | null>(null);
    /** Set when this pane originates a block selection, so the scroll effect can
     *  ignore the echo. */
    const fromThisPane = useRef(false);

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
            /* What is on screen before the request goes out.
             *
             * Re-lift has to wait for a *different* result, not just any result.
             * The previous version stays stored until the new one arrives — that
             * is deliberate, since findings cite specific text — so a poll that
             * stops at the first truthy response stops immediately on the old
             * output and reports success without anything having changed. */
            const previousVersion = lifted?.version_id ?? null;
            const isNew = (candidate: LiftedFunction) =>
                previousVersion === null || (candidate.version_id ?? null) !== previousVersion;

            const next = await requestLift(detail.va);
            setState(next);
            // The workflow is asynchronous, so poll rather than assume. A real
            // deployment would prefer a websocket or SSE; polling keeps the
            // backend contract to plain REST.
            if (next === "queued" || next === "running") {
                const timer = window.setInterval(async () => {
                    const result = await getLifted(detail.va);
                    if (result && isNew(result)) {
                        setLifted(result);
                        setState(result.state ?? "done");
                        // The hover surfaces cached "no description" for this
                        // address. Leaving it would have the call card still
                        // reporting "not decompiled yet" over fresh output.
                        forgetBlurb(detail.va);
                        window.clearInterval(timer);
                    }
                }, 2000);
                /* Five minutes, not two.
                 *
                 * A free-tier request measured at 1m51s — queued behind paid
                 * traffic rather than slow to compute — which left nine seconds
                 * of margin. Past the ceiling the poll stopped silently while
                 * the result was still coming, so the pane sat on "queued"
                 * forever and the lift looked broken when it had in fact
                 * succeeded. The backend's own dispatch timeout is five minutes;
                 * the pane should not give up first. */
                window.setTimeout(() => {
                    window.clearInterval(timer);
                    setState((current) => {
                        if (current !== "queued" && current !== "running") return current;
                        // Say so rather than leaving it stuck on "queued": the
                        // result may still land, and reopening the function will
                        // show it.
                        setError(
                            "No result after five minutes. The request may still be "
                            + "running — reopen this function to check, or press "
                            + "Re-lift to send it again.",
                        );
                        return "failed";
                    });
                }, 300000);
            } else {
                setLifted(await getLifted(detail.va));
                forgetBlurb(detail.va);
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

    /* --- Expansion -------------------------------------------------------
     * Held here rather than inside the tree so Collapse all is one operation
     * and so switching function starts clean. */
    const toggleExpansion = useCallback((key: string) => {
        setExpanded((current) => {
            const next = new Set(current);
            if (next.has(key)) next.delete(key); else next.add(key);
            return next;
        });
    }, []);

    // Expansions describe lines in a function that is no longer on screen.
    useEffect(() => { setExpanded(new Set()); }, [detail.va]);

    /* --- Highlight sync, decompiler side ---------------------------------
     * Clicking a block in the disassembly already highlighted the matching C
     * line, but on a long function that highlight landed off-screen and the
     * click looked like it had done nothing. The assembly pane has scrolled to
     * meet the decompiler since the beginning; this is the other half.
     *
     * Skipped when this pane caused the selection, otherwise clicking a line
     * makes the view jump under your own cursor. */
    useEffect(() => {
        if (fromThisPane.current) { fromThisPane.current = false; return; }
        if (!selectedBlock || !lifted) return;

        const hit = (lifted.line_mapping ?? []).find((e) => e.block === selectedBlock);
        if (!hit) return;
        const row = document.getElementById(`cline-${hit.line}`);
        const box = codeRef.current;
        if (!row || !box) return;

        // Only when it is actually out of view. Scrolling something already on
        // screen is motion with no information in it.
        const rowRect = row.getBoundingClientRect();
        const boxRect = box.getBoundingClientRect();
        if (rowRect.top >= boxRect.top && rowRect.bottom <= boxRect.bottom) return;
        row.scrollIntoView({ block: "center" });
    }, [selectedBlock, lifted]);

    return (
        <>
            <div className="lift-bar">
                <button className="xp" onClick={onLift} disabled={busy || state === "running"}>
                    {lifted ? "Re-lift" : "Lift with AI"}
                </button>
                <span className={`lift-state ${state}`}>{state}</span>

                {/* Available whether or not anything has been lifted, and whether
                    or not the AI layer is configured: what we would send is worth
                    seeing before deciding to send it. */}
                {onShowInput && (
                    <button
                        className="xp"
                        onClick={onShowInput}
                        title="Show the exact context that would be sent to the model"
                    >
                        Show AI input
                    </button>
                )}

                {/* Nothing to review when the call failed. */}
                {lifted && !lifted.parse_error && (
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

                {/* Only once there is something to collapse. A permanently
                    disabled button teaches nothing. */}
                {expanded.size > 0 && (
                    <button
                        className="xp"
                        onClick={() => setExpanded(new Set())}
                        title="Close every expanded callee"
                    >
                        Collapse all ({expanded.size})
                    </button>
                )}

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

            {/* A stored failure is not output. The AI layer has to post something
                or the batch never settles, so a rate-limited function comes back
                carrying an apology in the summary field. Rendering that through
                the normal header claimed it was AI-generated with medium
                confidence and offered Accept and Reject on it — the tool
                asserting a result it does not have, which is the one thing this
                project is built not to do. */}
            {lifted?.parse_error && (
                <div className="notice">
                    <b>This function was not analysed.</b>
                    <br />
                    {lifted.error ?? lifted.description
                        ?? "The model call did not succeed."}
                    <br />
                    <br />
                    Nothing was produced, so there is nothing to accept or review.
                    Press <b>Re-lift</b> to try this one again, or re-run the
                    automated pass — it retries only the functions that failed.

                    {/* The reply itself, when there was one. Without it every
                        parse failure looks the same, and they need different
                        fixes: an empty completion, a truncated one, and prose
                        instead of JSON are three different problems. */}
                    {(lifted.finish_reason || lifted.raw_excerpt) && (
                        <>
                            <br />
                            <br />
                            <b>What the provider returned</b>
                            {lifted.finish_reason && (
                                <>
                                    {" — stopped because: "}
                                    <span className="mono">{lifted.finish_reason}</span>
                                </>
                            )}
                            {lifted.raw_excerpt ? (
                                <div
                                    className="code"
                                    style={{ maxHeight: 160, overflow: "auto", marginTop: 4 }}
                                >
                                    <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>
                                        {lifted.raw_excerpt}
                                    </pre>
                                </div>
                            ) : (
                                <div className="dim">
                                    The reply was empty — no text at all was returned.
                                </div>
                            )}
                        </>
                    )}
                </div>
            )}

            {lifted && !lifted.parse_error && (
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
                        {/* Stated whether or not it is complete. The prompt asks
                            for every block; this is the only thing that checks,
                            and a silent 100% would be exactly the unverified
                            claim the rest of the tool refuses to make. */}
                        {lifted.coverage && (
                            <>
                                <br />
                                <b>Coverage:</b>{" "}
                                <span
                                    className={lifted.coverage.missing.length === 0
                                        ? "sev informational"
                                        : "sev medium"}
                                >
                                    {lifted.coverage.blocks_covered} of{" "}
                                    {lifted.coverage.blocks_total} blocks
                                </span>
                                {lifted.coverage.missing.length > 0 && (
                                    <span className="dim">
                                        {"  "}unaccounted for:{" "}
                                        <span className="mono">
                                            {lifted.coverage.missing.slice(0, 8).join(", ")}
                                        </span>
                                        {lifted.coverage.missing.length > 8
                                            && ` and ${lifted.coverage.missing.length - 8} more`}
                                        . Either the model skipped them or they were
                                        trimmed from the prompt.
                                    </span>
                                )}
                                {lifted.coverage.unknown.length > 0 && (
                                    <span className="sev high">
                                        {"  "}{lifted.coverage.unknown.length} tag
                                        {lifted.coverage.unknown.length === 1 ? "" : "s"} name a
                                        block this function does not contain — the line mapping
                                        is unreliable.
                                    </span>
                                )}
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

                    <div className="code" ref={codeRef}>
                        <CCodeView
                            ownerVa={detail.va}
                            code={lifted.c_code ?? []}
                            lineMapping={lifted.line_mapping ?? []}
                            callees={detail.callees ?? []}
                            depth={0}
                            ancestors={[]}
                            selectedBlock={selectedBlock}
                            onSelectBlock={(block) => {
                                // The scroll effect must not answer a selection
                                // this pane just made — the line is already under
                                // the pointer.
                                fromThisPane.current = true;
                                onSelectBlock(block);
                            }}
                            shared={{ expanded, onToggle: toggleExpansion }}
                        />
                    </div>
                </>
            )}
        </>
    );
}
