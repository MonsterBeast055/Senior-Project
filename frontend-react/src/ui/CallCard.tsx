/*
 * CallCard.tsx - What does this call do, without going there.
 *
 * Most of the time the question at a call site is "what is that?", not "take me
 * there". Answering it in place is a better fix for lost context than making
 * navigation easier, because the best navigation is the trip you did not make.
 *
 * Two triggers, one component:
 *
 *   hover  a read-only summary that disappears freely
 *   click  the same card, pinned, with the actions on it
 *
 * That split is not decoration. A button inside a hover-dismissed card is
 * unreachable — the mouse leaves the trigger on its way to the button and the
 * card goes with it. Hovering stays weightless; acting takes a deliberate click.
 */
import { useEffect } from "react";
import type { FunctionSummary } from "../api/types";
import { useFunctionBlurb } from "./useFunctionBlurb";

export interface CallAnchor {
    va: string;
    /** Where the trigger is on screen, so the card can sit beside it. */
    rect: DOMRect;
    pinned: boolean;
}

/** Keeps the card on screen when the call site is near an edge. Measured
 *  against the viewport because the card is positioned fixed — the listing
 *  scrolls underneath it. */
function place(rect: DOMRect) {
    const WIDTH = 330;
    const GAP = 6;
    const left = Math.min(rect.left, window.innerWidth - WIDTH - GAP);
    const below = rect.bottom + GAP;
    // Flip above the line when there is no room beneath it.
    const flip = below + 150 > window.innerHeight;
    return {
        left: Math.max(GAP, left),
        top: flip ? Math.max(GAP, rect.top - 150 - GAP) : below,
        width: WIDTH,
    };
}

export default function CallCard({
    anchor, functions, onOpen, onShowInDecompiler, onDismiss,
}: {
    anchor: CallAnchor | null;
    functions: FunctionSummary[];
    /** Make this the selected function — a real navigation. */
    onOpen: (va: string) => void;
    /** Stay on the current function and go read this call in the C. */
    onShowInDecompiler: (va: string) => void;
    onDismiss: () => void;
}) {
    const va = anchor?.va ?? null;
    const { blurb, pending } = useFunctionBlurb(va);

    /* Escape closes a pinned card. Without it the only way out is a precise
     * click on the small dismiss control, which is a poor deal for something
     * opened by accident. */
    useEffect(() => {
        if (!anchor?.pinned) return;
        const onKey = (event: KeyboardEvent) => {
            if (event.key === "Escape") {
                event.stopPropagation();
                onDismiss();
            }
        };
        window.addEventListener("keydown", onKey, true);
        return () => window.removeEventListener("keydown", onKey, true);
    }, [anchor?.pinned, onDismiss]);

    if (!anchor) return null;

    const summary = functions.find((candidate) => candidate.va === anchor.va);
    const position = place(anchor.rect);

    return (
        <div
            className={`callcard${anchor.pinned ? " pinned" : ""}`}
            style={{ position: "fixed", ...position, zIndex: 60 }}
            // A pinned card must survive the mouse entering it; an unpinned one
            // is dismissed by the trigger's own mouseleave.
            onMouseDown={(event) => event.stopPropagation()}
        >
            <div className="cc-head">
                <b>{summary?.name ?? anchor.va}</b>
                {anchor.pinned && (
                    <span
                        className="cc-x"
                        title="Dismiss (Esc)"
                        onClick={onDismiss}
                    >
                        &times;
                    </span>
                )}
            </div>

            <div className="cc-body">
                {pending && <span className="dim">Looking up the summary&hellip;</span>}

                {!pending && blurb && <span>{blurb}</span>}

                {!pending && !blurb && (
                    <span className="dim">
                        Not decompiled yet. The engine's facts are below; a
                        description appears once the AI pass reaches this function.
                    </span>
                )}
            </div>

            {/* Always shown, and deliberately below the description: these come
                from the engine and are true whether or not a model has run. */}
            {summary && (
                <div className="cc-facts">
                    <span className="mono">{anchor.va}</span>
                    {" · "}{summary.block_count} blocks
                    {" · "}{summary.instruction_count} instructions
                    {summary.information_score !== undefined && (
                        <>{" · "}score {summary.information_score}</>
                    )}
                    {summary.is_library_code && <> · library code</>}
                    {summary.is_thunk && <> · thunk</>}
                </div>
            )}

            {anchor.pinned && (
                <div className="cc-actions">
                    <button
                        className="xp"
                        onClick={() => onOpen(anchor.va)}
                        title="Make this the selected function"
                    >
                        Open
                    </button>
                    {/* Expansion is the Decompiler's, keyed to a line of C. The
                        assembly has no line to hang it on, so this points you at
                        the pane that does rather than duplicating the mechanism. */}
                    <button
                        className="xp"
                        onClick={() => onShowInDecompiler(anchor.va)}
                        title="Switch to the Decompiler, where this call can be expanded in place"
                    >
                        Expand in C
                    </button>
                </div>
            )}

            {!anchor.pinned && (
                <div className="cc-hint dim">click for actions</div>
            )}
        </div>
    );
}
