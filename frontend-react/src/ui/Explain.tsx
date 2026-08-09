/*
 * Explain.tsx - "How did you decide that?"
 *
 * Hover any derived number and this shows the arithmetic behind it, using that
 * row's real values rather than a generic description of the algorithm.
 *
 * The reason this exists is the same reason the engine carries provenance on
 * every fact. A tool that says "score 74" or "severity high" and cannot show its
 * working is asking to be trusted. One that shows `3 APIs × 7 = 21` is making a
 * claim you can check — and disagree with, which is more useful still.
 *
 * A hover panel rather than a tooltip: `title` gives no formatting, truncates,
 * and takes a second to appear. This is instant, laid out, and readable.
 */
import { useLayoutEffect, useRef, useState, type ReactNode } from "react";

interface Props {
    title: string;
    children: ReactNode;
    /** The element that triggers the popup. */
    anchor: ReactNode;
    /** Extra classes for the wrapping span, so callers can control layout. */
    className?: string;
}

const PANEL_WIDTH = 320;
const GAP = 4;

export default function Explain({ title, children, anchor, className }: Props) {
    const [open, setOpen] = useState(false);
    const [pos, setPos] = useState<{ left: number; top: number } | null>(null);
    const hostRef = useRef<HTMLSpanElement>(null);
    const panelRef = useRef<HTMLDivElement>(null);

    /* Positioned `fixed` against the viewport, not `absolute` against the row.
     *
     * Every place this is used sits inside a scrolling panel — the symbol tree and
     * the findings list both live in `.panel > .body { overflow: auto }`. An
     * absolutely positioned child of a scroll container is clipped by it, so the
     * popup would have been cut off at the panel edge, which in a 300px column
     * means showing about a third of it.
     *
     * Fixed positioning escapes the clip, at the cost of having to place it by
     * hand. Both axes are clamped to the viewport: the left column is at x≈0, so
     * a right-aligned panel would hang off the left edge, and rows near the bottom
     * would open a 250px panel below the fold. */
    useLayoutEffect(() => {
        if (!open || !hostRef.current) return;
        const box = hostRef.current.getBoundingClientRect();
        const height = panelRef.current?.offsetHeight ?? 240;

        let left = box.right - PANEL_WIDTH;
        if (left < GAP) left = GAP;
        if (left + PANEL_WIDTH > window.innerWidth - GAP) {
            left = window.innerWidth - PANEL_WIDTH - GAP;
        }

        let top = box.bottom + GAP;
        if (top + height > window.innerHeight - GAP) {
            // Flip above; if it does not fit there either, pin to the top edge
            // rather than letting it run off screen.
            top = Math.max(GAP, box.top - height - GAP);
        }
        setPos({ left, top });
    }, [open]);

    return (
        <span
            ref={hostRef}
            className={`explain-host${className ? ` ${className}` : ""}`}
            onMouseEnter={() => setOpen(true)}
            onMouseLeave={() => { setOpen(false); setPos(null); }}
        >
            {anchor}
            {open && (
                <div
                    ref={panelRef}
                    className="explain-pop"
                    style={{
                        left: pos?.left ?? -9999,
                        top: pos?.top ?? -9999,
                        // Hidden for the first paint, before the measurement runs.
                        // Otherwise the panel flashes at the wrong place.
                        visibility: pos ? "visible" : "hidden",
                    }}
                    // The popup sits inside a clickable row. Without this, moving
                    // the mouse onto the panel counts as clicking the row.
                    onClick={(event) => event.stopPropagation()}
                >
                    <div className="explain-title">{title}</div>
                    <div className="explain-body">{children}</div>
                </div>
            )}
        </span>
    );
}

/** One line of a derivation: a label, a value, and optionally what it contributed. */
export function ExplainRow({
    label, value, note, strong,
}: {
    label: ReactNode;
    value: ReactNode;
    note?: ReactNode;
    strong?: boolean;
}) {
    return (
        <div className={`explain-row${strong ? " strong" : ""}`}>
            <span className="el">{label}</span>
            <span className="ev">{value}</span>
            {note && <span className="en">{note}</span>}
        </div>
    );
}
