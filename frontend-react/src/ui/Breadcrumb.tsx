/*
 * Breadcrumb.tsx - Where you have been, and how to get back.
 *
 * The trail is the path you actually clicked, not the program's call structure.
 * Those are different questions — "how did I get here" versus "what is this in
 * service of" — and conflating them makes both answers wrong. The call-graph
 * view is a separate thing.
 *
 * What makes this worth more than IDA's jump list is the hover. A trail of
 * `sub_140002500 › sub_140004a10 › sub_140001c88` is unreadable as names; it is
 * perfectly readable as descriptions, and this project is the rare one that has
 * a description for every function.
 */
import type { FunctionSummary } from "../api/types";
import { useFunctionBlurb } from "./useFunctionBlurb";

/** Enough to see the shape of a descent without wrapping onto a second line.
 *  Older entries stay reachable through Back; they are not lost, just not
 *  drawn. */
const VISIBLE = 5;

function Crumb({
    va, name, current, onJump,
}: {
    va: string;
    name: string;
    current: boolean;
    onJump: () => void;
}) {
    const { blurb } = useFunctionBlurb(va);
    return (
        <span
            className={`crumb${current ? " current" : ""}`}
            onClick={current ? undefined : onJump}
            // Native tooltip rather than a popup: this is a hint, and a second
            // floating surface competing with the call card would be noise.
            title={blurb ? `${va}\n\n${blurb}` : `${va}\n\n(not decompiled yet)`}
        >
            {name}
        </span>
    );
}

export default function Breadcrumb({
    trail, index, functions, onJump, onBack, onForward, onPinRoot, rootPinned,
}: {
    /** Addresses, oldest first. */
    trail: string[];
    /** Position within `trail`. Entries after it are the forward history. */
    index: number;
    functions: FunctionSummary[];
    onJump: (index: number) => void;
    onBack: () => void;
    onForward: () => void;
    /** Mark the current function as the thing being investigated. */
    onPinRoot: () => void;
    rootPinned: boolean;
}) {
    if (trail.length === 0) return null;

    const nameOf = (va: string) =>
        functions.find((candidate) => candidate.va === va)?.name ?? va;

    // Only the path up to where you are. Forward entries are reachable with the
    // forward button but do not belong in a trail of where you have been.
    const walked = trail.slice(0, index + 1);
    const shown = walked.slice(-VISIBLE);
    const hidden = walked.length - shown.length;

    return (
        <div className="crumbs">
            <button
                className="xp crumbnav"
                onClick={onBack}
                disabled={index <= 0}
                title="Back (Alt+Left, or Esc)"
            >
                &#8592;
            </button>
            <button
                className="xp crumbnav"
                onClick={onForward}
                disabled={index >= trail.length - 1}
                title="Forward (Alt+Right)"
            >
                &#8594;
            </button>

            <span className="crumbsep">|</span>

            {hidden > 0 && (
                <>
                    <span
                        className="crumb dim"
                        title={`${hidden} earlier ${hidden === 1 ? "step" : "steps"}`}
                    >
                        &hellip;
                    </span>
                    <span className="crumbsep">&rsaquo;</span>
                </>
            )}

            {shown.map((va, position) => {
                const absolute = hidden + position;
                return (
                    <span key={`${va}-${absolute}`}>
                        <Crumb
                            va={va}
                            name={nameOf(va)}
                            current={absolute === index}
                            onJump={() => onJump(absolute)}
                        />
                        {position < shown.length - 1 && (
                            <span className="crumbsep">&rsaquo;</span>
                        )}
                    </span>
                );
            })}

            <span style={{ flex: 1 }} />

            {/* Pins whatever is current. The trail says how you got here; this
                says what you are here for, and the two are answered by different
                machinery — clicks versus the call graph. */}
            <button
                className="xp crumbnav"
                onClick={onPinRoot}
                disabled={index < 0}
                title={rootPinned
                    ? "Pin this function as the root instead"
                    : "Pin this function as the root you are investigating"}
                style={{ minWidth: 48 }}
            >
                {rootPinned ? "Repin" : "Pin"}
            </button>
        </div>
    );
}
