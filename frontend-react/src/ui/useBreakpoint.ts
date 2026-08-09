/*
 * useBreakpoint.ts - Which columns the viewport can actually hold.
 *
 * The CSS hides columns below its breakpoints, but hiding alone would make the
 * content unreachable. React needs to know the same thresholds so it can move
 * that content into the centre pane's tab strip instead. The numbers here must
 * match the media queries in styles/xp.css.
 */
import { useEffect, useState } from "react";

/** wide: 3 columns. medium: no decompiler column. narrow: single column. */
export type Breakpoint = "wide" | "medium" | "narrow";

const MEDIUM_MAX = 1180;
const NARROW_MAX = 860;

function measure(): Breakpoint {
    const width = window.innerWidth;
    if (width <= NARROW_MAX) return "narrow";
    if (width <= MEDIUM_MAX) return "medium";
    return "wide";
}

export function useBreakpoint(): Breakpoint {
    const [breakpoint, setBreakpoint] = useState<Breakpoint>(measure);

    useEffect(() => {
        // matchMedia rather than a resize listener: it fires only when a
        // threshold is actually crossed, not on every pixel of a window drag.
        const queries = [
            window.matchMedia(`(max-width: ${NARROW_MAX}px)`),
            window.matchMedia(`(max-width: ${MEDIUM_MAX}px)`),
        ];
        const update = () => setBreakpoint(measure());
        queries.forEach((query) => query.addEventListener("change", update));
        return () => queries.forEach((query) => query.removeEventListener("change", update));
    }, []);

    return breakpoint;
}
