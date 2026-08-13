/*
 * useFunctionBlurb.ts - One sentence about a function, for hover surfaces.
 *
 * The breadcrumb and the call card both want the same thing: given an address,
 * a short description of what lives there. Both are hover-driven, so the same
 * address gets asked for repeatedly as a mouse crosses a listing.
 *
 * Hence the module-level cache. It is deliberately not React state: the point is
 * that it survives unmounts, so moving between functions does not re-fetch a
 * description that was already retrieved. A run is immutable once analysed, so
 * there is nothing to invalidate — except a lift landing, which is why
 * `forgetBlurb` exists for the code that records one.
 */
import { useEffect, useState } from "react";
import { getLifted } from "../api/client";

/** null means "asked, and there is no lift for this address" — distinct from
 *  undefined, which means "not asked yet". Caching the negative matters: an
 *  un-lifted function is the common case while the AI pass is still running,
 *  and without this every hover would re-request a known 404. */
const cache = new Map<string, string | null>();
const inFlight = new Map<string, Promise<void>>();

/** Drop a cached description. Call after a lift result arrives for this address,
 *  or the card keeps showing "not decompiled yet" against fresh output. */
export function forgetBlurb(va: string) {
    cache.delete(va);
    inFlight.delete(va);
}

async function load(va: string) {
    if (inFlight.has(va)) return inFlight.get(va);
    const work = (async () => {
        try {
            const lifted = await getLifted(va);
            // `description` is what the backend maps the model's `summary` onto.
            const text = lifted?.description?.trim();
            cache.set(va, text ? text : null);
        } catch {
            // A failed lookup caches as absent rather than retrying on every
            // mouse move. The card degrades to the engine's own facts, which is
            // the same thing it shows before the AI pass has run.
            cache.set(va, null);
        } finally {
            inFlight.delete(va);
        }
    })();
    inFlight.set(va, work);
    return work;
}

/**
 * The AI description for `va`, or null when there is none.
 *
 * `pending` is true only while a first fetch is outstanding — a cache hit
 * resolves synchronously on the first render, so a re-hover shows text
 * immediately instead of flashing a spinner at something already known.
 */
export function useFunctionBlurb(va: string | null): {
    blurb: string | null;
    pending: boolean;
} {
    const known = va !== null ? cache.get(va) : null;
    const [, bump] = useState(0);

    useEffect(() => {
        if (va === null || cache.has(va)) return;
        let cancelled = false;
        void load(va).then(() => { if (!cancelled) bump((n) => n + 1); });
        return () => { cancelled = true; };
    }, [va]);

    if (va === null) return { blurb: null, pending: false };
    return { blurb: known ?? null, pending: !cache.has(va) };
}
