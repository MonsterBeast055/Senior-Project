/*
 * RootPath.tsx - What is this function in service of?
 *
 * The breadcrumb answers "how did I get here" — the path you clicked, wandering
 * included. This answers a different question: given a function you care about,
 * how does the program actually reach the one you are looking at now. It comes
 * from the call graph, not from your clicks, so it is the same whether you
 * arrived directly or after twenty detours.
 *
 * Six levels into a descent, "how did I get here" stops being the thing you have
 * lost. What you have lost is why you started.
 *
 * The honest-failure cases matter as much as the path:
 *
 *   no path        you have navigated somewhere the root cannot reach. Worth
 *                  knowing — it usually means you followed an xref upward.
 *   incomplete     the search failed, but nodes along the way have unresolved
 *                  indirect calls, so a path may exist that the graph cannot
 *                  see. Saying "no path" there would be a false negative stated
 *                  as fact, which is the failure mode this project exists to
 *                  avoid.
 */
import { useEffect, useMemo, useState } from "react";
import { getCallGraph } from "../api/client";
import type { CallGraphDocument, FunctionSummary } from "../api/types";

type Search =
    | { kind: "path"; path: string[] }
    | { kind: "none"; incomplete: boolean }
    | { kind: "self" };

/**
 * Shortest call path from `root` to `target`, breadth-first.
 *
 * Shortest rather than any: with cycles a depth-first walk can return a
 * ten-hop path where a two-hop one exists, and a path claiming more structure
 * than the program has is worse than a short one.
 */
function findPath(graph: CallGraphDocument, root: string, target: string): Search {
    if (root === target) return { kind: "self" };

    const outgoing = new Map<string, string[]>();
    for (const edge of graph.edges) {
        const list = outgoing.get(edge.from);
        if (list) list.push(edge.to); else outgoing.set(edge.from, [edge.to]);
    }

    const cameFrom = new Map<string, string>();
    const seen = new Set<string>([root]);
    let frontier = [root];

    while (frontier.length > 0) {
        const next: string[] = [];
        for (const node of frontier) {
            for (const child of outgoing.get(node) ?? []) {
                if (seen.has(child)) continue;
                seen.add(child);
                cameFrom.set(child, node);
                if (child === target) {
                    const path = [target];
                    let step = target;
                    while (step !== root) {
                        step = cameFrom.get(step)!;
                        path.unshift(step);
                    }
                    return { kind: "path", path };
                }
                next.push(child);
            }
        }
        frontier = next;
    }

    /* Nothing found. Whether that means "no path" depends on how much of the
     * graph we could actually see: an unresolved indirect call anywhere in the
     * region we searched is an edge that exists in the program and not here. */
    const incomplete = graph.nodes.some(
        (node) => node.has_indirect_calls && seen.has(node.va));
    return { kind: "none", incomplete };
}

export default function RootPath({
    rootVa, currentVa, runId, functions, onJump, onUnpin,
}: {
    rootVa: string;
    currentVa: string | null;
    /** Refetches when the run changes; the graph belongs to one analysis. */
    runId: string;
    functions: FunctionSummary[];
    onJump: (va: string) => void;
    onUnpin: () => void;
}) {
    const [graph, setGraph] = useState<CallGraphDocument | null>(null);
    const [failed, setFailed] = useState(false);

    useEffect(() => {
        let cancelled = false;
        setGraph(null);
        setFailed(false);
        void getCallGraph()
            .then((document) => { if (!cancelled) setGraph(document); })
            .catch(() => { if (!cancelled) setFailed(true); });
        return () => { cancelled = true; };
    }, [runId]);

    const search = useMemo(
        () => (graph && currentVa ? findPath(graph, rootVa, currentVa) : null),
        [graph, rootVa, currentVa]);

    const nameOf = (va: string) =>
        functions.find((candidate) => candidate.va === va)?.name ?? va;

    return (
        <div className="rootpath">
            <span className="rp-label" title="Pinned root — the function you are investigating">
                &#9679; root
            </span>

            {failed && (
                <span className="dim">
                    no call graph in this run &mdash; it predates <span className="mono">callgraph.json</span>
                </span>
            )}

            {!failed && !graph && <span className="dim">loading call graph&hellip;</span>}

            {search?.kind === "self" && (
                <span className="crumb current">{nameOf(rootVa)}</span>
            )}

            {search?.kind === "path" && search.path.map((va, position) => (
                <span key={`${va}-${position}`}>
                    <span
                        className={`crumb${va === currentVa ? " current" : ""}`}
                        onClick={va === currentVa ? undefined : () => onJump(va)}
                        title={va}
                    >
                        {nameOf(va)}
                    </span>
                    {position < search.path.length - 1 && (
                        <span className="crumbsep">&rsaquo;</span>
                    )}
                </span>
            ))}

            {search?.kind === "none" && (
                <span className="dim">
                    <span className="crumb" onClick={() => onJump(rootVa)}>
                        {nameOf(rootVa)}
                    </span>
                    {search.incomplete
                        ? " does not reach here through any resolved call — but"
                          + " unresolved indirect calls lie on the way, so one may"
                          + " exist that the graph cannot see"
                        : " does not reach this function"}
                </span>
            )}

            <span style={{ flex: 1 }} />
            <button className="xp crumbnav" onClick={onUnpin} title="Unpin the root">
                &times;
            </button>
        </div>
    );
}
