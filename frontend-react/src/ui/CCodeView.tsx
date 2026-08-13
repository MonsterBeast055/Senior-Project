/*
 * CCodeView.tsx - Decompiled C, with callees expandable in place.
 *
 * The problem this solves: six levels into a call chain you have forgotten what
 * you were looking at. Navigating to a callee answers "what does it do" at the
 * cost of losing "what was I reading". Expanding it in place answers both.
 *
 * Two invariants hold this together.
 *
 * 1. Expansion is a VIEW state, never a selection change. The pane is still
 *    about the function you opened; the CFG, the assembly and the breadcrumb do
 *    not move. Otherwise expansion is just navigation with extra steps, which is
 *    the thing it exists to avoid.
 *
 * 2. Own lines keep their original numbers. `line_mapping` is keyed by line
 *    number, so renumbering as content is injected would silently break the
 *    highlight sync with the disassembly. Expanded bodies are rendered as
 *    separate rows between the numbered ones rather than spliced into them, so
 *    no renumbering ever happens.
 *
 * Depth is capped and ancestors are tracked because binaries recurse — direct
 * and mutual both. Without the guard, expanding A -> B -> A never terminates.
 */
import { useEffect, useState } from "react";
import { getFunction, getLifted } from "../api/client";
import type { FunctionDetail, FunctionRef, LineMapping } from "../api/types";

/** Two levels of callee below the function you opened. Past that the indentation
 *  costs more readability than the context buys. */
export const MAX_DEPTH = 2;

/** Identifies one expansion point: a line within a particular function. */
export const expansionKey = (ownerVa: string, line: number) => `${ownerVa}#${line}`;

/** Which callee, if any, this line calls.
 *
 *  Matching on name is a heuristic — the model wrote the text, so there is no
 *  structural link back to the call graph. Longest name first, or `sub_1400`
 *  would match inside `sub_140002500` and expand the wrong function. */
function calleeOn(text: string, callees: FunctionRef[]): FunctionRef | null {
    let best: FunctionRef | null = null;
    for (const candidate of callees) {
        if (!candidate.name || !text.includes(candidate.name)) continue;
        if (!best || candidate.name.length > best.name.length) best = candidate;
    }
    return best;
}

interface Shared {
    expanded: Set<string>;
    onToggle: (key: string) => void;
}

export default function CCodeView({
    ownerVa, code, lineMapping, callees, depth, ancestors,
    selectedBlock, onSelectBlock, shared,
}: {
    ownerVa: string;
    code: string[];
    lineMapping: LineMapping[];
    callees: FunctionRef[];
    depth: number;
    /** Functions already open above this one. Stops A -> B -> A. */
    ancestors: string[];
    /** Only the top level participates: an expanded body's blocks belong to a
     *  different function, so highlighting them against this selection would be
     *  meaningless. */
    selectedBlock: string | null;
    onSelectBlock: ((block: string) => void) | null;
    shared: Shared;
}) {
    const mapping = new Map<number, string>();
    lineMapping.forEach((entry) => mapping.set(entry.line, entry.block));

    return (
        <>
            {code.map((text, index) => {
                const line = index + 1;
                const block = mapping.get(line);
                const highlighted = block != null && block === selectedBlock;

                const target = depth < MAX_DEPTH ? calleeOn(text, callees) : null;
                const cyclic = target != null
                    && (ancestors.includes(target.va) || target.va === ownerVa);
                const key = expansionKey(ownerVa, line);
                const open = shared.expanded.has(key);

                return (
                    <div key={line}>
                        <div
                            id={depth === 0 ? `cline-${line}` : undefined}
                            className={`row${highlighted ? " highlight" : ""}`}
                            onClick={() => block && onSelectBlock?.(block)}
                            title={block ? `block ${block}` : undefined}
                        >
                            <span className="asm-addr">
                                {String(line).padStart(3, " ")}
                            </span>
                            {"  "}
                            <span style={{ paddingLeft: depth * 14 }}>{text}</span>

                            {target && !cyclic && (
                                <span
                                    className="cexpand"
                                    title={open
                                        ? `Collapse ${target.name}`
                                        : `Expand ${target.name} here`}
                                    onClick={(event) => {
                                        // The row selects a block; the toggle
                                        // toggles. They must not both fire.
                                        event.stopPropagation();
                                        shared.onToggle(key);
                                    }}
                                >
                                    {open ? "[-]" : "[+]"}
                                </span>
                            )}

                            {/* Named rather than hidden. A call you cannot expand
                                because it loops back is worth knowing about; a
                                missing control just looks broken. */}
                            {target && cyclic && (
                                <span
                                    className="cexpand dim"
                                    title={`${target.name} is already open above this — expanding it would not terminate`}
                                >
                                    [&#8635;]
                                </span>
                            )}
                        </div>

                        {open && target && (
                            <ExpandedCallee
                                target={target}
                                depth={depth + 1}
                                ancestors={[...ancestors, ownerVa]}
                                shared={shared}
                                onCollapse={() => shared.onToggle(key)}
                            />
                        )}
                    </div>
                );
            })}
        </>
    );
}

/* --- One expanded callee ------------------------------------------------- */

function ExpandedCallee({
    target, depth, ancestors, shared, onCollapse,
}: {
    target: FunctionRef;
    depth: number;
    ancestors: string[];
    shared: Shared;
    onCollapse: () => void;
}) {
    const [detail, setDetail] = useState<FunctionDetail | null>(null);
    const [code, setCode] = useState<string[] | null>(null);
    const [mapping, setMapping] = useState<LineMapping[]>([]);
    const [state, setState] = useState<"loading" | "ready" | "not-lifted" | "failed">(
        "loading");

    useEffect(() => {
        let cancelled = false;
        setState("loading");
        void (async () => {
            try {
                // Both: the code to show, and the callee list that lets the level
                // below this one be expandable in turn.
                const [lifted, next] = await Promise.all([
                    getLifted(target.va),
                    getFunction(target.va),
                ]);
                if (cancelled) return;
                setDetail(next);
                if (lifted && (lifted.c_code ?? []).length > 0) {
                    setCode(lifted.c_code);
                    setMapping(lifted.line_mapping ?? []);
                    setState("ready");
                } else {
                    setState("not-lifted");
                }
            } catch {
                if (!cancelled) setState("failed");
            }
        })();
        return () => { cancelled = true; };
    }, [target.va]);

    const indent = depth * 14;

    return (
        <div className="cnest" style={{ marginLeft: indent }}>
            <div className="cnest-bar">
                <span
                    className="cexpand"
                    title="Collapse"
                    onClick={onCollapse}
                >
                    [-]
                </span>
                {" "}
                <b>{target.name}</b>
                <span className="dim">{"  "}{target.va}</span>
                <span style={{ flex: 1 }} />
                <span className="dim">expanded &mdash; read only</span>
            </div>

            {state === "loading" && (
                <div className="dim" style={{ padding: "2px 6px" }}>Loading&hellip;</div>
            )}

            {state === "failed" && (
                <div className="dim" style={{ padding: "2px 6px" }}>
                    Could not load {target.va}.
                </div>
            )}

            {state === "not-lifted" && (
                <div className="dim" style={{ padding: "2px 6px" }}>
                    Not decompiled yet. Open it and press <b>Lift with AI</b>, or wait
                    for the batch pass to reach it.
                </div>
            )}

            {state === "ready" && code && (
                <CCodeView
                    ownerVa={target.va}
                    code={code}
                    lineMapping={mapping}
                    callees={detail?.callees ?? []}
                    depth={depth}
                    ancestors={ancestors}
                    // An expanded body's blocks are not this pane's selection.
                    selectedBlock={null}
                    onSelectBlock={null}
                    shared={shared}
                />
            )}
        </div>
    );
}
