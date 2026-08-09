/*
 * FindingsBox.tsx - The conclusions, in one place.
 *
 * Split out of the symbol tree deliberately. The tree answers "where do I go" —
 * functions, imports, strings, sections. Findings answer "what did we conclude".
 * Those are different kinds of thing, and mixing them made the tree crowded while
 * burying the output the project actually exists to produce.
 *
 * Engine and AI findings share one list with a Source column, because the
 * interesting case is both flagging the same function: agreement is corroboration,
 * and disagreement is worth looking at. Two separate lists would hide exactly that.
 *
 * Severity is always the engine's, on every row. An AI row shows the severity of
 * the engine finding it matched, or nothing at all — never a rating the model
 * invented. The backend enforces this too; showing it here is the visible half.
 */
import { useMemo, useState } from "react";
import type { AiFinding } from "../api/client";
import type { Finding, FindingsDocument } from "../api/types";
import { Severity } from "./Chrome";
import Explain from "./Explain";
import { SeverityDerivation } from "./Derivations";

type Source = "engine" | "ai";

/** One row, whichever side it came from. */
interface Row {
    key: string;
    source: Source;
    va: string;
    functionName: string;
    api: string;
    kind: string;
    severity: string | null;
    reachable: boolean | null;
    pathLength: number;
    /** AI only: no static finding stands behind this row. */
    uncorroborated: boolean;
    /** AI only: the decompiled code this was reasoned from has since been
     *  re-lifted. The finding still stands; its source text has moved on. */
    stale: boolean;
    /** The engine finding, when there is one — needed to open the detail window. */
    finding: Finding | null;
    detail: string | null;
}

const FILTERS = ["All", "Reachable", "Engine", "AI"] as const;
type Filter = (typeof FILTERS)[number];

/* Short labels, because the column is narrow. The full meaning goes in the
   tooltip rather than being truncated on screen. */
const FILTER_LABEL: Record<Filter, string> = {
    "All": "All",
    "Reachable": "Reach",
    "Engine": "Eng",
    "AI": "AI",
};
const FILTER_HINT: Record<Filter, string> = {
    "All": "Every finding, engine and AI",
    "Reachable": "Only findings a call path reaches from untrusted input",
    "Engine": "Static analysis findings only",
    "AI": "Model-reported findings only",
};

const SEVERITY_RANK: Record<string, number> = {
    high: 3, medium: 2, low: 1, informational: 0,
};

interface Props {
    findings: FindingsDocument | null;
    aiFindings: AiFinding[];
    /** Set when the backend has no n8n configured, so the box can say so once. */
    n8nConfigured: boolean | null;
    currentVa: string | null;
    onOpenFunction: (va: string) => void;
    /** Opens the detail window: engine facts, call path, AI explanation. */
    onExplain: (finding: Finding) => void;
}

export default function FindingsBox({
    findings, aiFindings, n8nConfigured, currentVa, onOpenFunction, onExplain,
}: Props) {
    const [filter, setFilter] = useState<Filter>("All");

    const rows = useMemo<Row[]>(() => {
        const out: Row[] = [];

        (findings?.findings ?? []).forEach((f, index) => {
            out.push({
                key: `e${index}`,
                source: "engine",
                va: f.function,
                functionName: f.function_name,
                api: f.api,
                kind: f.kind,
                severity: f.severity,
                reachable: f.reachable_from_input,
                pathLength: f.call_path.length,
                uncorroborated: false,
                stale: false,
                finding: f,
                detail: null,
            });
        });

        aiFindings.forEach((f, index) => {
            // Reuse the engine finding for the same function so the detail window
            // still has real facts to show behind the model's prose.
            const engineMatch = (findings?.findings ?? []).find(
                (e) => e.function === f.function && e.api === f.api,
            ) ?? null;
            out.push({
                key: `a${index}`,
                source: "ai",
                va: f.function,
                functionName: f.function_name,
                api: f.api,
                kind: f.kind,
                severity: f.severity,
                reachable: f.reachable_from_input,
                pathLength: f.call_path.length,
                uncorroborated: !f.engine_corroborated,
                stale: !!f.stale,
                finding: engineMatch,
                detail: f.detail,
            });
        });

        // Reachable first, then severity, then engine before AI. Sorting by
        // severity alone would float an unreachable High above a reachable one,
        // which inverts the thing that actually decides whether it matters.
        return out.sort((a, b) => {
            const reach = Number(b.reachable === true) - Number(a.reachable === true);
            if (reach !== 0) return reach;
            const sev = (SEVERITY_RANK[b.severity ?? ""] ?? -1)
                      - (SEVERITY_RANK[a.severity ?? ""] ?? -1);
            if (sev !== 0) return sev;
            return a.source === b.source ? 0 : a.source === "engine" ? -1 : 1;
        });
    }, [findings, aiFindings]);

    const visible = useMemo(() => {
        if (filter === "Reachable") return rows.filter((r) => r.reachable === true);
        if (filter === "Engine") return rows.filter((r) => r.source === "engine");
        if (filter === "AI") return rows.filter((r) => r.source === "ai");
        return rows;
    }, [rows, filter]);

    const engineCount = rows.filter((r) => r.source === "engine").length;
    const aiCount = rows.length - engineCount;
    const impactful = rows.filter(
        (r) => r.reachable === true && (SEVERITY_RANK[r.severity ?? ""] ?? 0) >= 2,
    ).length;

    return (
        <div className="findingsbox">
            <div className="fbfilters">
                {FILTERS.map((name) => (
                    <span
                        key={name}
                        className={`fbfilter${filter === name ? " active" : ""}`}
                        onClick={() => setFilter(name)}
                        title={
                            `${FILTER_HINT[name]}`
                            + (name === "Engine" ? ` — ${engineCount}`
                               : name === "AI" ? ` — ${aiCount}` : "")
                        }
                    >
                        {FILTER_LABEL[name]}
                    </span>
                ))}
                <span style={{ flex: 1 }} />
                {impactful > 0 && (
                    <span
                        className="sev high fbimpact"
                        title="Reachable from untrusted input and at least medium severity"
                    >
                        {impactful}
                    </span>
                )}
            </div>

            {visible.length === 0 ? (
                <div className="empty">
                    {rows.length === 0
                        ? "No findings."
                        : `Nothing matches "${filter}".`}
                    {rows.length === 0 && n8nConfigured === false && (
                        <div className="dim" style={{ marginTop: 6 }}>
                            Engine findings appear here as soon as a binary is analysed.
                            AI findings need the n8n workflow.
                        </div>
                    )}
                </div>
            ) : (
                <div className="fblist">
                    {visible.map((row) => (
                        <div
                            key={row.key}
                            className={`fbrow${row.va === currentVa ? " selected" : ""}`}
                            onClick={() => onOpenFunction(row.va)}
                            title={row.detail ?? `${row.api} in ${row.functionName}`}
                        >
                            <div className="fbhead">
                                {/* Severity may be absent on an AI row with no
                                    matching engine finding. Showing "—" is correct:
                                    we have no rating, and inventing one is exactly
                                    what this design refuses to do. */}
                                {/* Hovering the badge shows how the rating was
                                    composed, with this finding's own values. */}
                                {row.severity && row.finding ? (
                                    <Explain
                                        title="How this severity was derived"
                                        anchor={<Severity level={row.severity as never} />}
                                    >
                                        <SeverityDerivation finding={row.finding} />
                                    </Explain>
                                ) : row.severity ? (
                                    <Severity level={row.severity as never} />
                                ) : (
                                    <span className="dim" title="No engine finding stands behind this row, so there is no rating to show.">—</span>
                                )}

                                <span className={`fbsrc ${row.source}`}>
                                    {row.source === "engine" ? "engine" : "AI"}
                                </span>

                                <span className="fbkind" title={row.kind}>{row.kind}</span>
                                <span style={{ flex: 1 }} />

                                {row.reachable === true && (
                                    <span className="badge warn" title="A call path exists from an input source">
                                        reachable
                                    </span>
                                )}
                                {row.uncorroborated && (
                                    <span
                                        className="badge"
                                        title="The model raised this; the static engine did not flag it. A lead, not a result."
                                    >
                                        unconfirmed
                                    </span>
                                )}
                                {row.stale && (
                                    <span
                                        className="badge"
                                        title="This was reasoned from a decompiled version that has since been re-lifted. The finding still stands, but the code it describes has been regenerated — re-run Find bugs on this function to refresh it."
                                    >
                                        stale
                                    </span>
                                )}
                            </div>

                            <div className="fbmeta">
                                <span className="mono">{row.api.split("!").pop()}</span>
                                <span className="mono fbfn" title={row.functionName}>
                                    {row.functionName}
                                </span>
                                {row.pathLength > 0 && (
                                    <span className="dim">· {row.pathLength}</span>
                                )}
                                <span style={{ flex: 1 }} />
                                {row.finding && (
                                    <button
                                        className="xp fbwhy"
                                        title="Why is it rated this way? Engine derivation, call path, and the AI explanation."
                                        onClick={(event) => {
                                            // The row navigates; the button must not.
                                            event.stopPropagation();
                                            onExplain(row.finding!);
                                        }}
                                    >
                                        why?
                                    </button>
                                )}
                            </div>

                            {row.detail && <div className="fbdetail">{row.detail}</div>}
                        </div>
                    ))}
                </div>
            )}

            {/* The methodology caveat, kept attached to the findings rather than
                left in a document nobody opens. Severity here is call-graph
                reachability, not taint analysis. */}
            {findings && rows.length > 0 && (
                <div className="fbfoot dim">
                    Severity is the engine's, derived from the sink kind plus
                    reachability — never the model's. A path existing does not prove
                    attacker data reaches the argument.
                </div>
            )}
        </div>
    );
}
