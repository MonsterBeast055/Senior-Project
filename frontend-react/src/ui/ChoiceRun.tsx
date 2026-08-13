/*
 * ChoiceRun.tsx - Pick the functions yourself.
 *
 * The engine's own selection is a good default and a bad monopoly: it ranks by
 * information score, which answers "does this function have a recognisable
 * purpose" and not "is this the one I am investigating". Someone who has read
 * the findings usually knows better than the heuristic.
 *
 * The design constraint is that every choice here costs money and minutes, so
 * nothing may be discovered after the fact. Depth expansion is exponential;
 * the count is therefore previewed on the server before anything is sent, and
 * the confirmation says how many requests it will make.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import {
    previewSelection, startAiBatch, type AiTask, type SelectionPreview,
} from "../api/client";
import type { Finding, FindingsDocument, FunctionSummary } from "../api/types";

const STAGES: { task: AiTask; label: string; note: string }[] = [
    { task: "decompile", label: "Lift to C", note: "the expensive one" },
    { task: "bugs", label: "Find bugs", note: "reads the summaries lifting produces" },
    { task: "behaviour", label: "Describe capabilities", note: "cheap" },
];

export default function ChoiceRun({
    functions, findings, analysed, onClose, onMessage,
}: {
    functions: FunctionSummary[];
    findings: FindingsDocument | null;
    /** Addresses that already have a decompile result. */
    analysed: Set<string>;
    onClose: () => void;
    onMessage: (text: string) => void;
}) {
    const [picked, setPicked] = useState<Set<string>>(new Set());
    const [pickedFindings, setPickedFindings] = useState<Set<string>>(new Set());
    const [depth, setDepth] = useState(0);
    const [tasks, setTasks] = useState<Set<AiTask>>(new Set(["decompile"]));
    const [filter, setFilter] = useState("");
    const [skipAnalysed, setSkipAnalysed] = useState(true);
    const [preview, setPreview] = useState<SelectionPreview | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);

    const findingKey = (f: Finding) => `${f.function}|${f.api}`;

    const visible = useMemo(() => {
        const needle = filter.trim().toLowerCase();
        return functions
            .filter((f) => !f.is_thunk && !f.is_imported_stub && !f.is_library_code)
            .filter((f) => !needle
                || f.name.toLowerCase().includes(needle)
                || f.va.includes(needle))
            .sort((a, b) => (b.information_score ?? 0) - (a.information_score ?? 0))
            .slice(0, 400);
    }, [functions, filter]);

    /* Previewed on the server, because only it can walk the call graph — and
     * because the number has to be right rather than approximately right. */
    const refreshPreview = useCallback(async () => {
        if (picked.size === 0 && pickedFindings.size === 0) {
            setPreview(null);
            return;
        }
        setError(null);
        try {
            const chosen = (findings?.findings ?? [])
                .filter((f) => pickedFindings.has(findingKey(f)))
                .map((f) => ({ function: f.function, api: f.api }));
            setPreview(await previewSelection({
                only: [...picked],
                depth,
                findings: chosen,
            }));
        } catch (cause) {
            setError((cause as Error).message);
        }
    }, [picked, pickedFindings, depth, findings]);

    useEffect(() => { void refreshPreview(); }, [refreshPreview]);

    function toggle(set: Set<string>, key: string, apply: (next: Set<string>) => void) {
        const next = new Set(set);
        if (next.has(key)) next.delete(key); else next.add(key);
        apply(next);
    }

    /* What will actually be sent. `skipAnalysed` drops functions that already
     * have a result — the common case is adding a few to an earlier run, and
     * paying twice for the rest is the mistake worth defaulting against. */
    const finalSelection = useMemo(() => {
        const all = preview?.selected ?? [];
        return skipAnalysed ? all.filter((va) => !analysed.has(va)) : all;
    }, [preview, skipAnalysed, analysed]);

    const requests = finalSelection.length * tasks.size;

    async function run() {
        if (finalSelection.length === 0 || tasks.size === 0) return;
        setBusy(true);
        setError(null);
        try {
            // Stage order still matters: bug hunting reads what lifting produced.
            for (const stage of STAGES) {
                if (!tasks.has(stage.task)) continue;
                await startAiBatch(stage.task, { only: finalSelection });
            }
            onMessage(
                `Started on ${finalSelection.length} function`
                + `${finalSelection.length === 1 ? "" : "s"} across ${tasks.size} stage`
                + `${tasks.size === 1 ? "" : "s"}.`,
            );
            onClose();
        } catch (cause) {
            setError((cause as Error).message);
        } finally {
            setBusy(false);
        }
    }

    return (
        <div className="page-inner" style={{ padding: "6px 8px" }}>
            <p className="dim" style={{ margin: "0 0 6px 0" }}>
                Choose the functions yourself. The engine&apos;s ranking is a good
                default, but it measures whether a function has a recognisable
                purpose — not whether it is the one you are investigating.
            </p>

            <div className="choicegrid">
                {/* --- functions ------------------------------------------- */}
                <div>
                    <div className="toolbar" style={{ borderTop: "none" }}>
                        <input
                            className="xp"
                            style={{ width: 150 }}
                            value={filter}
                            placeholder="filter by name or address"
                            onChange={(event) => setFilter(event.target.value)}
                        />
                        <span className="dim">{picked.size} picked</span>
                        <span style={{ flex: 1 }} />
                        <button className="xp" onClick={() => setPicked(new Set())}>
                            Clear
                        </button>
                    </div>

                    <div className="choicelist">
                        {visible.map((f) => {
                            const done = analysed.has(f.va);
                            return (
                                <label key={f.va} className="choicerow">
                                    <input
                                        type="checkbox"
                                        checked={picked.has(f.va)}
                                        onChange={() => toggle(picked, f.va, setPicked)}
                                    />
                                    <span className="tlabel">{f.name}</span>
                                    <span className="dim mono">{f.va}</span>
                                    <span style={{ flex: 1 }} />
                                    {/* Already analysed is shown, not hidden: you may
                                        deliberately want to redo one. */}
                                    {done && <span className="fbsrc engine">done</span>}
                                    <span className="dim">sc {f.information_score ?? 0}</span>
                                </label>
                            );
                        })}
                        {visible.length === 0 && (
                            <div className="empty">Nothing matches that filter.</div>
                        )}
                    </div>
                    {functions.length > visible.length && !filter && (
                        <p className="dim" style={{ margin: "2px 0 0 0" }}>
                            Showing the {visible.length} highest-scoring. Filter to reach
                            the rest.
                        </p>
                    )}
                </div>

                {/* --- findings -------------------------------------------- */}
                <div>
                    <b>Hunt specific findings</b>
                    <p className="dim" style={{ margin: "2px 0 4px 0" }}>
                        Selecting a finding adds every function on its call path. The
                        path is already derived, so this is a lookup rather than a
                        second analysis.
                    </p>
                    <div className="choicelist" style={{ maxHeight: 170 }}>
                        {(findings?.findings ?? []).map((f) => (
                            <label key={findingKey(f)} className="choicerow">
                                <input
                                    type="checkbox"
                                    checked={pickedFindings.has(findingKey(f))}
                                    onChange={() => toggle(
                                        pickedFindings, findingKey(f), setPickedFindings)}
                                />
                                <span className={`sev ${f.severity}`}>{f.severity}</span>
                                <span className="tlabel">{f.kind}</span>
                                <span className="dim mono">{f.function_name}</span>
                                <span style={{ flex: 1 }} />
                                <span className="dim">{f.call_path.length} hops</span>
                            </label>
                        ))}
                        {(findings?.findings ?? []).length === 0 && (
                            <div className="empty">No engine findings in this run.</div>
                        )}
                    </div>
                </div>
            </div>

            {/* --- depth and stages ---------------------------------------- */}
            <div className="toolbar">
                <span>Depth:</span>
                <select
                    className="xp"
                    value={depth}
                    onChange={(event) => setDepth(Number(event.target.value))}
                >
                    {[0, 1, 2, 3, 4, 5, 6, 7].map((d) => (
                        <option key={d} value={d}>{d}</option>
                    ))}
                </select>
                <span className="dim">
                    {depth === 0
                        ? "the chosen functions only"
                        : `and everything they call, ${depth} level${depth === 1 ? "" : "s"} down`}
                </span>
                <span style={{ flex: 1 }} />
                {STAGES.map((stage) => (
                    <label key={stage.task} style={{ marginLeft: 8 }} title={stage.note}>
                        <input
                            type="checkbox"
                            checked={tasks.has(stage.task)}
                            onChange={() => {
                                const next = new Set(tasks);
                                if (next.has(stage.task)) next.delete(stage.task);
                                else next.add(stage.task);
                                setTasks(next);
                            }}
                        />{" "}
                        {stage.label}
                    </label>
                ))}
            </div>

            {error && <div className="notice"><b>Failed.</b> {error}</div>}

            {/* --- the confirmation ---------------------------------------- */}
            <div className="notice">
                {preview ? (
                    <>
                        <b>
                            {finalSelection.length} function
                            {finalSelection.length === 1 ? "" : "s"} ×{" "}
                            {tasks.size} stage{tasks.size === 1 ? "" : "s"} ={" "}
                            {requests} request{requests === 1 ? "" : "s"}.
                        </b>
                        {depth > 0 && (
                            <span>
                                {"  "}{picked.size} chosen, expanded to{" "}
                                {preview.selected.length} at depth {preview.depth}.
                            </span>
                        )}
                        {preview.from_findings > 0 && (
                            <span>
                                {"  "}{preview.from_findings} came from the selected
                                findings&apos; call paths.
                            </span>
                        )}
                        {skipAnalysed
                            && preview.selected.length > finalSelection.length && (
                            <span>
                                {"  "}
                                {preview.selected.length - finalSelection.length} already
                                analysed and skipped.
                            </span>
                        )}
                        {/* The ceiling is disclosed rather than silently applied.
                            A truncated selection that looked complete would be the
                            worst outcome here. */}
                        {preview.truncated && (
                            <>
                                <br />
                                <span className="sev high">
                                    Expansion hit the ceiling of {preview.ceiling} and was
                                    cut short.
                                </span>{" "}
                                Levels nearest your chosen functions were kept. Reduce the
                                depth to be sure of what is included.
                            </>
                        )}
                    </>
                ) : (
                    <span className="dim">
                        Pick at least one function or finding.
                    </span>
                )}
            </div>

            <div className="toolbar">
                <label>
                    <input
                        type="checkbox"
                        checked={skipAnalysed}
                        onChange={() => setSkipAnalysed((on) => !on)}
                    />{" "}
                    Skip functions that already have a result
                </label>
                <span style={{ flex: 1 }} />
                <button className="xp" onClick={onClose}>Cancel</button>
                <button
                    className="xp"
                    disabled={busy || finalSelection.length === 0 || tasks.size === 0}
                    onClick={() => void run()}
                >
                    {busy ? "Starting…" : `Run on ${finalSelection.length}`}
                </button>
            </div>
        </div>
    );
}
