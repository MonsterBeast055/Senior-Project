/*
 * AiAnalysisView.tsx - The AI Analysis tab: whole-binary work, one click.
 *
 * This tab used to carry a mode chooser and a three-pane manual dashboard. Both
 * are gone, because the split was drawn in the wrong place.
 *
 * The right division is scope, not automation:
 *
 *   Analysis tab      one function — its assembly, its graph, and Lift with AI
 *                     when you want that function decompiled
 *   AI Analysis tab   the whole binary — run every pass, watch it, read the result
 *
 * A "Decompile" pane here was a straight duplicate of Lift with AI: same function,
 * same request, different button. Two ways to do one thing is how a UI teaches
 * people that it does not know its own mind.
 *
 * What remains is the automated run and the behaviour profile it produces. The
 * tree and findings box stay on the left because they are how you read the result
 * — a finished run is only useful if you can click straight into what it found.
 */
import { useCallback, useEffect, useState } from "react";
import {
    getAiCoverage, getAiFindings, getBehaviourProfile,
    type AiFinding, type BehaviourProfile,
} from "../api/client";
import type {
    ExtractedString, Finding, FindingsDocument, FunctionDetail, FunctionSummary,
    ImageInfo,
} from "../api/types";
import AiInputView from "./AiInputView";
import ChoiceRun from "./ChoiceRun";
import { Panel } from "./Chrome";
import AutomatedRun from "./AutomatedRun";
import FindingsBox from "./FindingsBox";
import FloatingWindow from "./FloatingWindow";
import SymbolTree from "./SymbolTree";

interface Props {
    detail: FunctionDetail | null;
    /** Selects a function without leaving this view. */
    onSelectFunction: (va: string) => void;
    onOpenFunction: (va: string) => void;
    onMessage: (text: string) => void;
    functions: FunctionSummary[];
    image: ImageInfo | null;
    strings: ExtractedString[];
    findings: FindingsDocument | null;
    /** Opens the finding detail window, which the shell owns. */
    onExplainFinding: (finding: Finding) => void;
    /* Rendered but not shown. The shell keeps this tab mounted while you are on
     * another one so a run in progress keeps advancing — see `.aipage.hidden`. */
    hidden?: boolean;
    /** Back to the upload page, without losing a run that is still going. */
    onGoHome: () => void;
}

export default function AiAnalysisView({
    detail, onSelectFunction, onOpenFunction, onMessage,
    functions, image, strings, findings, onExplainFinding,
    hidden = false, onGoHome,
}: Props) {
    const [treeFilter, setTreeFilter] = useState("");
    const [aiFindings, setAiFindings] = useState<AiFinding[]>([]);
    const [n8nConfigured, setN8nConfigured] = useState<boolean | null>(null);
    const [profile, setProfile] = useState<BehaviourProfile | null>(null);
    /** Bumped by the run each time a stage completes, to refetch results. */
    const [nonce, setNonce] = useState(0);
    /** Addresses with a decompile result, for the tree's green marks. */
    const [analysed, setAnalysed] = useState<Set<string>>(new Set());
    const [choiceOpen, setChoiceOpen] = useState(false);

    const reload = useCallback(async () => {
        /* Which functions have been through the model. Read from the stored
         * results rather than the current job, so a function lifted on its own
         * weeks ago still counts as analysed. */
        try {
            const coverage = await getAiCoverage();
            setAnalysed(new Set(coverage.decompile ?? []));
        } catch { /* the marks degrade to "engine only", which is not a lie */ }
        try {
            const document = await getAiFindings();
            if (document) {
                setAiFindings(document.findings);
                setN8nConfigured(document.n8n_configured);
            }
        } catch { /* engine findings still render */ }
        try {
            setProfile(await getBehaviourProfile());
        } catch { /* profile is optional */ }
    }, []);

    useEffect(() => { void reload(); }, [reload, nonce, findings]);

    /* Stable identity matters here. AutomatedRun's polling effect lists this in
     * its dependencies, so an inline arrow — a new function on every render —
     * tore the interval down and rebuilt it each time the job counters changed.
     * It mostly survived that, but a render arriving faster than the poll period
     * would keep resetting the timer and the run would stop advancing. */
    const onRunProgress = useCallback((text: string) => {
        onMessage(text);
        setNonce((n) => n + 1);
    }, [onMessage]);

    return (
        <div className={`aipage${hidden ? " hidden" : ""}`}>
            {/* The same tree as the Analysis tab. A finished run is only useful if
                you can click from a result straight into the code behind it. */}
            <div className="aitree">
                <Panel caption="Symbol tree">
                    <SymbolTree
                        functions={functions}
                        image={image}
                        strings={strings}
                        currentVa={detail?.va ?? null}
                        filter={treeFilter}
                        analysed={analysed}
                        onOpenFunction={onSelectFunction}
                    />
                    {/* Colour alone would fail a colour-blind reader and every
                        printed copy of the report, so the legend spells it out. */}
                    <div className="tree-legend">
                        <span><span className="tmark mk-ai">●</span> AI</span>
                        <span><span className="tmark mk-engine">●</span> engine only</span>
                        <span><span className="tmark mk-limited">●</span> limited</span>
                    </div>
                </Panel>
                <input
                    className="xp"
                    style={{ margin: "3px 0 0 0" }}
                    value={treeFilter}
                    placeholder="filter the tree"
                    onChange={(event) => setTreeFilter(event.target.value)}
                />

                <Panel
                    caption="Findings"
                    hint={aiFindings.length > 0 ? `+${aiFindings.length} AI` : undefined}
                >
                    <FindingsBox
                        findings={findings}
                        aiFindings={aiFindings}
                        n8nConfigured={n8nConfigured}
                        currentVa={detail?.va ?? null}
                        onOpenFunction={onSelectFunction}
                        onExplain={onExplainFinding}
                    />
                </Panel>
            </div>

            <div className="aiwin">
                <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
                    <h1 style={{ margin: 0 }}>AI Analysis</h1>
                    <span style={{ flex: 1 }} />
                    {/* Leaving is safe now: the tab stays mounted and the run keeps
                        going. Said on the button so nobody avoids clicking it. */}
                    <button
                        className="xp"
                        onClick={onGoHome}
                        title="Back to the upload page. A run in progress keeps going."
                    >
                        Home
                    </button>
                </div>
                <p className="dim" style={{ marginTop: 6 }}>
                    Whole-binary passes. To decompile a single function, use{" "}
                    <b>Lift with AI</b> in the Decompiler pane on the Analysis tab —
                    this page is for running everything at once.
                </p>
                <p className="dim">
                    Model output is clearly separated from the engine's. Findings,
                    severities and call paths are the engine's and are never
                    overwritten; a model explains a rating here, it never sets one.
                </p>

                <AutomatedRun onMessage={onRunProgress} onChooseRun={() => setChoiceOpen(true)} />

                {choiceOpen && (
                    <FloatingWindow
                        title="Automated analysis — by choice"
                        hint="pick the functions, and how deep to follow what they call"
                        onClose={() => setChoiceOpen(false)}
                        initial={{ x: 90, y: 70, width: 900, height: 620 }}
                    >
                        <ChoiceRun
                            functions={functions}
                            findings={findings}
                            analysed={analysed}
                            onClose={() => { setChoiceOpen(false); setNonce((n) => n + 1); }}
                            onMessage={onMessage}
                        />
                    </FloatingWindow>
                )}

                {/* The run above sends one of these per function per stage. Being
                    able to open one is the difference between "the AI analysed
                    it" and being able to say what the AI was actually given. */}
                <h2 style={{ marginTop: 14 }}>What gets sent to the model</h2>
                {!detail && (
                    <div className="empty">
                        Pick a function in the tree to see the context that would be
                        sent for it.
                    </div>
                )}
                {detail && (
                    <>
                        <p className="dim">
                            Every function in the run is sent a bundle like this, once
                            per stage. Showing <b>{detail.name}</b> — select another in
                            the tree to compare.
                        </p>
                        <AiInputView va={detail.va} name={detail.name} />
                    </>
                )}

                {/* --- What the run actually found -----------------------------
                    These are the point of the pass, and they were readable only
                    in the 260px sidebar, where every title truncated to
                    "Indirect Call to Impo...". The box on the left stays: it is
                    how you navigate between findings and it merges the engine's
                    with the model's. This is where you read them. */}
                <h2 style={{ marginTop: 14 }}>
                    Defects reported by the model
                    {aiFindings.length > 0 && (
                        <span className="dim" style={{ fontWeight: "normal" }}>
                            {"  "}{aiFindings.length}
                        </span>
                    )}
                </h2>

                {aiFindings.length === 0 && (
                    <div className="empty">
                        Nothing reported yet. Run the automated analysis, or use
                        <b> Find bugs</b> on a single function.
                    </div>
                )}

                {aiFindings.map((finding, index) => (
                    <div
                        key={`${finding.function}-${finding.api}-${index}`}
                        className="aifinding"
                    >
                        <div className="aif-head">
                            {/* Severity is the engine's or absent. A model-only
                                lead gets no rating rather than borrowing one. */}
                            {finding.severity
                                ? <span className={`sev ${finding.severity}`}>{finding.severity}</span>
                                : <span className="dim">no rating</span>}
                            <span
                                className={finding.engine_corroborated ? "fbsrc engine" : "fbsrc ai"}
                                title={finding.engine_corroborated
                                    ? "A static finding stands behind this issue"
                                    : "The engine never flagged this — a lead, not a result"}
                            >
                                {finding.engine_corroborated ? "corroborated" : "unconfirmed"}
                            </span>
                            {finding.stale && (
                                <span className="fbsrc ai" title="Reasoned from a decompilation that has since been replaced">
                                    stale
                                </span>
                            )}
                            <b>{finding.kind}</b>
                        </div>

                        <div className="aif-body">{finding.detail}</div>

                        <div className="aif-foot">
                            <span
                                className="crumb"
                                onClick={() => onSelectFunction(finding.function)}
                                title="Open this function"
                            >
                                {finding.function_name || finding.function}
                            </span>
                            {finding.api && finding.api !== "—" && (
                                <span className="mono dim">{"  "}{finding.api}</span>
                            )}
                            {finding.call_path.length > 0 && (
                                <span className="dim">
                                    {"  ·  path: "}
                                    {finding.call_path.map((step) => step.name || step.va).join(" > ")}
                                </span>
                            )}
                            {finding.model_confidence && (
                                <span className="dim">{"  ·  model confidence "}{finding.model_confidence}</span>
                            )}
                        </div>
                    </div>
                ))}

                {/* --- Behaviour profile: the run's whole-binary output --------- */}
                <h2 style={{ marginTop: 14 }}>Capabilities</h2>

                {!profile && (
                    <div className="empty">No profile available for this run.</div>
                )}

                {profile && (
                    <>
                        <div className="notice">
                            <b>Capability evidence, not a verdict.</b> {profile.disclaimer}
                        </div>

                        {profile.packed_sections.length > 0 && (
                            <div className="notice" style={{ marginTop: 6 }}>
                                <b>Possibly packed.</b>{" "}
                                {profile.packed_sections
                                    .map((s) => `${s.name} (entropy ${s.entropy.toFixed(2)})`)
                                    .join(", ")}
                                . High entropy in an executable section limits what
                                static analysis can see, so treat everything below as a
                                floor rather than a complete picture.
                            </div>
                        )}

                        {profile.capabilities.length === 0 && (
                            <div className="empty" style={{ marginTop: 8 }}>
                                No capability signals matched. The binary imports nothing
                                associated with persistence, injection, networking,
                                credential access or anti-analysis.
                            </div>
                        )}

                        {profile.capabilities.map((capability) => (
                            <div key={capability.id} style={{ marginTop: 10 }}>
                                <h3 style={{ margin: "0 0 2px 0" }}>
                                    {capability.label}{" "}
                                    <span className="dim">
                                        ({capability.function_count} function
                                        {capability.function_count === 1 ? "" : "s"}
                                        {capability.reachable_count > 0 && (
                                            <>, {capability.reachable_count} reachable from input</>
                                        )})
                                    </span>
                                </h3>
                                <table className="grid">
                                    <thead>
                                        <tr>
                                            <th style={{ width: 130 }}>Function</th>
                                            <th>Evidence</th>
                                            <th style={{ width: 56 }} />
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {capability.evidence.slice(0, 12).map((site) => (
                                            <tr key={site.va}>
                                                <td>
                                                    <span className="mono">{site.name}</span>
                                                    {site.reachable_from_input && (
                                                        <>
                                                            <br />
                                                            <span className="badge warn">
                                                                reachable
                                                            </span>
                                                        </>
                                                    )}
                                                </td>
                                                <td>
                                                    {site.api_calls.length > 0 && (
                                                        <div className="mono dim">
                                                            {site.api_calls.join(", ")}
                                                        </div>
                                                    )}
                                                    {site.strings.length > 0 && (
                                                        <div className="mono asm-str">
                                                            {site.strings
                                                                .map((s) => `"${s}"`)
                                                                .join(", ")}
                                                        </div>
                                                    )}
                                                    {site.explanation && (
                                                        <div style={{ marginTop: 3 }}>
                                                            {site.explanation}
                                                        </div>
                                                    )}
                                                </td>
                                                <td>
                                                    <button
                                                        className="xp"
                                                        onClick={() => onOpenFunction(site.va)}
                                                    >
                                                        Open
                                                    </button>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                                {capability.evidence.length > 12 && (
                                    <p className="dim">
                                        and {capability.evidence.length - 12} more, by
                                        descending information score.
                                    </p>
                                )}
                            </div>
                        ))}

                        {!profile.ai_explanations_available && (
                            <p className="dim" style={{ marginTop: 8 }}>
                                Per-function narrative would be added by the AI pass. The
                                evidence above is the engine's and does not depend on it.
                            </p>
                        )}
                    </>
                )}
            </div>
        </div>
    );
}
