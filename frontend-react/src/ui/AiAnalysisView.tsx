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
import { getAiFindings, getBehaviourProfile, type AiFinding, type BehaviourProfile } from "../api/client";
import type {
    ExtractedString, Finding, FindingsDocument, FunctionDetail, FunctionSummary,
    ImageInfo,
} from "../api/types";
import { Panel } from "./Chrome";
import AutomatedRun from "./AutomatedRun";
import FindingsBox from "./FindingsBox";
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
}

export default function AiAnalysisView({
    detail, onSelectFunction, onOpenFunction, onMessage,
    functions, image, strings, findings, onExplainFinding,
}: Props) {
    const [treeFilter, setTreeFilter] = useState("");
    const [aiFindings, setAiFindings] = useState<AiFinding[]>([]);
    const [n8nConfigured, setN8nConfigured] = useState<boolean | null>(null);
    const [profile, setProfile] = useState<BehaviourProfile | null>(null);
    /** Bumped by the run each time a stage completes, to refetch results. */
    const [nonce, setNonce] = useState(0);

    const reload = useCallback(async () => {
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

    return (
        <div className="aipage">
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
                        onOpenFunction={onSelectFunction}
                    />
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
                <h1>AI Analysis</h1>
                <p className="dim">
                    Whole-binary passes. To decompile a single function, use{" "}
                    <b>Lift with AI</b> in the Decompiler pane on the Analysis tab —
                    this page is for running everything at once.
                </p>
                <p className="dim">
                    Model output is clearly separated from the engine's. Findings,
                    severities and call paths are the engine's and are never
                    overwritten; a model explains a rating here, it never sets one.
                </p>

                <AutomatedRun
                    onMessage={(text) => { onMessage(text); setNonce((n) => n + 1); }}
                />

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
