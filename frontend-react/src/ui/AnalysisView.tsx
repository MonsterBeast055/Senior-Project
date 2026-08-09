/*
 * AnalysisView.tsx - The workspace.
 *
 * Layout intent: the two panes people actually read — assembly and decompiled C —
 * get the whole middle of the window. Navigation is one tree on the left,
 * metrics are a single line at the bottom, the graph is a window you open when
 * you want it, and the tabular views are a dock that starts collapsed.
 *
 * Responsiveness is not CSS alone. Below the breakpoints the stylesheet hides
 * columns, so this component moves their content into the centre tab strip.
 * Hiding without relocating is how panes become unreachable.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { getAiFindings, getFunction, type AiFinding } from "../api/client";
import type {
    ExtractedString, Finding, FindingsDocument, FunctionDetail, FunctionSummary,
    ImageInfo,
} from "../api/types";
import { Panel, TabStrip } from "./Chrome";
import CfgGraph from "./CfgGraph";
import Decompiler from "./Decompiler";
import FindingsBox from "./FindingsBox";
import FloatingWindow from "./FloatingWindow";
import MetricsBar from "./MetricsBar";
import SymbolTree from "./SymbolTree";
import XrefWindow, { xrefTitle, type XrefSubject } from "./XrefWindow";
import {
    Disassembly, ImportsPane, SectionsPane, StringsPane, XrefsPane,
} from "./Panes";
import { useBreakpoint } from "./useBreakpoint";

/* No "Findings" tab. Findings have their own box in the left column now; a third
   copy of the same list would be one more place for it to disagree with itself. */
const DOCK_TABS = ["Strings", "Cross-references", "Imports", "Sections"] as const;
type DockTab = (typeof DOCK_TABS)[number];

interface Props {
    image: ImageInfo | null;
    functions: FunctionSummary[];
    findings: FindingsDocument | null;
    strings: ExtractedString[];
    onMessage: (text: string) => void;
    /** A function the global search asked to open. */
    gotoFunction?: string | null;
    onGotoConsumed?: () => void;
    /** Mirrors the selected function up to the shell, so the AI Analysis window
     *  can act on it. Selection still lives here; this only reports it. */
    onSelectionChange?: (detail: FunctionDetail | null) => void;
    /** The finding detail window is owned by the shell, because the AI Analysis tab
     *  opens it too. This only asks for it. */
    onExplainFinding: (finding: Finding) => void;
}

export default function AnalysisView({
    image, functions, findings, strings, onMessage, gotoFunction, onGotoConsumed,
    onSelectionChange, onExplainFinding,
}: Props) {
    const breakpoint = useBreakpoint();

    const [detail, setDetail] = useState<FunctionDetail | null>(null);
    const [selectedBlock, setSelectedBlock] = useState<string | null>(null);
    const [filter, setFilter] = useState("");
    const [dockTab, setDockTab] = useState<DockTab>("Strings");

    // Collapsed by default: the tree covers navigation, and these tables are for
    // when you want the tabular view specifically.
    const [dockOpen, setDockOpen] = useState(false);
    const [graphOpen, setGraphOpen] = useState(false);
    // "Who uses this?" for imports, strings and sections. A window rather than a
    // pane, for the same reason the graph is one: you want it beside the listing
    // you are reading, not instead of it.
    const [openXref, setOpenXref] = useState<XrefSubject | null>(null);
    const [showLibraryStrings, setShowLibraryStrings] = useState(false);
    const [aiFindings, setAiFindings] = useState<AiFinding[]>([]);
    const [n8nConfigured, setN8nConfigured] = useState<boolean | null>(null);

    // Which panes the centre tab strip must carry at this width.
    //
    // Below 860px the stylesheet sets `#col-functions { display: none }`, which
    // hides BOTH panels in the left column. Hiding without relocating is how panes
    // become unreachable - so everything that lives there has to reappear here.
    // The findings box is the newest occupant and the easiest to forget.
    const centerTabs = useMemo(() => {
        const tabs: string[] = [];
        if (breakpoint === "narrow") tabs.push("Symbols", "Findings");
        tabs.push("Assembly");
        if (breakpoint !== "wide") tabs.push("Decompiler");
        // No "Graph" tab: the graph lives in the floating window, where it can
        // sit beside the listing instead of replacing it.
        return tabs;
    }, [breakpoint]);

    const [centerTab, setCenterTab] = useState("Assembly");

    useEffect(() => {
        if (!centerTabs.includes(centerTab)) setCenterTab("Assembly");
    }, [centerTabs, centerTab]);

    const openFunction = useCallback(async (va: string) => {
        onMessage(`Loading ${va} ...`);
        try {
            const next = await getFunction(va);
            if (!next) {
                onMessage(`No detail available for ${va}`);
                return;
            }
            setDetail(next);
            onSelectionChange?.(next);
            setSelectedBlock(null);
            onMessage(`Loaded ${next.name}`);
            // On narrow screens the tree is a tab, so picking from it should move
            // to the code rather than leaving you looking at the tree.
            if (breakpoint === "narrow"
                && (centerTab === "Symbols" || centerTab === "Findings")) {
                setCenterTab("Assembly");
            }
        } catch (cause) {
            onMessage(`Load failed: ${(cause as Error).message}`);
        }
    }, [onMessage, breakpoint, centerTab, onSelectionChange]);

    /* AI findings arrive minutes after the engine's, so they are fetched
     * separately and merged in the box. Failure is silent on purpose: the engine
     * findings are the ones that matter, and an error banner for a missing
     * optional list would be noise. */
    useEffect(() => {
        let cancelled = false;
        void getAiFindings()
            .then((document) => {
                if (cancelled || !document) return;
                setAiFindings(document.findings);
                setN8nConfigured(document.n8n_configured);
            })
            .catch(() => { /* engine findings still render */ });
        return () => { cancelled = true; };
    }, [findings]);

    useEffect(() => {
        if (!detail && functions.length > 0) void openFunction(functions[0].va);
        // First arrival only; re-running would fight the user's selection.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [functions]);

    // The global search lives in the shell, so it hands the request down here
    // and this clears it once acted on.
    useEffect(() => {
        if (!gotoFunction) return;
        void openFunction(gotoFunction);
        onGotoConsumed?.();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [gotoFunction]);

    const selectBlock = useCallback((va: string) => {
        setSelectedBlock(va);
        const target = document.getElementById(`blk-${va}`);
        // Instant. A scroll that animates is a scroll you wait for.
        if (target) target.scrollIntoView({ block: "center" });
    }, []);

    const tree = (
        <SymbolTree
            functions={functions}
            image={image}
            strings={strings}
            currentVa={detail?.va ?? null}
            filter={filter}
            onOpenFunction={(va) => void openFunction(va)}
            onOpenXref={setOpenXref}
        />
    );

    const findingsBox = (
        <FindingsBox
            findings={findings}
            aiFindings={aiFindings}
            n8nConfigured={n8nConfigured}
            currentVa={detail?.va ?? null}
            onOpenFunction={(va) => void openFunction(va)}
            onExplain={onExplainFinding}
        />
    );

    const decompiler = detail ? (
        <Decompiler
            key={detail.va}
            detail={detail}
            selectedBlock={selectedBlock}
            onSelectBlock={selectBlock}
        />
    ) : (
        <div className="empty">Select a function.</div>
    );

    const graph = detail ? (
        <CfgGraph
            detail={detail}
            selectedBlock={selectedBlock}
            onSelectBlock={selectBlock}
        />
    ) : (
        <div className="empty">Select a function.</div>
    );

    return (
        <>
            <div className="toolbar">
                <span>Filter tree:</span>
                <input
                    className="xp"
                    style={{ width: 150 }}
                    value={filter}
                    placeholder="narrow the tree"
                    title="Filters the symbol tree. For jumping anywhere, use the search in the menu bar (Ctrl+K)."
                    onChange={(event) => setFilter(event.target.value)}
                />
                <button className="xp" onClick={() => setFilter("")}>Clear</button>
                <div className="sep" />
                <button
                    className="xp"
                    onClick={() => setGraphOpen((open) => !open)}
                    title="Open the control-flow graph in a movable window"
                >
                    {graphOpen ? "Close graph window" : "Graph window"}
                </button>
                <button className="xp" onClick={() => setDockOpen((open) => !open)}>
                    {dockOpen ? "Hide tables" : "Show tables"}
                </button>
                <span style={{ flex: 1 }} />
                {detail && (
                    <span className="dim">
                        {detail.blocks.length} blocks · {detail.instruction_count} insns ·
                        cx {detail.cyclomatic_complexity ?? "-"}
                        {detail.reachable_from_input && (
                            <span className="badge warn" style={{ marginLeft: 6 }}>
                                reachable from input
                            </span>
                        )}
                    </span>
                )}
            </div>

            <div className="workspace">
                {breakpoint !== "narrow" && (
                    <div className="column" id="col-functions">
                        <Panel caption="Symbol tree">{tree}</Panel>
                        <Panel
                            caption="Findings"
                            hint={
                                findings
                                    ? `${findings.summary.impactful} impactful`
                                    : undefined
                            }
                        >
                            {findingsBox}
                        </Panel>
                    </div>
                )}

                <div className="column" id="col-center">
                    <Panel
                        caption={detail ? detail.name : "Assembly"}
                        hint={detail?.va}
                        tabs={
                            <TabStrip
                                tabs={centerTabs}
                                active={centerTab}
                                onChange={setCenterTab}
                            />
                        }
                    >
                        {centerTab === "Symbols" && tree}

                        {/* Same component, same state - only the container moves. */}
                        {centerTab === "Findings" && findingsBox}

                        {centerTab === "Assembly" &&
                            (detail ? (
                                <Disassembly
                                    detail={detail}
                                    selectedBlock={selectedBlock}
                                    onSelectBlock={selectBlock}
                                />
                            ) : (
                                <div className="empty">Select a function.</div>
                            ))}

                        {centerTab === "Decompiler" && decompiler}
                    </Panel>
                </div>

                {breakpoint === "wide" && (
                    <div className="column" id="col-right">
                        <Panel caption="Decompiler" hint="AI-generated">
                            {decompiler}
                        </Panel>
                    </div>
                )}
            </div>

            <div className={`bottom-dock${dockOpen ? "" : " collapsed"}`}>
                <Panel
                    caption={
                        <span
                            style={{ cursor: "default" }}
                            onClick={() => setDockOpen((open) => !open)}
                            title="Click to show or hide"
                        >
                            {dockOpen ? "−" : "+"} Tables
                        </span>
                    }
                    tabs={
                        dockOpen ? (
                            <TabStrip tabs={DOCK_TABS} active={dockTab} onChange={setDockTab} />
                        ) : undefined
                    }
                >
                    {/* Gated on dockOpen, not just hidden by CSS. The collapsed
                        rule still exists for the caption/height, but visibility no
                        longer depends on the stylesheet having loaded. */}
                    {dockOpen && dockTab === "Strings" && (
                        <StringsPane
                            strings={strings}
                            onOpenXref={setOpenXref}
                            hasXrefIndex={Array.isArray(image?.string_xrefs)}
                            showLibrary={showLibraryStrings}
                            onShowLibrary={setShowLibraryStrings}
                        />
                    )}
                    {dockOpen && dockTab === "Cross-references" && (
                        <XrefsPane detail={detail} onOpen={(va) => void openFunction(va)} />
                    )}
                    {dockOpen && dockTab === "Imports" && (
                        <ImportsPane image={image} onOpenXref={setOpenXref} />
                    )}
                    {dockOpen && dockTab === "Sections" && (
                        <SectionsPane image={image} onOpenXref={setOpenXref} />
                    )}
                </Panel>
            </div>

            <MetricsBar
                image={image}
                functions={functions}
                findings={findings}
                onShowFindings={() => {
                    // The box is always visible in the left column, so there is
                    // nothing to reveal - scroll to it instead of opening a dock
                    // tab that no longer exists.
                    document.querySelector(".findingsbox")
                        ?.scrollIntoView({ block: "nearest" });
                }}
            />

            {/* Stays in this view rather than moving to the shell with the finding
                window: an xref list acts on the tree and dock tables that live
                here, and nothing outside this view opens one. */}
            {openXref && (
                <FloatingWindow
                    title={xrefTitle(openXref)}
                    hint="click Open to jump to a function"
                    onClose={() => setOpenXref(null)}
                    initial={{ x: 130, y: 110, width: 620, height: 460 }}
                >
                    <XrefWindow
                        subject={openXref}
                        image={image}
                        functions={functions}
                        onOpenFunction={(va) => {
                            void openFunction(va);
                            // Left open on purpose: working through a caller list
                            // one entry at a time is the normal way to use this.
                        }}
                    />
                </FloatingWindow>
            )}

            {/* Not an iframe: a floating panel stays in this component tree, so
                the graph shares `selectedBlock` with the listing and the
                click-to-highlight sync keeps working across both. */}
            {graphOpen && detail && (
                <FloatingWindow
                    title={`Graph — ${detail.name}`}
                    hint="drag title to move · corner to resize · double-click to maximise · Esc to close"
                    onClose={() => setGraphOpen(false)}
                    initial={{ width: 720, height: 520 }}
                >
                    {graph}
                </FloatingWindow>
            )}
        </>
    );
}
