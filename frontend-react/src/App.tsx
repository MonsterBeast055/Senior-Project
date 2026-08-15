/*
 * App.tsx - Shell: view routing, data loading, menus, status bar.
 *
 * Three views. Upload creates a run, Analysis inspects one, Reports lists what
 * is stored. Analysis is only reachable once a run is loaded — an empty
 * three-pane workspace is a worse first impression than a drop zone.
 *
 * The menu bar and the global search live here rather than in the workspace,
 * because both act on the whole run rather than on one pane.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
    configure, currentMode, currentRun, getFindings, getFunction, getFunctions,
    getHealth, getImage, getStrings, setRun, type DataMode,
} from "./api/client";
import type {
    ExtractedString, Finding, FindingsDocument, FunctionDetail, FunctionSummary,
    ImageInfo,
} from "./api/types";
import { StatusBar, TitleBar } from "./ui/Chrome";
import AnalysisView from "./ui/AnalysisView";
import AiAnalysisView from "./ui/AiAnalysisView";
import BackendStatus from "./ui/BackendStatus";
import Breadcrumb from "./ui/Breadcrumb";
import RootPath from "./ui/RootPath";
import SecurityView from "./ui/SecurityView";
import ContextPrompt from "./ui/ContextPrompt";
import FindingWindow from "./ui/FindingWindow";
import FloatingWindow from "./ui/FloatingWindow";
import MenuBar, { type MenuDefinition } from "./ui/MenuBar";
import ReportsView from "./ui/ReportsView";
import SummaryView from "./ui/SummaryView";
import UploadView from "./ui/UploadView";
import "./styles/xp.css";

/* Order here is the order of the tabs. AI Analysis sits between Analysis and
   Reports: you analyse a binary, then ask the model about it, then look back at
   what you have accumulated. */
type View = "upload" | "analysis" | "ai" | "security" | "summary" | "reports";

const VIEW_LABEL: Record<View, string> = {
    upload: "Upload",
    analysis: "Analysis",
    ai: "AI Analysis",
    security: "Security",
    summary: "Summary",
    reports: "Reports",
};

export default function App() {
    const [view, setView] = useState<View>("upload");
    // Live backend by default. Sample mode was the right default while no backend
    // existed; now that uploading works, starting in sample mode means the first
    // upload silently simulates itself, which is worse than a connection error.
    // Analysis → Data source still switches back for offline browsing.
    const [mode, setMode] = useState<DataMode>("api");
    const [apiBase, setApiBase] = useState("/api");

    const [runId, setRunId] = useState<string>("sample-notepad");
    const [fileName, setFileName] = useState("notepad.exe");
    const [image, setImage] = useState<ImageInfo | null>(null);
    const [functions, setFunctions] = useState<FunctionSummary[]>([]);
    const [findings, setFindings] = useState<FindingsDocument | null>(null);
    const [strings, setStrings] = useState<ExtractedString[]>([]);
    const [loaded, setLoaded] = useState(false);
    const [message, setMessage] = useState("Ready");

    const [contextOpen, setContextOpen] = useState(false);
    const [pendingFunction, setPendingFunction] = useState<string | null>(null);

    // Lifted out of AnalysisView so the AI window knows what is selected. The
    // workspace still owns the selection; this mirrors it.
    const [selectedDetail, setSelectedDetail] = useState<FunctionDetail | null>(null);
    // null while unknown. Three states rather than a boolean, so the menu can say
    // "unknown" instead of asserting "not configured" before the check returns.
    const [n8nReady, setN8nReady] = useState<boolean | null>(null);
    // Lifted out of AnalysisView: the AI tab opens it too, and two copies of a
    // floating window is how you end up with two of them on screen.
    const [openFinding, setOpenFinding] = useState<Finding | null>(null);

    /* --- Loading -------------------------------------------------------- */

    const loadRun = useCallback(async (id: string, askForContext = false) => {
        configure(mode, apiBase);
        setRun(id);
        setRunId(id);
        /* Both are addresses in the outgoing binary. Carrying them into the next
         * one would produce a trail of crumbs that resolve to nothing and a root
         * that may name an unrelated function at the same offset. */
        setNav({ trail: [], index: -1 });
        setRootVa(null);
        setMessage(`Loading run ${id} ...`);
        try {
            const [nextImage, nextFunctions, nextFindings, nextStrings] = await Promise.all([
                getImage(), getFunctions(), getFindings(), getStrings(),
            ]);
            setImage(nextImage);
            setFunctions(nextFunctions);
            setFindings(nextFindings);
            setStrings(nextStrings);
            setLoaded(true);
            setView("analysis");
            // Only after a fresh upload. Asking again every time a stored report
            // is reopened would make it something people click past.
            if (askForContext) setContextOpen(true);
            setMessage(currentMode() === "sample" ? "Ready (sample data)" : "Ready");
        } catch (cause) {
            setMessage(
                `Load failed: ${(cause as Error).message} — is the backend running? ` +
                `Switch Data to Sample to browse offline.`,
            );
        }
    }, [mode, apiBase]);

    useEffect(() => {
        configure(mode, apiBase);
        if (loaded) void loadRun(currentRun());
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [mode, apiBase]);

    // Asked once per data-source change, not polled: whether n8n is wired up is a
    // deployment fact, not a live signal.
    useEffect(() => {
        void getHealth().then((health) =>
            setN8nReady(health.reachable ? !!health.n8n_configured : null));
    }, [mode, apiBase]);

    /* --- Menus ---------------------------------------------------------- */

    const menus = useMemo<MenuDefinition[]>(() => [
        {
            title: "File",
            items: [
                { label: "Upload binary…", accel: "Ctrl+O", run: () => setView("upload") },
                { label: "Previous reports", accel: "Ctrl+R", run: () => setView("reports") },
                { separator: true, label: "" },
                {
                    label: "Reload this run",
                    accel: "F5",
                    enabled: loaded,
                    run: () => void loadRun(runId),
                },
                { separator: true, label: "" },
                {
                    label: "Export findings as JSON",
                    enabled: !!findings,
                    run: () => {
                        // Client-side download: the data is already here, so a
                        // round trip to the backend would add nothing.
                        const blob = new Blob([JSON.stringify(findings, null, 2)], {
                            type: "application/json",
                        });
                        const url = URL.createObjectURL(blob);
                        const anchor = document.createElement("a");
                        anchor.href = url;
                        anchor.download = `${runId}-findings.json`;
                        anchor.click();
                        URL.revokeObjectURL(url);
                    },
                },
            ],
        },
        {
            title: "Edit",
            items: [
                {
                    label: "Binary context…",
                    enabled: loaded,
                    run: () => setContextOpen(true),
                },
                { separator: true, label: "" },
                {
                    label: "Copy run id",
                    enabled: loaded,
                    run: () => void navigator.clipboard?.writeText(runId),
                },
            ],
        },
        {
            title: "View",
            items: [
                {
                    label: "Go to…",
                    accel: "Ctrl+K",
                    enabled: loaded,
                    run: () =>
                        (document.querySelector(
                            ".globalsearch input",
                        ) as HTMLInputElement | null)?.focus(),
                },
                { separator: true, label: "" },
                { label: "Upload", checked: view === "upload", run: () => setView("upload") },
                {
                    label: "Analysis",
                    checked: view === "analysis",
                    enabled: loaded,
                    run: () => setView("analysis"),
                },
                {
                    label: "AI Analysis",
                    checked: view === "ai",
                    enabled: loaded,
                    run: () => setView("ai"),
                },
                {
                    label: "Security",
                    checked: view === "security",
                    enabled: loaded,
                    run: () => setView("security"),
                },
                {
                    label: "Summary",
                    checked: view === "summary",
                    enabled: loaded,
                    run: () => setView("summary"),
                },
                { label: "Reports", checked: view === "reports", run: () => setView("reports") },
            ],
        },
        {
            title: "Analysis",
            items: [
                {
                    label: "Data source: sample",
                    checked: mode === "sample",
                    run: () => setMode("sample"),
                },
                {
                    label: "Data source: backend API",
                    checked: mode === "api",
                    run: () => setMode("api"),
                },
                { separator: true, label: "" },
                {
                    label: `Coverage: ${
                        image ? `${(image.coverage.code_fraction * 100).toFixed(1)}%` : "-"
                    }`,
                    enabled: false,
                },
                {
                    label: `Impactful findings: ${findings?.summary.impactful ?? 0}`,
                    enabled: false,
                },
                {
                    // Kept because it is the answer to "why is the AI Analysis tab
                    // empty", and there is nowhere else to look it up.
                    label: n8nReady === false
                        ? "AI layer (n8n): not configured"
                        : n8nReady === true
                            ? "AI layer (n8n): connected"
                            : "AI layer (n8n): unknown",
                    enabled: false,
                },
            ],
        },
        {
            title: "Help",
            items: [
                {
                    label: "How severity is decided",
                    run: () =>
                        setMessage(
                            "Severity is derived by the engine from the sink kind plus " +
                            "whether untrusted input can reach it. The AI explains impact; " +
                            "it never sets the rating.",
                        ),
                },
                {
                    label: "Keyboard: Ctrl+K search, Esc close window",
                    enabled: false,
                },
            ],
        },
    ], [view, mode, loaded, runId, image, findings, loadRun, n8nReady]);

    /* --- Navigation history --------------------------------------------- */

    /* Lives here rather than in AnalysisView because both tabs navigate, and two
     * histories that each saw half the moves is worse than none.
     *
     * One piece of state, not two. `trail` and `index` change together on every
     * move, and as separate useStates a stale closure could advance one without
     * the other — which shows up as a breadcrumb pointing at the wrong crumb. */
    const [nav, setNav] = useState<{ trail: string[]; index: number }>({
        trail: [], index: -1,
    });
    /* The function under investigation, if one has been pinned. Separate from
     * the trail on purpose: the trail is where you have been, this is what for.
     * Survives navigation; cleared when the run changes, since an address means
     * nothing in a different binary. */
    const [rootVa, setRootVa] = useState<string | null>(null);
    // Read inside callbacks that must not re-create themselves on every move.
    const navRef = useRef(nav);
    useEffect(() => { navRef.current = nav; }, [nav]);
    /* The address a Back/Forward/crumb jump is expecting, or null.
     *
     * A jump's selection comes back through the same path as a fresh click, and
     * without this the trail would grow every time you tried to retrace it —
     * going back would append the destination instead of moving the pointer.
     *
     * It holds the address rather than a boolean because a jump can fail: if the
     * function will not load, no selection arrives and a boolean would stay set,
     * silently swallowing the next genuine navigation. Comparing addresses means
     * a mismatch is treated as the real move it is. */
    const replayingTo = useRef<string | null>(null);

    const recordVisit = useCallback((va: string) => {
        if (replayingTo.current === va) { replayingTo.current = null; return; }
        replayingTo.current = null;
        setNav(({ trail, index }) => {
            // Re-selecting what is already current is not a move.
            if (trail[index] === va) return { trail, index };
            // Navigating after going back discards the forward entries, the way
            // a browser does: they describe a future you did not take.
            const kept = [...trail.slice(0, index + 1), va];
            // Capped so a long session cannot grow without bound. Dropping the
            // oldest is right — a trail is about recent descent.
            const capped = kept.slice(-40);
            return { trail: capped, index: capped.length - 1 };
        });
    }, []);

    const goToHistory = useCallback((index: number) => {
        const { trail } = navRef.current;
        if (index < 0 || index >= trail.length) return;
        replayingTo.current = trail[index];
        setNav((current) => ({ ...current, index }));
        setView("analysis");
        setPendingFunction(trail[index]);
    }, []);

    /* Alt+Arrow matches every browser. Esc is IDA's, and RE people reach for it
     * without thinking — but only when nothing else wants it, so a floating
     * window or a pinned card keeps first claim on the key. */
    useEffect(() => {
        const onKey = (event: KeyboardEvent) => {
            if (event.defaultPrevented) return;
            const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(
                (event.target as HTMLElement)?.tagName ?? "");
            if (typing) return;

            if (event.altKey && event.key === "ArrowLeft") {
                event.preventDefault();
                goToHistory(navRef.current.index - 1);
            } else if (event.altKey && event.key === "ArrowRight") {
                event.preventDefault();
                goToHistory(navRef.current.index + 1);
            } else if (event.key === "Escape" && navRef.current.index > 0) {
                goToHistory(navRef.current.index - 1);
            }
        };
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [goToHistory]);

    /* --- Selection ------------------------------------------------------ */

    /* Loads a function and makes it the current selection, without changing view.
     * The Analysis tab reports its own selection up through onSelectionChange; the
     * AI tab's tree calls this. Both end at the same piece of state, so the two
     * views never disagree about what is selected. */
    const selectFunction = useCallback(async (va: string) => {
        try {
            const next = await getFunction(va);
            if (!next) {
                setMessage(`No detail available for ${va}`);
                return;
            }
            setSelectedDetail(next);
            setMessage(`Selected ${next.name}`);
        } catch (cause) {
            setMessage(`Load failed: ${(cause as Error).message}`);
        }
    }, []);

    /* --- Search routes into the analysis view --------------------------- */

    const onOpenFunction = useCallback((va: string) => {
        setView("analysis");
        setPendingFunction(va);
    }, []);

    const coverage = image
        ? `coverage ${(image.coverage.code_fraction * 100).toFixed(1)}%  ` +
          `${image.coverage.function_count} functions`
        : "-";

    return (
        <div id="app">
            <TitleBar
                title={
                    "Senior-Project Binary Analyzer" +
                    (loaded && image ? ` — ${fileName}` : "")
                }
            />

            <MenuBar
                menus={menus}
                functions={functions}
                image={image}
                strings={strings}
                findings={findings}
                onOpenFunction={onOpenFunction}
                searchEnabled={loaded}
            />

            <div className="viewnav">
                {(["upload", "analysis", "ai", "security", "summary", "reports"] as View[]).map((id) => {
                    // Every view but Upload and Reports needs a loaded run: one
                    // has nothing to show, one nothing to ask about, one no binary
                    // to inspect, and one no runs to track.
                    const enabled = !["analysis", "ai", "security", "summary"].includes(id) || loaded;
                    return (
                        <div
                            key={id}
                            className={
                                `vtab${view === id ? " active" : ""}` +
                                (enabled ? "" : " disabled")
                            }
                            onClick={() => enabled && setView(id)}
                            title={enabled ? undefined : "Upload or open a report first"}
                        >
                            {VIEW_LABEL[id]}
                        </div>
                    );
                })}
                <span style={{ flex: 1 }} />
                <div style={{ display: "flex", alignItems: "center", gap: 5, padding: "2px 4px" }}>
                    {/* Two processes have to be running. When one is not, this is
                        where you find out — rather than in the Vite terminal. */}
                    <BackendStatus nonce={`${mode}:${apiBase}`} />
                    <span className="dim">{mode === "sample" ? "" : apiBase}</span>
                    {mode === "api" && (
                        <input
                            className="xp"
                            style={{ width: 140 }}
                            value={apiBase}
                            onChange={(event) => setApiBase(event.target.value)}
                            title="API base URL"
                        />
                    )}
                </div>
            </div>

            {/* Always mounted: the upload progress poll lives inside it, and
                switching to Reports mid-analysis used to stop the tracking. */}
            <UploadView
                hidden={view !== "upload"}
                onOpenRun={(id, name) => {
                    if (name) setFileName(name);
                    void loadRun(id, true);
                }}
            />

            {/* Mounted whenever a run is loaded, hidden rather than unmounted when
                another tab is showing. An automated run is driven by this view's
                own poll — it starts each stage when the previous one settles — so
                unmounting it on a tab switch silently halted the run partway
                through. Switching to Reports mid-run used to leave decompilation
                finished and bug hunting never started, with no error to show for
                it.

                Reports is the only view still unmounted on a switch: it is a
                list refetched on mount, holding no timer and no state a user
                could lose. */}
            {loaded && (
                <AiAnalysisView
                    hidden={view !== "ai"}
                    detail={selectedDetail}
                    onSelectFunction={(va) => void selectFunction(va)}
                    onOpenFunction={onOpenFunction}
                    onMessage={setMessage}
                    functions={functions}
                    image={image}
                    strings={strings}
                    findings={findings}
                    onExplainFinding={setOpenFinding}
                    onGoHome={() => setView("upload")}
                />
            )}

            {/* Conditional, unlike Analysis and AI: this view holds no timer and
                no state a user could lose, and the backend remembers whether a
                hardened build exists, so returning restores everything. */}
            {view === "security" && loaded && (
                <SecurityView fileName={fileName} onMessage={setMessage} />
            )}

            {/* Conditional for the same reason as Security: it holds no timer
                and no unsaved state. Everything it shows is read back from the
                job files, so leaving and returning costs nothing. */}
            {view === "summary" && loaded && (
                <SummaryView
                    onMessage={setMessage}
                    onOpenFunction={(va) => {
                        void selectFunction(va);
                        setView("analysis");
                    }}
                />
            )}

            {view === "reports" && (
                <ReportsView
                    currentRun={runId}
                    onOpenRun={(id, name) => {
                        if (name) setFileName(name);
                        void loadRun(id);
                    }}
                />
            )}

            {/* Only on Analysis: it describes a descent through functions, and
                the other views do not have one. */}
            {view === "analysis" && loaded && (
                <Breadcrumb
                    trail={nav.trail}
                    index={nav.index}
                    functions={functions}
                    onJump={goToHistory}
                    onBack={() => goToHistory(nav.index - 1)}
                    onForward={() => goToHistory(nav.index + 1)}
                    onPinRoot={() => {
                        const here = nav.trail[nav.index];
                        if (here) setRootVa(here);
                    }}
                    rootPinned={rootVa !== null}
                />
            )}

            {view === "analysis" && loaded && rootVa && (
                <RootPath
                    rootVa={rootVa}
                    currentVa={nav.trail[nav.index] ?? null}
                    runId={runId}
                    functions={functions}
                    onJump={onOpenFunction}
                    onUnpin={() => setRootVa(null)}
                />
            )}

            {/* Mounted for the life of the run, hidden when another tab shows.
                Same reasoning as the AI tab above: this view owns the selected
                function, the open graph window, the tree filter, the dock state
                and every inline expansion, none of which survives an unmount and
                none of which the shell can restore. Going to Reports and back
                used to reset the workspace to the first function. */}
            {loaded && (
                <AnalysisView
                    hidden={view !== "analysis"}
                    image={image}
                    functions={functions}
                    findings={findings}
                    strings={strings}
                    onMessage={setMessage}
                    gotoFunction={pendingFunction}
                    onGotoConsumed={() => setPendingFunction(null)}
                    onSelectionChange={(next) => {
                        setSelectedDetail(next);
                        // Every route into a function funnels through here —
                        // tree, xrefs, search, call card — so this is the one
                        // place the trail has to be recorded.
                        if (next) recordVisit(next.va);
                    }}
                    onExplainFinding={setOpenFinding}
                />
            )}

            {/* Why is this rated high? Engine facts and the call path first, AI
                narrative second, clearly separated. Owned here because both the
                Analysis and AI Analysis tabs open it. */}
            {openFinding && (
                <FloatingWindow
                    title={`Finding — ${openFinding.kind}`}
                    hint={`${openFinding.severity} · ${openFinding.function}`}
                    onClose={() => setOpenFinding(null)}
                    initial={{ x: 90, y: 90, width: 720, height: 560 }}
                >
                    <FindingWindow
                        finding={openFinding}
                        onOpenFunction={onOpenFunction}
                    />
                </FloatingWindow>
            )}

            {/* Post-upload, and reopenable from Edit. Skippable — a prompt that
                blocks the workspace gets dismissed reflexively. */}
            {contextOpen && (
                <FloatingWindow
                    title="What do you know about this binary?"
                    hint="optional · improves AI output more than any engine feature"
                    onClose={() => setContextOpen(false)}
                    initial={{ x: 70, y: 70, width: 640, height: 560 }}
                >
                    <ContextPrompt
                        image={image}
                        fileName={fileName}
                        onDone={() => {
                            setContextOpen(false);
                            setMessage("Context saved — it will be included in AI prompts.");
                        }}
                    />
                </FloatingWindow>
            )}

            <StatusBar
                cells={[
                    { text: image ? fileName : "No run" },
                    { text: image ? `${image.arch}  base ${image.image_base}` : "-" },
                    { text: coverage },
                    { text: message, grow: true },
                ]}
            />
        </div>
    );
}
