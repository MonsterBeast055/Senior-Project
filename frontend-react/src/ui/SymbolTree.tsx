/*
 * SymbolTree.tsx - Ghidra-style navigation tree.
 *
 * Navigation only: functions, imports grouped by library, strings, sections.
 * Collapsed by default apart from Functions, because the point of a tree is that
 * closed folders cost one line each.
 *
 * Findings deliberately do NOT live here. A tree answers "where do I go"; a
 * finding is a conclusion, which is a different kind of thing. They have their own
 * box below this one - see FindingsBox.
 *
 * Rendering is flat: the recursive shape is flattened into a visible-row array
 * and only those rows are rendered. Nested <div>s per level would put a
 * 2712-function binary's whole subtree in the DOM even while collapsed.
 */
import { useMemo, useState } from "react";
import type { ExtractedString, FunctionSummary, ImageInfo } from "../api/types";
import type { XrefSubject } from "./XrefWindow";
import Explain from "./Explain";
import { ScoreDerivation } from "./Derivations";

type NodeKind = "folder" | "function" | "import" | "string" | "section";

interface TreeNode {
    id: string;
    kind: NodeKind;
    label: string;
    /** Right-aligned secondary text: score, severity, entropy. */
    meta?: string;
    /** Child count shown after the label. */
    count?: number;
    /** Set on leaves that navigate to a function. */
    va?: string;
    /** Set on leaves whose useful action is "show me who uses this" rather than
     *  "go to this address" - imports, strings, sections. */
    xref?: XrefSubject;
    children?: TreeNode[];
    /** Tints the row's severity. */
    severity?: string;
    /** Present on function leaves. Lets the row explain its own score on hover
     *  instead of showing a bare number nobody can check. */
    fn?: FunctionSummary;
}

/* How far a function has been taken.
 *
 * The engine analyses everything it discovers, so "not analysed by the engine"
 * would be an almost empty category and a useless colour. What is worth
 * distinguishing is where the engine's own result is unreliable — an unresolved
 * jump table leaves the control-flow graph incomplete at a known point — and
 * whether a model has been over it. */
export type AnalysisState = "ai" | "engine" | "limited";

const STATE_MARK: Record<AnalysisState, { glyph: string; cls: string; title: string }> = {
    ai: {
        glyph: "●",
        cls: "mk-ai",
        title: "Decompiled by the AI layer",
    },
    engine: {
        glyph: "●",
        cls: "mk-engine",
        title: "Analysed by the engine. No AI result yet.",
    },
    limited: {
        glyph: "●",
        cls: "mk-limited",
        title:
            "The engine's own analysis is incomplete here — an unresolved jump "
            + "target, or a thunk or library function that is deliberately never "
            + "sent to the model.",
    },
};

const ICONS: Record<NodeKind, { glyph: string; cls: string }> = {
    folder:   { glyph: "■", cls: "" },
    function: { glyph: "ƒ", cls: "fn" },
    import:   { glyph: "→", cls: "imp" },
    string:   { glyph: '"', cls: "str" },
    section:  { glyph: "≡", cls: "sect" },
};

function buildTree(
    functions: FunctionSummary[],
    image: ImageInfo | null,
    strings: ExtractedString[],
): TreeNode[] {
    const roots: TreeNode[] = [];

    // --- Functions ------------------------------------------------------
    // Split by triage score rather than listed flat. On a 2712-function binary
    // the useful question is "which of these is worth opening", and the engine
    // already answers it.
    const real = functions.filter((f) => !f.is_thunk && !f.is_imported_stub);
    const thunks = functions.filter((f) => f.is_thunk || f.is_imported_stub);
    const interesting = real.filter((f) => (f.information_score ?? 0) >= 20);
    const rest = real.filter((f) => (f.information_score ?? 0) < 20);

    const fnLeaf = (f: FunctionSummary): TreeNode => ({
        id: `fn:${f.va}`,
        kind: "function",
        label: f.name,
        meta: `${f.block_count} blk`,
        va: f.va,
        fn: f,
    });

    roots.push({
        id: "functions",
        kind: "folder",
        label: "Functions",
        count: real.length,
        children: [
            {
                id: "fn-interesting",
                kind: "folder",
                label: "Worth review (score ≥ 20)",
                count: interesting.length,
                children: interesting
                    .slice()
                    .sort((a, b) => (b.information_score ?? 0) - (a.information_score ?? 0))
                    .map((f) => ({ ...fnLeaf(f), meta: `sc ${f.information_score ?? 0}` })),
            },
            {
                id: "fn-rest",
                kind: "folder",
                label: "Other",
                count: rest.length,
                children: rest.map(fnLeaf),
            },
            {
                id: "fn-thunks",
                kind: "folder",
                label: "Thunks and import stubs",
                count: thunks.length,
                children: thunks.map(fnLeaf),
            },
        ],
    });

    // --- Imports, grouped by library ------------------------------------
    // Caller counts come from the engine's api_xrefs index. Built once here
    // rather than searched per row: a DLL with 1200 imports would otherwise do
    // 1200 linear scans of the same array on every render.
    //
    // `hasXrefIndex` is the important distinction, and getting it wrong is exactly
    // the bug this replaces. An absent index and an import with zero callers are
    // completely different facts: the first means "we did not compute this", the
    // second means "nothing calls it". Collapsing them labelled every single
    // import "unused" on any run produced by an engine build predating the index —
    // a confident, wrong answer.
    const hasXrefIndex = Array.isArray(image?.api_xrefs);
    const apiCallerCount = new Map<string, number>();
    (image?.api_xrefs ?? []).forEach((entry) => {
        apiCallerCount.set(entry.api, entry.count);
    });

    if (image && image.imports.length > 0) {
        const byLibrary = new Map<string, typeof image.imports>();
        image.imports.forEach((entry) => {
            const list = byLibrary.get(entry.library) ?? [];
            list.push(entry);
            byLibrary.set(entry.library, list);
        });

        roots.push({
            id: "imports",
            kind: "folder",
            label: "Imports",
            count: image.imports.length,
            children: [...byLibrary.entries()]
                .sort((a, b) => a[0].localeCompare(b[0]))
                .map(([library, entries]) => ({
                    id: `lib:${library}`,
                    kind: "folder" as NodeKind,
                    label: library,
                    count: entries.length,
                    children: entries.map((entry) => {
                        // `library!name` is how the engine keys api_xrefs, and how
                        // findings name their sink. Build it the same way here so
                        // the lookup cannot drift.
                        const api = `${entry.library}!${entry.name
                            || `ordinal_${entry.ordinal}`}`;
                        const callers = apiCallerCount.get(api) ?? 0;
                        return {
                            id: `imp:${entry.iat_slot}`,
                            kind: "import" as NodeKind,
                            label: entry.name || `ordinal ${entry.ordinal}`,
                            // With an index, the caller count is the useful number —
                            // an import called from 12 places matters more than one
                            // called from none. Without one, fall back to the IAT
                            // slot rather than claiming a count we do not have.
                            meta: !hasXrefIndex
                                ? "callers unknown"
                                : callers > 0
                                    ? `${callers} caller${callers === 1 ? "" : "s"}`
                                    : "no callers found",
                            // Clickable even with no index. Making the row inert was
                            // the wrong call: a row that shows an address and then
                            // does nothing when clicked teaches nothing, and looks
                            // like a broken feature. Clicking now opens a window that
                            // says what is missing and how to fix it.
                            xref: { kind: "api", name: api } as XrefSubject,
                        };
                    }),
                })),
        });
    }

    // --- Strings --------------------------------------------------------
    // No index check here: string rows are always clickable, and XrefWindow tells
    // the difference between "no index computed" and "nothing references it". Those
    // are different answers and both are better than a row that does nothing.
    if (strings.length > 0) {
        // Split, not filtered. Library strings are genuinely in the binary, so
        // hiding them outright would be a lie; putting them in their own closed
        // folder costs one line and keeps the program's own strings readable.
        const own = strings.filter((entry) => !entry.library_only);
        const runtime = strings.filter((entry) => entry.library_only);

        const stringLeaf = (entry: ExtractedString): TreeNode => ({
            id: `str:${entry.address}`,
            kind: "string",
            label: entry.text,
            meta: entry.refs ? `${entry.refs} ref${entry.refs === 1 ? "" : "s"}`
                             : entry.encoding,
            // Always clickable, even when the index is absent or nothing
            // references it — the window explains which of the two it is.
            xref: {
                kind: "string",
                address: entry.address,
                text: entry.text,
            } as XrefSubject,
        });

        roots.push({
            id: "strings",
            kind: "folder",
            label: "Strings",
            count: strings.length,
            children: runtime.length === 0
                // No point in a single-child grouping when there is nothing to
                // separate it from.
                ? own.map(stringLeaf)
                : [
                    {
                        id: "str-own",
                        kind: "folder" as NodeKind,
                        label: "Program strings",
                        count: own.length,
                        children: own.map(stringLeaf),
                    },
                    {
                        id: "str-runtime",
                        kind: "folder" as NodeKind,
                        label: "C runtime / library strings",
                        count: runtime.length,
                        children: runtime.map(stringLeaf),
                    },
                ],
        });
    }

    // --- Sections -------------------------------------------------------
    if (image) {
        roots.push({
            id: "sections",
            kind: "folder",
            label: "Sections",
            count: image.sections.length,
            children: image.sections.map((section) => ({
                id: `sect:${section.name}`,
                kind: "section",
                label: section.name,
                meta:
                    (section.readable ? "R" : "-") +
                    (section.writable ? "W" : "-") +
                    (section.executable ? "X" : "-") +
                    `  ${section.entropy.toFixed(2)}`,
                // High entropy in an executable section is the packing signal.
                severity: section.entropy > 7.0 && section.executable ? "high" : undefined,
                // Only executable sections contain functions, so only they get a
                // useful list. The window says so for the others rather than
                // showing an empty table.
                xref: { kind: "section", name: section.name } as XrefSubject,
            })),
        });
    }

    return roots;
}

interface Row {
    node: TreeNode;
    depth: number;
    expandable: boolean;
    expanded: boolean;
}

function flatten(
    nodes: TreeNode[],
    open: Set<string>,
    depth = 0,
    out: Row[] = [],
): Row[] {
    nodes.forEach((node) => {
        const expandable = !!node.children && node.children.length > 0;
        const expanded = expandable && open.has(node.id);
        out.push({ node, depth, expandable, expanded });
        if (expanded) flatten(node.children!, open, depth + 1, out);
    });
    return out;
}

/** Which mark a function gets. `analysed` holds the addresses with an AI result. */
function stateOf(fn: FunctionSummary, analysed: Set<string>): AnalysisState {
    if (analysed.has(fn.va)) return "ai";
    // Never going to be sent to a model, so "waiting for AI" would be a lie.
    if (fn.is_thunk || fn.is_imported_stub || fn.is_library_code) return "limited";
    // Nothing to show for itself: no blocks recovered at all.
    if ((fn.block_count ?? 0) === 0) return "limited";
    return "engine";
}

interface Props {
    functions: FunctionSummary[];
    image: ImageInfo | null;
    strings: ExtractedString[];
    currentVa: string | null;
    filter: string;
    /** Addresses that have a decompile result. Drives the green marks. */
    analysed?: Set<string>;
    onOpenFunction: (va: string) => void;
    /** Imports, strings and sections do not navigate to an address — they ask
     *  "who uses this". The shell opens a window for the answer. */
    onOpenXref?: (subject: XrefSubject) => void;
}

const NO_ANALYSIS: Set<string> = new Set();

export default function SymbolTree({
    functions, image, strings, currentVa, filter, analysed = NO_ANALYSIS,
    onOpenFunction, onOpenXref,
}: Props) {
    const [open, setOpen] = useState<Set<string>>(
        // Functions open by default: that is what a person came to look at.
        () => new Set([
            "functions", "fn-interesting",
            // Not "str-runtime": that folder existing but closed is the point.
            "str-own",
        ]),
    );

    const tree = useMemo(
        () => buildTree(functions, image, strings),
        [functions, image, strings],
    );

    // A filter that matched only leaves would hide them inside closed folders,
    // so filtering force-expands everything that still has a match.
    const { rows, filtering } = useMemo(() => {
        const needle = filter.trim().toLowerCase();
        if (!needle) return { rows: flatten(tree, open), filtering: false };

        function prune(nodes: TreeNode[]): TreeNode[] {
            const kept: TreeNode[] = [];
            nodes.forEach((node) => {
                const children = node.children ? prune(node.children) : undefined;
                const selfMatch =
                    node.label.toLowerCase().includes(needle) ||
                    (node.va ?? "").toLowerCase().includes(needle);
                if (selfMatch || (children && children.length > 0)) {
                    kept.push({ ...node, children });
                }
            });
            return kept;
        }

        const pruned = prune(tree);
        const allIds = new Set<string>();
        (function collect(nodes: TreeNode[]) {
            nodes.forEach((n) => { allIds.add(n.id); if (n.children) collect(n.children); });
        })(pruned);

        return { rows: flatten(pruned, allIds), filtering: true };
    }, [tree, open, filter]);

    function toggle(id: string) {
        setOpen((current) => {
            const next = new Set(current);
            if (next.has(id)) next.delete(id); else next.add(id);
            return next;
        });
    }

    if (rows.length === 0) {
        return <div className="empty">Nothing matches.</div>;
    }

    return (
        <div className="tree">
            {rows.map(({ node, depth, expandable, expanded }) => {
                const icon = ICONS[node.kind];
                const selected = node.va != null && node.va === currentVa
                                 && node.kind === "function";
                return (
                    <div
                        key={node.id}
                        className={`tnode${selected ? " selected" : ""}`}
                        title={
                            node.va
                                ? `${node.label}  ${node.va}`
                                : node.xref
                                    // Imports and strings have no code address of
                                    // their own, so say what clicking does instead
                                    // of showing a name the row already displays.
                                    ? `${node.label} — click to see which functions use this`
                                    : node.label
                        }
                        onClick={() => {
                            if (expandable) toggle(node.id);
                            else if (node.va) onOpenFunction(node.va);
                            // Leaves with no address of their own: the useful
                            // action is the reverse lookup, not navigation.
                            else if (node.xref) onOpenXref?.(node.xref);
                        }}
                    >
                        {Array.from({ length: depth }).map((_, index) => (
                            <span className="tindent" key={index} />
                        ))}

                        <span className={`ttoggle${expandable ? "" : " empty"}`}>
                            {expandable ? (expanded ? "−" : "+") : ""}
                        </span>

                        {/* Only on functions: an import or a string has nothing
                            to be analysed. */}
                        {node.kind === "function" && node.fn && (() => {
                            const mark = STATE_MARK[stateOf(node.fn, analysed)];
                            return (
                                <span className={`tmark ${mark.cls}`} title={mark.title}>
                                    {mark.glyph}
                                </span>
                            );
                        })()}

                        <span className={`ticon ${icon.cls}`}>{icon.glyph}</span>

                        <span className={`tlabel${node.kind === "string" ? "" : ""}`}>
                            {node.label}
                        </span>

                        {node.count != null && <span className="tcount">({node.count})</span>}

                        {node.meta && (
                            <span className="tmeta">
                                {node.fn ? (
                                    // Hovering the score shows the arithmetic behind
                                    // it. The whole point of publishing a triage
                                    // number is that someone can disagree with it.
                                    <Explain
                                        title={`Why score ${node.fn.information_score ?? 0}?`}
                                        anchor={<span className="explain-cue">{node.meta}</span>}
                                    >
                                        <ScoreDerivation fn={node.fn} />
                                    </Explain>
                                ) : node.severity && node.severity !== "informational" ? (
                                    <span className={`sev ${node.severity}`}>{node.meta}</span>
                                ) : (
                                    node.meta
                                )}
                            </span>
                        )}
                    </div>
                );
            })}
            {filtering && (
                <div className="dim" style={{ padding: "4px 8px" }}>
                    filtered — folders auto-expanded
                </div>
            )}
        </div>
    );
}
