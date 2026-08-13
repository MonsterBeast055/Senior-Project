/*
 * Panes.tsx - Disassembly listing and the bottom dock tables.
 */
import { Severity } from "./Chrome";
import type {
    ExtractedString, Finding, FindingsDocument, FunctionDetail, ImageInfo,
} from "../api/types";
import type { XrefSubject } from "./XrefWindow";

/* --- Disassembly -------------------------------------------------------- */

export function Disassembly({
    detail, selectedBlock, onSelectBlock, onHoverCall, onPinCall,
}: {
    detail: FunctionDetail;
    selectedBlock: string | null;
    onSelectBlock: (va: string) => void;
    /** Hover a call target. `va` is null when the pointer leaves it. */
    onHoverCall?: (va: string | null, element: HTMLElement | null) => void;
    /** Click a call target: same card, pinned, with actions. */
    onPinCall?: (va: string, element: HTMLElement) => void;
}) {
    return (
        <div className="code">
            {detail.blocks.map((block) => (
                <div key={block.start}>
                    <div
                        className="blockhdr"
                        id={`blk-${block.start}`}
                        onClick={() => onSelectBlock(block.start)}
                    >
                        {block.start}
                        {block.has_unresolved_exit && (
                            <span className="warn"> [unresolved exit]</span>
                        )}
                    </div>
                    {block.instructions.map((insn) => (
                        <div
                            key={insn.va}
                            className={`row${block.start === selectedBlock ? " highlight" : ""}`}
                            onClick={() => onSelectBlock(block.start)}
                        >
                            <span className="asm-addr">{insn.va}</span>
                            {"  "}
                            <span className="asm-mnem">{insn.mnemonic.padEnd(8)}</span>
                            <span className="asm-ops">{insn.operands}</span>
                            {/* The resolved name is what turns
                                `call qword [rip+0x1f0ce]` into CreateFileW.
                                For a call into the image it is also the handle
                                for the summary card — an import has no function
                                of ours behind it, so it stays inert text. */}
                            {insn.flow === "call" && insn.target ? (
                                <span
                                    className="asm-api asm-callto"
                                    onMouseEnter={(event) =>
                                        onHoverCall?.(insn.target!, event.currentTarget)}
                                    onMouseLeave={() => onHoverCall?.(null, null)}
                                    onClick={(event) => {
                                        // The row's own handler selects the block;
                                        // clicking the target means the target.
                                        event.stopPropagation();
                                        onPinCall?.(insn.target!, event.currentTarget);
                                    }}
                                >
                                    {"  ; " + (insn.target_name ?? insn.target)}
                                </span>
                            ) : insn.target_name ? (
                                <span className="asm-api">{"  ; " + insn.target_name}</span>
                            ) : null}
                        </div>
                    ))}
                </div>
            ))}
        </div>
    );
}

/* --- Findings ----------------------------------------------------------- */

export function FindingsPane({
    findings, onOpen, onExplain,
}: {
    findings: FindingsDocument | null;
    onOpen: (va: string) => void;
    /** Opens the detail window: engine facts, call path, and an optional AI
     *  explanation of impact. */
    onExplain?: (finding: Finding) => void;
}) {
    if (!findings) return <div className="empty">No findings.</div>;

    return (
        <>
            {/* Not decoration. Severity here is call-graph reachability, not
                taint analysis - it shows a path exists, not that attacker data
                reaches the argument. Drop this banner and the tool starts
                overstating its own confidence. */}
            <div className="notice">
                <b>Requires review.</b> {findings.methodology.note}
            </div>
            <table className="grid">
                <thead>
                    <tr>
                        <th style={{ width: 74 }}>Severity</th>
                        <th style={{ width: 104 }}>Function</th>
                        <th style={{ width: 120 }}>Kind</th>
                        <th>API</th>
                        <th style={{ width: 150 }}>Reachable from</th>
                        <th style={{ width: 56 }} className="num">Path</th>
                        <th style={{ width: 60 }} />
                    </tr>
                </thead>
                <tbody>
                    {findings.findings.map((finding, index) => (
                        <tr
                            key={index}
                            title={finding.limitation}
                            onClick={() => onOpen(finding.function)}
                        >
                            <td><Severity level={finding.severity} /></td>
                            <td className="mono">{finding.function}</td>
                            <td>{finding.kind}</td>
                            <td className="mono">{finding.api}</td>
                            <td>
                                {finding.sources.length > 0
                                    ? finding.sources.join(", ")
                                    : <span className="dim">not reachable</span>}
                            </td>
                            <td className="num dim">{finding.call_path.length}</td>
                            <td>
                                {onExplain && (
                                    <button
                                        className="xp"
                                        style={{ height: 17 }}
                                        title="Why is it rated this way?"
                                        onClick={(event) => {
                                            // The row navigates; the button must not.
                                            event.stopPropagation();
                                            onExplain(finding);
                                        }}
                                    >
                                        why?
                                    </button>
                                )}
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </>
    );
}

/* --- Strings ------------------------------------------------------------ */

export function StringsPane({
    strings, onOpenXref, hasXrefIndex = true, showLibrary = false, onShowLibrary,
}: {
    strings: ExtractedString[];
    onOpenXref?: (subject: XrefSubject) => void;
    /** False on runs analysed before string_xrefs existed. `refs` has always been
     *  emitted, so a positive count with no index is a real state. */
    hasXrefIndex?: boolean;
    /** Lifted so the choice survives switching dock tabs. */
    showLibrary?: boolean;
    onShowLibrary?: (show: boolean) => void;
}) {
    if (strings.length === 0) return <div className="empty">No strings.</div>;

    const runtimeCount = strings.filter((entry) => entry.library_only).length;
    const shown = showLibrary ? strings : strings.filter((entry) => !entry.library_only);

    return (
        <>
        {runtimeCount > 0 && (
            <div className="toolbar" style={{ borderBottom: "none" }}>
                <label style={{ display: "flex", alignItems: "center", gap: 4 }}>
                    <input
                        type="checkbox"
                        checked={showLibrary}
                        onChange={(event) => onShowLibrary?.(event.target.checked)}
                    />
                    Show C runtime strings
                </label>
                <span className="dim">
                    {runtimeCount} hidden — MSVC runtime literals like{" "}
                    <span className="mono">(null)</span>, present in every binary
                    built with it
                </span>
            </div>
        )}
        <table className="grid">
            <thead>
                <tr>
                    <th style={{ width: 110 }}>Address</th>
                    <th style={{ width: 56 }}>Enc</th>
                    <th style={{ width: 44 }} className="num">Refs</th>
                    <th>Text</th>
                    <th style={{ width: 58 }} />
                </tr>
            </thead>
            <tbody>
                {shown.map((entry) => (
                    <tr key={entry.address}>
                        <td className="mono">{entry.address}</td>
                        <td className="dim">{entry.encoding}</td>
                        <td className="num dim">{entry.refs ?? 0}</td>
                        <td className="mono asm-str">{entry.text}</td>
                        <td>
                            {/* Only offered when something references it. A "Uses"
                                button that always opens an empty list trains people
                                to stop clicking it. */}
                            {onOpenXref && hasXrefIndex && (entry.refs ?? 0) > 0 && (
                                <button
                                    className="xp"
                                    onClick={() => onOpenXref({
                                        kind: "string",
                                        address: entry.address,
                                        text: entry.text,
                                    })}
                                >
                                    Uses
                                </button>
                            )}
                        </td>
                    </tr>
                ))}
            </tbody>
        </table>
        </>
    );
}

/* --- Cross-references --------------------------------------------------- */

export function XrefsPane({
    detail, onOpen,
}: {
    detail: FunctionDetail | null;
    onOpen: (va: string) => void;
}) {
    if (!detail) return <div className="empty">Select a function.</div>;

    function table(title: string, list: { va: string; name: string }[]) {
        if (list.length === 0) {
            return <div className="empty">No {title.toLowerCase()}.</div>;
        }
        return (
            <table className="grid">
                <thead>
                    <tr>
                        <th style={{ width: 110 }}>Address</th>
                        <th>{title}</th>
                    </tr>
                </thead>
                <tbody>
                    {list.map((entry) => (
                        <tr key={entry.va} onClick={() => onOpen(entry.va)}>
                            <td className="mono">{entry.va}</td>
                            <td>{entry.name}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        );
    }

    return (
        <div style={{ display: "flex", gap: 6, alignItems: "flex-start" }}>
            <div style={{ flex: 1 }}>{table("Called by", detail.callers)}</div>
            <div style={{ flex: 1 }}>{table("Calls", detail.callees)}</div>
        </div>
    );
}

/* --- Imports and sections ----------------------------------------------- */

export function ImportsPane({
    image, onOpenXref,
}: {
    image: ImageInfo | null;
    onOpenXref?: (subject: XrefSubject) => void;
}) {
    if (!image) return <div className="empty">No image loaded.</div>;

    // Built once, not searched per row: a DLL can import well over a thousand
    // symbols and this table renders all of them.
    //
    // hasIndex separates "not computed" from "zero callers". Without it, a run from
    // an engine build predating api_xrefs shows 0 against every import, which reads
    // as a finding rather than a missing feature.
    const hasIndex = Array.isArray(image.api_xrefs);
    const callers = new Map<string, number>();
    (image.api_xrefs ?? []).forEach((entry) => callers.set(entry.api, entry.count));

    return (
        <>
        {/* Shown once at the top rather than as a tooltip on every row. The fix is
            a rebuild and a re-run, which is a thing to go and do, not a hint. */}
        {!hasIndex && (
            <div className="notice">
                <b>No cross-reference index in this run.</b> It was analysed by an
                engine build that did not emit{" "}
                <span className="mono">api_xrefs</span>, so caller counts are
                unknown — not zero. Rebuild the engine and re-run the binary.
            </div>
        )}
        <table className="grid">
            <thead>
                <tr>
                    <th style={{ width: 110 }}>IAT slot</th>
                    <th style={{ width: 280 }}>Library</th>
                    <th>Function</th>
                    <th style={{ width: 56 }} className="num">Callers</th>
                    <th style={{ width: 64 }} />
                </tr>
            </thead>
            <tbody>
                {image.imports.map((entry) => {
                    // Keyed exactly as the engine keys api_xrefs.
                    const api = `${entry.library}!${entry.name || `ordinal_${entry.ordinal}`}`;
                    const count = callers.get(api) ?? 0;
                    return (
                        <tr key={entry.iat_slot}>
                            <td className="mono">{entry.iat_slot}</td>
                            <td className="dim">{entry.library}</td>
                            <td className="mono">{entry.name}</td>
                            <td className="num">
                                {!hasIndex
                                    ? <span className="dim" title="This run was analysed before cross-reference indexes existed. Re-run it.">—</span>
                                    : count > 0 ? count : <span className="dim">0</span>}
                            </td>
                            <td>
                                {onOpenXref && hasIndex && count > 0 && (
                                    <button
                                        className="xp"
                                        onClick={() => onOpenXref({ kind: "api", name: api })}
                                    >
                                        Callers
                                    </button>
                                )}
                            </td>
                        </tr>
                    );
                })}
            </tbody>
        </table>
        </>
    );
}

export function SectionsPane({
    image, onOpenXref,
}: {
    image: ImageInfo | null;
    onOpenXref?: (subject: XrefSubject) => void;
}) {
    if (!image) return <div className="empty">No image loaded.</div>;
    return (
        <table className="grid">
            <thead>
                <tr>
                    <th style={{ width: 80 }}>Name</th>
                    <th style={{ width: 110 }}>Address</th>
                    <th style={{ width: 90 }} className="num">Virtual</th>
                    <th style={{ width: 90 }} className="num">Raw</th>
                    <th style={{ width: 70 }}>Flags</th>
                    <th style={{ width: 70 }} className="num">Entropy</th>
                    <th />
                </tr>
            </thead>
            <tbody>
                {image.sections.map((section) => (
                    <tr key={section.name}>
                        <td className="mono">{section.name}</td>
                        <td className="mono">{section.va}</td>
                        <td className="num">{section.virtual_size}</td>
                        <td className="num">{section.raw_size}</td>
                        <td className="mono">
                            {(section.readable ? "R" : "-") +
                             (section.writable ? "W" : "-") +
                             (section.executable ? "X" : "-")}
                        </td>
                        <td className="num">{section.entropy.toFixed(3)}</td>
                        <td>
                            {/* High entropy in an executable section is the
                                classic packing signal, so it is called out
                                rather than just printed. */}
                            {section.entropy > 7.0 && section.executable && (
                                <span className="badge warn">high entropy</span>
                            )}
                            {/* Only executable sections hold functions. Offering
                                the action on .rdata would promise a list that is
                                empty by definition. */}
                            {onOpenXref && section.executable && (
                                <button
                                    className="xp"
                                    style={{ marginLeft: 6 }}
                                    onClick={() =>
                                        onOpenXref({ kind: "section", name: section.name })}
                                >
                                    Functions
                                </button>
                            )}
                        </td>
                    </tr>
                ))}
            </tbody>
        </table>
    );
}
