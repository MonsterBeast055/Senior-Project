/*
 * XrefWindow.tsx - Who uses this?
 *
 * The reverse direction of the tree. Clicking an import used to do nothing, which
 * was the honest consequence of a real gap: jumping *to* an import is pointless
 * (its address is an IAT slot in .idata, holding a pointer, not code), so the only
 * useful move is showing the code that calls it. Same for a string, and for a
 * section — "which functions live here" beats "here are some data bytes".
 *
 * One component for all three because the answer is always the same shape: a list
 * of functions, each clickable. Only the question differs.
 */
import type { ImageInfo, FunctionSummary, XrefSite } from "../api/types";

export type XrefSubject =
    | { kind: "api"; name: string }
    | { kind: "string"; address: string; text: string }
    | { kind: "section"; name: string };

interface Props {
    subject: XrefSubject;
    image: ImageInfo | null;
    functions: FunctionSummary[];
    onOpenFunction: (va: string) => void;
}

/** Human-readable title for a subject, used by the window chrome too. */
export function xrefTitle(subject: XrefSubject): string {
    if (subject.kind === "api") return `Callers of ${subject.name}`;
    if (subject.kind === "section") return `Functions in ${subject.name}`;
    const clipped =
        subject.text.length > 42 ? `${subject.text.slice(0, 42)}…` : subject.text;
    return `Uses of "${clipped}"`;
}

/** Hex string compare that behaves like a number. Sorting "0x1000" next to
 *  "0x900" as text puts them in the wrong order. */
function byAddress(a: string, b: string): number {
    const left = BigInt(a);
    const right = BigInt(b);
    return left < right ? -1 : left > right ? 1 : 0;
}

export default function XrefWindow({ subject, image, functions, onOpenFunction }: Props) {
    /* Sites come from the engine for api and string subjects; sections are derived
     * here, because a section is a range and membership is just arithmetic — no
     * reason to make the engine emit a third index for it. */
    let sites: XrefSite[] = [];
    let missingIndex = false;
    let note: string | null = null;

    if (subject.kind === "api") {
        const entry = image?.api_xrefs?.find((x) => x.api === subject.name);
        if (!image?.api_xrefs) missingIndex = true;
        sites = entry?.functions ?? [];
        note =
            "The functions that call this import. An import has no code address of "
            + "its own — the hex beside it is its IAT slot, a pointer in .idata with "
            + "no instructions at it. Indirect calls through that slot are resolved "
            + "and counted here, which matters because that is how nearly every "
            + "Windows API call is compiled.";
    } else if (subject.kind === "string") {
        const entry = image?.string_xrefs?.find((x) => x.address === subject.address);
        if (!image?.string_xrefs) missingIndex = true;
        sites = entry?.functions ?? [];
        note = `String at ${subject.address}.`;
    } else {
        const section = image?.sections.find((s) => s.name === subject.name);
        if (!section) {
            return <div className="empty">No such section.</div>;
        }
        const start = BigInt(section.va);
        const end = start + BigInt(section.virtual_size);
        sites = functions
            .filter((f) => {
                const va = BigInt(f.va);
                return va >= start && va < end;
            })
            .map((f) => ({ va: f.va, name: f.name }));
        note = section.executable
            ? `${section.va} … ${`0x${end.toString(16)}`} · executable, so this is `
              + `where code lives.`
            // Worth saying rather than showing an empty list and letting someone
            // conclude the analysis failed.
            : `${section.va} … ${`0x${end.toString(16)}`} · not executable, so no `
              + `functions are expected here. Its contents are data — strings, `
              + `import tables, relocations.`;
    }

    if (missingIndex) {
        return (
            <div className="xrefwin">
                <div className="notice">
                    <b>This run has no cross-reference index, so there is no answer to
                    give — not an empty one.</b>
                    <br /><br />
                    It was analysed by an engine build that did not yet emit{" "}
                    <span className="mono">api_xrefs</span> and{" "}
                    <span className="mono">string_xrefs</span>. To fix it: rebuild the
                    engine (Visual Studio, x64-release) and upload the binary again.
                    Stored runs are not retro-fitted, because the indexes come out of
                    the engine rather than the API.
                </div>
                {/* The likely reason someone clicked. Worth answering here, because
                    the instinct is to expect navigation and the address on screen
                    makes that instinct look right. */}
                <p className="dim">
                    An import has no code address of its own. The hex you see next to
                    it is its <b>IAT slot</b> — a pointer in{" "}
                    <span className="mono">.idata</span> that the loader fills in at
                    run time. There are no instructions there to jump to, which is why
                    this window lists the functions that <i>call</i> the import instead.
                </p>
            </div>
        );
    }

    return (
        <div className="xrefwin">
            {note && <p className="dim" style={{ margin: "0 0 8px 0" }}>{note}</p>}

            {sites.length === 0 ? (
                <div className="empty">
                    Nothing references this in the analysed code.
                    <div className="dim" style={{ marginTop: 6 }}>
                        That can mean it genuinely is unused, or that the only reference
                        is through an indirect call or jump table the analysis could not
                        resolve.
                    </div>
                </div>
            ) : (
                <table className="grid">
                    <thead>
                        <tr>
                            <th style={{ width: 130 }}>Address</th>
                            <th>Function</th>
                            <th style={{ width: 62 }} />
                        </tr>
                    </thead>
                    <tbody>
                        {[...sites]
                            .sort((a, b) => byAddress(a.va, b.va))
                            .map((site) => (
                                <tr key={site.va}>
                                    <td className="mono">{site.va}</td>
                                    <td>{site.name}</td>
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
            )}

            <p className="dim" style={{ marginTop: 8 }}>
                {sites.length} {sites.length === 1 ? "function" : "functions"}.
            </p>
        </div>
    );
}
