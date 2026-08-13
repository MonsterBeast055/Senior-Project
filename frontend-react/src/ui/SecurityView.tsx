/*
 * SecurityView.tsx - Exploit mitigations, and producing a hardened build.
 *
 * The engine could already do all of this; it was reachable only from the
 * command line, which in a browser-based tool means nobody using the tool ever
 * saw it. This is that capability, in the application.
 *
 * The claim this page makes is deliberately narrow, and the wording matters.
 * Enabling DEP does not fix an overflow — the overflow still happens. What it
 * removes is the attacker's ability to execute what they wrote into the buffer,
 * so the program crashes instead of running their code. Saying "hardened" and
 * meaning "repaired" would be exactly the overstatement the rest of this project
 * is built to avoid, so the page says which of the two it did.
 */
import { useCallback, useEffect, useState } from "react";
import { getMitigations, hardenBinary, hardenedDownloadUrl } from "../api/client";
// From types, not client: client imports these for its own signatures and does
// not re-export them.
import type { HardenResponse, MitigationsResponse } from "../api/types";

/** One row of the checklist. `fixable` marks what this tool can turn on. */
function Check({
    label, on, detail, fixable,
}: {
    label: string;
    on: boolean | undefined;
    detail: string;
    fixable: boolean;
}) {
    return (
        <tr>
            <td style={{ whiteSpace: "nowrap" }}>
                <span className={on ? "sev informational" : "sev medium"}>
                    {on ? "enabled" : "missing"}
                </span>
            </td>
            <td><b>{label}</b></td>
            <td className="dim">
                {detail}
                {!fixable && !on && (
                    <span> This cannot be added to an existing binary.</span>
                )}
            </td>
        </tr>
    );
}

export default function SecurityView({
    fileName, hidden = false, onMessage,
}: {
    fileName: string;
    hidden?: boolean;
    onMessage: (text: string) => void;
}) {
    const [report, setReport] = useState<MitigationsResponse | null>(null);
    const [result, setResult] = useState<HardenResponse | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);
    /* Off by default and never implied by the main button: it is the only
     * change here that can stop the program working. */
    const [fixWx, setFixWx] = useState(false);

    const load = useCallback(async () => {
        setError(null);
        try {
            setReport(await getMitigations());
        } catch (cause) {
            setReport(null);
            setError((cause as Error).message);
        }
    }, []);

    useEffect(() => { void load(); }, [load]);

    async function onHarden(options: { allowSigned?: boolean; fixWx?: boolean } = {}) {
        setBusy(true);
        setError(null);
        try {
            const next = await hardenBinary(options);
            setResult(next);
            onMessage(next.applied.length > 0
                ? `Hardened: ${next.applied.length} mitigation(s) enabled.`
                : "Nothing could be applied — see the reasons below.");
            await load();
        } catch (cause) {
            setError((cause as Error).message);
        } finally {
            setBusy(false);
        }
    }

    return (
        <div className={`page${hidden ? " hidden" : ""}`}>
            <div className="page-inner">
                <h1>Security mitigations</h1>
                <p className="dim">
                    What <b>{fileName}</b> asks the Windows loader to do for it, and
                    what this tool can raise. Read alongside the findings: these are
                    different claims about different things.
                </p>

                <div className="notice">
                    <b>This does not repair the defects the analysis found.</b> It
                    changes how the loader treats the image. Enabling DEP does not fix
                    an overflow — the overflow still happens, but the attacker's code
                    lands in memory that cannot execute, so the program crashes instead
                    of being taken over. Repairing the code itself would need the size
                    of each destination buffer, which this engine cannot derive; a
                    rewrite that guessed one could not be shown correct.
                </div>

                {error && (
                    <div className="notice">
                        <b>Could not read the binary.</b> {error}
                    </div>
                )}

                {!report && !error && <div className="empty">Reading headers&hellip;</div>}

                {report && report.parsed === false && (
                    <div className="notice">
                        <b>Not a readable PE image.</b> {report.problem}
                    </div>
                )}

                {/* The three states above are "loading", "parsed" and "not a PE".
                    A response that is none of them - a shape change, a field
                    renamed - matched no branch and rendered a blank page, which
                    is the least debuggable failure there is. Say so instead. */}
                {report && report.parsed === undefined && !error && (
                    <div className="notice">
                        <b>Unexpected response from the engine.</b> The mitigation
                        report came back without a <span className="mono">parsed</span>{" "}
                        field, so this page cannot read it. That usually means the
                        engine and this build disagree about the output shape — check{" "}
                        <span className="mono">/api/runs/&lt;id&gt;/mitigations</span>{" "}
                        directly.
                        <br />
                        <br />
                        <span className="mono dim">
                            {Object.keys(report).join(", ") || "(empty object)"}
                        </span>
                    </div>
                )}

                {report?.parsed && (
                    <>
                        <h2>Current state</h2>
                        <table className="grid">
                            <tbody>
                                <Check
                                    label="DEP (NX)"
                                    on={report.dep}
                                    fixable
                                    detail="Marks the stack and heap non-executable, so data written by an overflow cannot be run as code."
                                />
                                <Check
                                    label="ASLR"
                                    on={report.aslr}
                                    fixable
                                    detail="Loads the image at a randomised base, so an attacker cannot predict addresses."
                                />
                                <Check
                                    label="High-entropy ASLR"
                                    on={report.high_entropy_va}
                                    fixable
                                    detail="Full 64-bit randomisation range. Applies to 64-bit images only."
                                />
                                <Check
                                    label="W^X (no writable+executable section)"
                                    on={report.has_write_execute === false}
                                    fixable
                                    detail="Memory an attacker can write to and then execute is the shape most exploits need. No correct program requires both permissions on the same section."
                                />
                                <Check
                                    label="Control Flow Guard"
                                    on={report.cfg}
                                    fixable={false}
                                    detail="Validates indirect call targets at run time. It needs guard tables the compiler emits — rebuild with /guard:cf."
                                />
                            </tbody>
                        </table>

                        {/* Only when there is something to look at. A clean image
                            does not need its whole section table on screen. */}
                        {report.has_write_execute && report.sections && (
                            <>
                                <p className="dim">
                                    Sections carrying both permissions:
                                </p>
                                <table className="grid">
                                    <tbody>
                                        {report.sections.filter((s) => s.write_execute).map((s) => (
                                            <tr key={s.name}>
                                                <td className="mono">{s.name}</td>
                                                <td className="dim">
                                                    {[s.read && "read", s.write && "write",
                                                      s.execute && "execute"]
                                                        .filter(Boolean).join(" + ")}
                                                </td>
                                                <td className="dim">
                                                    {s.code
                                                        ? "holds code — the write permission is the one to remove"
                                                        : "holds data — the execute permission is the one to remove"}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                                {/* Named as the one risky change, because it is. */}
                                <div className="notice">
                                    <b>This is the one fix that can break the program.</b>{" "}
                                    Setting DEP or ASLR asks the loader to treat the image
                                    more strictly than it already was. Removing a
                                    section&apos;s write permission removes something the
                                    program may genuinely use — a packer decompressing
                                    into its own section, or self-modifying code, will
                                    fault on the first store. It is almost always a build
                                    accident, but &ldquo;almost always&rdquo; is not a
                                    basis for changing it without being asked.
                                </div>
                            </>
                        )}

                        <h2>Preconditions</h2>
                        <table className="grid">
                            <tbody>
                                <tr>
                                    <td style={{ whiteSpace: "nowrap" }}>
                                        <span className={report.has_relocations
                                            ? "sev informational" : "sev high"}>
                                            {report.has_relocations ? "present" : "absent"}
                                        </span>
                                    </td>
                                    <td><b>Relocation data</b></td>
                                    <td className="dim">
                                        ASLR needs it: without relocations the loader cannot
                                        place the image anywhere but its preferred base, so
                                        setting the flag would produce an image that is at
                                        best ignored and at worst fails to load.
                                        {report.relocations_stripped
                                            && " The COFF header says relocations were stripped."}
                                    </td>
                                </tr>
                                <tr>
                                    <td style={{ whiteSpace: "nowrap" }}>
                                        <span className={report.signed_image
                                            ? "sev medium" : "sev informational"}>
                                            {report.signed_image ? "signed" : "unsigned"}
                                        </span>
                                    </td>
                                    <td><b>Authenticode signature</b></td>
                                    <td className="dim">
                                        {report.signed_image
                                            ? "Any edit invalidates it. Hardening is refused unless you allow it deliberately, and the result would need re-signing."
                                            : "Nothing to invalidate."}
                                    </td>
                                </tr>
                                <tr>
                                    <td style={{ whiteSpace: "nowrap" }}>
                                        <span className="dim">{report.format}</span>
                                    </td>
                                    <td><b>Format</b></td>
                                    <td className="dim">
                                        Characteristics{" "}
                                        <span className="mono">{report.dll_characteristics}</span>
                                        {". Header checksum "}
                                        {report.checksum_valid ? "valid" : "stale"}.
                                    </td>
                                </tr>
                            </tbody>
                        </table>

                        {/* Stack cookies are code, not a header bit. Saying "off"
                            would imply this tool could turn them on. */}
                        <p className="dim">
                            <b>Stack cookies (/GS)</b> cannot be shown here at all. They
                            are compiler-emitted code rather than a header flag, so their
                            presence is not visible from the headers and cannot be added
                            to a finished binary. Rebuild with <span className="mono">/GS</span>.
                        </p>

                        <h2>Produce a hardened build</h2>
                        {report.fully_hardened ? (
                            <div className="notice">
                                <b>Already hardened.</b> Everything this tool can enable is
                                enabled. Running it would produce a byte-identical file.
                            </div>
                        ) : (
                            <p className="dim">
                                Writes a copy with the supported mitigations enabled and the
                                header checksum recomputed. The uploaded original is never
                                modified — it is the evidence every stored finding was
                                derived from.
                            </p>
                        )}

                        <div className="toolbar" style={{ borderTop: "none" }}>
                            <button
                                className="xp"
                                disabled={busy || report.fully_hardened}
                                onClick={() => void onHarden({ fixWx })}
                            >
                                {busy ? "Working…" : "Harden this binary"}
                            </button>
                            {report.signed_image && (
                                <button
                                    className="xp"
                                    disabled={busy}
                                    onClick={() => void onHarden({ allowSigned: true, fixWx })}
                                    title="Proceed even though it breaks the signature"
                                >
                                    Harden anyway (breaks signature)
                                </button>
                            )}
                            {report.has_write_execute && (
                                <label title="Removes the conflicting permission from each section that has both">
                                    <input
                                        type="checkbox"
                                        checked={fixWx}
                                        onChange={() => setFixWx((on) => !on)}
                                    />{" "}
                                    also enforce W^X
                                </label>
                            )}
                            <span style={{ flex: 1 }} />
                            {report.hardened?.available && (
                                <a className="xp" href={hardenedDownloadUrl()}>
                                    Download hardened executable
                                </a>
                            )}
                        </div>
                    </>
                )}

                {result && (
                    <>
                        <h2>Result</h2>
                        {!result.ok && (
                            <div className="notice">
                                <b>Refused.</b> {result.problem}
                            </div>
                        )}

                        {result.applied.length > 0 && (
                            <>
                                <p><b>Applied</b></p>
                                <ul style={{ margin: "0 0 10px 18px" }}>
                                    {result.applied.map((line, index) => (
                                        <li key={index}>{line}</li>
                                    ))}
                                </ul>
                            </>
                        )}

                        {/* Shown as prominently as the successes. A tool that knows
                            when it must not act is the more interesting claim. */}
                        {result.refused.length > 0 && (
                            <>
                                <p><b>Not applied, and why</b></p>
                                <ul style={{ margin: "0 0 10px 18px" }} className="dim">
                                    {result.refused.map((line, index) => (
                                        <li key={index}>{line}</li>
                                    ))}
                                </ul>
                            </>
                        )}

                        {/* The result stated as a diff rather than as prose. The
                            engine re-inspects the file it has just written, so
                            these are two independent readings — the "after"
                            column is measured from the produced bytes, not
                            predicted from what was requested. */}
                        {result.before?.parsed && result.after?.parsed && (
                            <>
                                <h2>Before and after</h2>
                                <table className="grid">
                                    <thead>
                                        <tr>
                                            <th>Mitigation</th>
                                            <th>Before</th>
                                            <th>After</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {([
                                            ["DEP (NX)", "dep"],
                                            ["ASLR", "aslr"],
                                            ["High-entropy ASLR", "high_entropy_va"],
                                            ["Control Flow Guard", "cfg"],
                                        ] as [string, keyof typeof result.before][]).map(
                                            ([label, key]) => {
                                                const was = Boolean(result.before[key]);
                                                const now = Boolean(result.after[key]);
                                                return (
                                                    <tr key={label}>
                                                        <td><b>{label}</b></td>
                                                        <td>
                                                            <span className={was
                                                                ? "sev informational" : "sev medium"}>
                                                                {was ? "enabled" : "missing"}
                                                            </span>
                                                        </td>
                                                        <td>
                                                            <span className={now
                                                                ? "sev informational" : "sev medium"}>
                                                                {now ? "enabled" : "missing"}
                                                            </span>
                                                            {!was && now && (
                                                                <span className="fbsrc engine">
                                                                    {"  "}changed
                                                                </span>
                                                            )}
                                                        </td>
                                                    </tr>
                                                );
                                            })}
                                        <tr>
                                            <td><b>W^X clean</b></td>
                                            <td>
                                                <span className={result.before.has_write_execute
                                                    ? "sev medium" : "sev informational"}>
                                                    {result.before.has_write_execute ? "no" : "yes"}
                                                </span>
                                            </td>
                                            <td>
                                                <span className={result.after.has_write_execute
                                                    ? "sev medium" : "sev informational"}>
                                                    {result.after.has_write_execute ? "no" : "yes"}
                                                </span>
                                                {result.before.has_write_execute
                                                    && !result.after.has_write_execute && (
                                                    <span className="fbsrc engine">{"  "}changed</span>
                                                )}
                                            </td>
                                        </tr>
                                        <tr>
                                            <td><b>Header checksum</b></td>
                                            <td className="dim">
                                                {result.before.checksum_valid ? "valid" : "stale"}
                                            </td>
                                            <td className="dim">
                                                {result.after.checksum_valid ? "valid" : "stale"}
                                            </td>
                                        </tr>
                                    </tbody>
                                </table>
                            </>
                        )}

                        <div className="notice">
                            <b>Verify it independently.</b> Do not take this page's word
                            for it — run Microsoft&apos;s BinSkim, or{" "}
                            <span className="mono">dumpbin /headers</span>, against the
                            downloaded file and compare. A security claim confirmed by a
                            third-party tool is worth considerably more than one confirmed
                            by the tool that made the change.
                        </div>
                    </>
                )}
            </div>
        </div>
    );
}
