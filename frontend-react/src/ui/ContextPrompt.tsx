/*
 * ContextPrompt.tsx - What the analysis cannot know.
 *
 * Shown once after an upload finishes. Deliberately NOT "confirm the
 * architecture": LIEF reads that from the PE header and is essentially never
 * wrong, so asking would be noise on every single run. The detected values are
 * displayed and overridable in case something genuinely is off, but they are not
 * the point.
 *
 * The point is the human fields. What the program is for, whether it is trusted,
 * which inputs matter — none of that is recoverable from bytes, and all of it
 * improves the AI layer's output more than any further engine feature would. A
 * model told "this is a config parser for an embedded device that reads files
 * over TFTP" produces dramatically better naming than one given the same
 * disassembly cold.
 *
 * Everything is skippable. A prompt that blocks the workspace on the first run
 * gets dismissed reflexively and then resented.
 */
import { useState } from "react";
import { saveBinaryContext } from "../api/client";
import type { BinaryContext, ImageInfo, TrustLevel } from "../api/types";

const INPUT_KINDS = [
    "network",
    "file",
    "command-line",
    "registry",
    "environment",
    "ipc",
    "user-input",
] as const;

interface Props {
    image: ImageInfo | null;
    fileName: string;
    onDone: () => void;
}

export default function ContextPrompt({ image, fileName, onDone }: Props) {
    const [purpose, setPurpose] = useState("");
    const [trust, setTrust] = useState<TrustLevel>("unknown");
    const [packer, setPacker] = useState("");
    const [inputs, setInputs] = useState<Set<string>>(new Set());
    const [notes, setNotes] = useState("");
    const [archOverride, setArchOverride] = useState("");
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const coverage = image?.coverage.code_fraction ?? 1;
    const packedHint = coverage < 0.8 ||
        !!image?.sections.some((s) => s.executable && s.entropy > 7.0);

    async function save(skip: boolean) {
        setBusy(true);
        setError(null);
        const context: BinaryContext = skip
            ? { detected_confirmed: false }
            : {
                  purpose: purpose.trim() || undefined,
                  trust,
                  packer: packer.trim() || undefined,
                  expected_inputs: inputs.size > 0 ? [...inputs] : undefined,
                  notes: notes.trim() || undefined,
                  arch_override: archOverride.trim() || undefined,
                  detected_confirmed: true,
              };
        try {
            await saveBinaryContext(context);
            onDone();
        } catch (cause) {
            setError((cause as Error).message);
        } finally {
            setBusy(false);
        }
    }

    function toggleInput(kind: string) {
        setInputs((current) => {
            const next = new Set(current);
            if (next.has(kind)) next.delete(kind); else next.add(kind);
            return next;
        });
    }

    return (
        <div style={{ height: "100%", overflow: "auto", padding: "8px 10px" }}>
            <p style={{ marginTop: 0, lineHeight: 1.5 }}>
                Analysis finished. These few answers are worth more to the AI layer than
                any extra static analysis — nothing below is recoverable from the bytes.
                All optional.
            </p>

            {/* Detected facts, shown for review rather than confirmation. */}
            <div className="blockhdr">Detected</div>
            <table className="grid" style={{ width: "100%" }}>
                <tbody>
                    <tr>
                        <td style={{ width: 130 }} className="dim">File</td>
                        <td>{fileName}</td>
                    </tr>
                    <tr>
                        <td className="dim">Architecture</td>
                        <td>
                            <span className="mono">{image?.arch ?? "-"}</span>
                            <span className="dim">
                                {" "}— read from the PE header, rarely wrong
                            </span>
                            <input
                                className="xp"
                                style={{ width: 90, marginLeft: 8 }}
                                placeholder="override"
                                value={archOverride}
                                onChange={(event) => setArchOverride(event.target.value)}
                            />
                        </td>
                    </tr>
                    <tr>
                        <td className="dim">Code coverage</td>
                        <td>
                            {(coverage * 100).toFixed(1)}%
                            {packedHint && (
                                <span className="badge warn" style={{ marginLeft: 6 }}>
                                    may be packed
                                </span>
                            )}
                        </td>
                    </tr>
                </tbody>
            </table>

            <div className="blockhdr" style={{ marginTop: 10 }}>
                What do you already know?
            </div>

            <div style={{ padding: "6px 4px" }}>
                <div style={{ marginBottom: 8 }}>
                    <div className="dim" style={{ marginBottom: 2 }}>
                        What is this program for? Even a rough guess helps a lot.
                    </div>
                    <input
                        className="xp"
                        style={{ width: "100%", maxWidth: 520 }}
                        placeholder="e.g. config parser for an embedded device, suspected loader"
                        value={purpose}
                        onChange={(event) => setPurpose(event.target.value)}
                    />
                </div>

                <div style={{ marginBottom: 8 }}>
                    <div className="dim" style={{ marginBottom: 2 }}>
                        How much do you trust it?
                    </div>
                    <select
                        className="xp"
                        value={trust}
                        onChange={(event) => setTrust(event.target.value as TrustLevel)}
                    >
                        <option value="trusted">Trusted — my own or a known-good build</option>
                        <option value="unknown">Unknown provenance</option>
                        <option value="suspected-malware">Suspected malware</option>
                    </select>
                    <span className="dim" style={{ marginLeft: 8 }}>
                        changes what the AI looks for, not what the engine reports
                    </span>
                </div>

                <div style={{ marginBottom: 8 }}>
                    <div className="dim" style={{ marginBottom: 2 }}>
                        Which inputs does it handle? Sharpens reachability triage.
                    </div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "2px 12px" }}>
                        {INPUT_KINDS.map((kind) => (
                            <label key={kind}>
                                <input
                                    type="checkbox"
                                    checked={inputs.has(kind)}
                                    onChange={() => toggleInput(kind)}
                                />{" "}
                                {kind}
                            </label>
                        ))}
                    </div>
                </div>

                <div style={{ marginBottom: 8 }}>
                    <div className="dim" style={{ marginBottom: 2 }}>
                        Known packer or protector?
                        {packedHint && (
                            <b> Coverage is low, so this binary may well be packed.</b>
                        )}
                    </div>
                    <input
                        className="xp"
                        style={{ width: 260 }}
                        placeholder="UPX, Themida, none, don't know"
                        value={packer}
                        onChange={(event) => setPacker(event.target.value)}
                    />
                </div>

                <div style={{ marginBottom: 8 }}>
                    <div className="dim" style={{ marginBottom: 2 }}>
                        Anything else the AI should know?
                    </div>
                    <textarea
                        className="xp"
                        style={{ width: "100%", maxWidth: 520, height: 52, resize: "vertical" }}
                        value={notes}
                        onChange={(event) => setNotes(event.target.value)}
                    />
                </div>
            </div>

            {error && (
                <div className="notice">
                    <b>Could not save.</b> {error}
                </div>
            )}

            <div style={{ display: "flex", gap: 6, padding: "4px 4px 10px 4px" }}>
                <button className="xp" disabled={busy} onClick={() => void save(false)}>
                    Save and continue
                </button>
                <button className="xp" disabled={busy} onClick={() => void save(true)}>
                    Skip
                </button>
                <span className="dim" style={{ alignSelf: "center" }}>
                    editable later from Analysis → Binary context
                </span>
            </div>
        </div>
    );
}
