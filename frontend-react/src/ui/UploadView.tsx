/*
 * UploadView.tsx - Submit a binary and watch the engine work through it.
 *
 * Two phases with different failure modes, so they are reported separately:
 * the upload itself (network, size), then analysis (parse errors, unsupported
 * architecture). Collapsing them into one bar hides which half went wrong.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { getRunStatus, uploadBinary } from "../api/client";
import type { RunStage, RunStatus } from "../api/types";

/* Mirrors Pipeline::analyze's stages, so the UI narrates what the engine is
 * actually doing rather than showing an indeterminate spinner. */
const STAGES: { key: RunStage; label: string }[] = [
    { key: "uploaded",                label: "Upload received" },
    { key: "loading",                 label: "Parsing PE headers, sections, imports" },
    { key: "disassembling",           label: "Disassembling (recursive descent, then sweep)" },
    { key: "discovering",             label: "Discovering function boundaries" },
    { key: "building-cfgs",           label: "Building control-flow graphs" },
    { key: "extracting-strings",      label: "Extracting referenced strings" },
    { key: "analysing-reachability",  label: "Checking input reachability" },
    { key: "exporting",               label: "Writing JSON" },
];

function humanSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

interface Props {
    /** File name is passed back so the shell can title the window with it. */
    onOpenRun: (runId: string, fileName?: string) => void;
}

export default function UploadView({ onOpenRun }: Props) {
    const [dragOver, setDragOver] = useState(false);
    const [file, setFile] = useState<File | null>(null);
    const [uploadPercent, setUploadPercent] = useState<number | null>(null);
    const [status, setStatus] = useState<RunStatus | null>(null);
    const [error, setError] = useState<string | null>(null);
    const inputRef = useRef<HTMLInputElement>(null);
    const pollRef = useRef<number | null>(null);

    useEffect(() => () => {
        if (pollRef.current) window.clearInterval(pollRef.current);
    }, []);

    const start = useCallback(async (chosen: File) => {
        setFile(chosen);
        setError(null);
        setStatus(null);
        setUploadPercent(0);

        try {
            const runId = await uploadBinary(chosen, setUploadPercent);
            setUploadPercent(100);

            // Analysis is asynchronous on the backend, so poll. A run that
            // finishes between polls is fine; a run that never reports `done`
            // stops at the timeout below rather than spinning forever.
            const began = Date.now();
            pollRef.current = window.setInterval(async () => {
                try {
                    const next = await getRunStatus(runId);
                    setStatus(next);

                    if (next.stage === "done") {
                        window.clearInterval(pollRef.current!);
                        onOpenRun(runId, chosen.name);
                    } else if (next.stage === "failed") {
                        window.clearInterval(pollRef.current!);
                        setError(next.error ?? "Analysis failed.");
                    } else if (Date.now() - began > 5 * 60 * 1000) {
                        window.clearInterval(pollRef.current!);
                        setError("Analysis did not finish within five minutes.");
                    }
                } catch (cause) {
                    window.clearInterval(pollRef.current!);
                    setError((cause as Error).message);
                }
            }, 900);
        } catch (cause) {
            setError((cause as Error).message);
            setUploadPercent(null);
        }
    }, [onOpenRun]);

    function onDrop(event: React.DragEvent) {
        event.preventDefault();
        setDragOver(false);
        const dropped = event.dataTransfer.files?.[0];
        if (dropped) void start(dropped);
    }

    const busy = uploadPercent !== null && !error;
    const stageIndex = status ? STAGES.findIndex((s) => s.key === status.stage) : -1;

    return (
        <div className="page">
            <div className="page-inner">
                <h1>Analyse a binary</h1>
                <p>
                    Upload a Windows PE executable or DLL. The engine parses it, disassembles
                    the code, recovers function boundaries and control-flow graphs, extracts
                    referenced strings, and checks which risky operations are reachable from
                    untrusted input.
                </p>

                {!busy && (
                    <>
                        <div
                            className={`dropzone${dragOver ? " over" : ""}`}
                            onDragOver={(event) => { event.preventDefault(); setDragOver(true); }}
                            onDragLeave={() => setDragOver(false)}
                            onDrop={onDrop}
                            onClick={() => inputRef.current?.click()}
                        >
                            <div className="big">Drop an .exe or .dll here</div>
                            <div className="sub">or click to choose a file</div>
                            <input
                                ref={inputRef}
                                type="file"
                                accept=".exe,.dll,.sys,.ocx,application/octet-stream"
                                style={{ display: "none" }}
                                onChange={(event) => {
                                    const chosen = event.target.files?.[0];
                                    if (chosen) void start(chosen);
                                }}
                            />
                        </div>

                        {/* Not legal boilerplate. Someone will eventually drop a
                            live malware sample into this, and they should know
                            the file is stored and never executed. */}
                        <div className="notice" style={{ marginTop: 10 }}>
                            <b>Static analysis only.</b> The uploaded file is parsed and read —
                            never executed. Even so, treat any sample as hostile: store it on a
                            machine you are willing to lose, and do not redistribute binaries
                            you do not own.
                        </div>
                    </>
                )}

                {file && busy && (
                    <>
                        <div className="filecard">
                            <span className="name">{file.name}</span>
                            <span className="dim">{humanSize(file.size)}</span>
                            <span style={{ flex: 1 }} />
                            <span className="dim">
                                {uploadPercent! < 100 ? `uploading ${uploadPercent}%` : "analysing"}
                            </span>
                        </div>

                        <div className="progress" style={{ marginTop: 6 }}>
                            <div
                                className="fill"
                                style={{
                                    width: `${uploadPercent! < 100
                                        ? uploadPercent
                                        : (status?.percent ?? 5)}%`,
                                }}
                            />
                        </div>

                        <ul className="steplist">
                            {STAGES.map((stage, index) => {
                                const state = stageIndex < 0
                                    ? (index === 0 && uploadPercent === 100 ? "active" : "pending")
                                    : index < stageIndex ? "done"
                                    : index === stageIndex ? "active"
                                    : "pending";
                                return (
                                    <li key={stage.key} className={state}>
                                        <span className="mark">
                                            {state === "done" ? "✓"
                                             : state === "active" ? "→" : "·"}
                                        </span>
                                        {stage.label}
                                    </li>
                                );
                            })}
                        </ul>

                        {status?.message && (
                            <p className="dim" style={{ marginTop: 8 }}>{status.message}</p>
                        )}
                    </>
                )}

                {error && (
                    <div className="notice" style={{ marginTop: 10 }}>
                        <b>Failed.</b> {error}
                        <br />
                        <br />
                        Common causes: the file is not a PE image (the engine reports{" "}
                        <span className="mono">missing MZ/PE signature</span>), the architecture
                        is neither x86 nor x86-64, or the backend is not running.
                        <div style={{ marginTop: 8 }}>
                            <button
                                className="xp"
                                onClick={() => {
                                    setError(null);
                                    setUploadPercent(null);
                                    setFile(null);
                                    setStatus(null);
                                }}
                            >
                                Try another file
                            </button>
                        </div>
                    </div>
                )}

                <h2>What you get</h2>
                <p>
                    A function index with triage scores, per-function disassembly with Windows
                    API calls resolved by name, a control-flow graph per function, referenced
                    strings, and a findings list showing which risky operations untrusted input
                    can actually reach — with the call path as evidence.
                </p>
                <p className="dim">
                    Decompiled C is produced separately by the AI layer and appears in the
                    Decompiler pane once that pass has run.
                </p>
            </div>
        </div>
    );
}
