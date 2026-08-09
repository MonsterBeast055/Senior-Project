/*
 * ReportsView.tsx - Previous analysis runs.
 *
 * Reopening a stored run matters for two reasons: engine analysis is seconds of
 * CPU per binary, and the AI pass costs real money per function. Neither should
 * be repeated just to look at a result again.
 */
import { useCallback, useEffect, useState } from "react";
import { deleteRun, listRuns } from "../api/client";
import type { RunSummary } from "../api/types";

function humanSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function humanWhen(iso: string): string {
    const then = new Date(iso);
    if (Number.isNaN(then.getTime())) return iso;
    const minutes = Math.round((Date.now() - then.getTime()) / 60000);
    if (minutes < 1) return "just now";
    if (minutes < 60) return `${minutes} min ago`;
    if (minutes < 60 * 24) return `${Math.round(minutes / 60)} h ago`;
    return then.toLocaleDateString();
}

interface Props {
    currentRun: string;
    onOpenRun: (runId: string, fileName?: string) => void;
}

export default function ReportsView({ currentRun, onOpenRun }: Props) {
    const [runs, setRuns] = useState<RunSummary[]>([]);
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);

    const reload = useCallback(async () => {
        setBusy(true);
        setError(null);
        try {
            setRuns(await listRuns());
        } catch (cause) {
            setError((cause as Error).message);
        } finally {
            setBusy(false);
        }
    }, []);

    useEffect(() => { void reload(); }, [reload]);

    async function onDelete(runId: string) {
        try {
            await deleteRun(runId);
            await reload();
        } catch (cause) {
            setError((cause as Error).message);
        }
    }

    return (
        <div className="page">
            <div className="page-inner">
                <h1>Previous reports</h1>
                <p>
                    Every uploaded binary keeps its analysis output, so a report can be
                    reopened without re-running the engine or paying for the AI pass again.
                </p>

                <div style={{ marginBottom: 8 }}>
                    <button className="xp" onClick={() => void reload()} disabled={busy}>
                        Refresh
                    </button>
                </div>

                {error && (
                    <div className="notice">
                        <b>Could not list runs.</b> {error}
                        <br />
                        Is the backend running? Switch Data to <i>Sample</i> to browse offline.
                    </div>
                )}

                {runs.length === 0 && !busy && !error && (
                    <div className="empty">
                        No reports yet. Upload a binary to create one.
                    </div>
                )}

                {runs.length > 0 && (
                    <div style={{ overflowX: "auto" }}>
                        <table className="grid" style={{ minWidth: 760 }}>
                            <thead>
                                <tr>
                                    <th>File</th>
                                    <th style={{ width: 70 }}>Arch</th>
                                    <th style={{ width: 84 }} className="num">Size</th>
                                    <th style={{ width: 76 }} className="num">Functions</th>
                                    <th style={{ width: 76 }} className="num">Coverage</th>
                                    <th style={{ width: 96 }} className="num" title="Reachable and at least medium severity">
                                        Impactful
                                    </th>
                                    <th style={{ width: 64 }} className="num">Lifted</th>
                                    <th style={{ width: 88 }}>When</th>
                                    <th style={{ width: 116 }} />
                                </tr>
                            </thead>
                            <tbody>
                                {runs.map((run) => (
                                    <tr
                                        key={run.run_id}
                                        className={run.run_id === currentRun ? "selected" : undefined}
                                    >
                                        <td>
                                            {run.file_name}
                                            {run.sha256 && (
                                                <span className="dim mono"> {run.sha256}</span>
                                            )}
                                        </td>
                                        <td className="mono">{run.arch ?? "-"}</td>
                                        <td className="num dim">{humanSize(run.file_size)}</td>
                                        <td className="num">{run.function_count ?? "-"}</td>
                                        <td className="num">
                                            {run.code_fraction != null
                                                ? `${(run.code_fraction * 100).toFixed(1)}%`
                                                : "-"}
                                        </td>
                                        <td className="num">
                                            {/* Only the reachable, medium-or-worse count is
                                                worth colouring. A raw "risky operations"
                                                total would look alarming and mean little. */}
                                            {run.impactful_findings ? (
                                                <span className="sev high">
                                                    {run.impactful_findings}
                                                </span>
                                            ) : (
                                                <span className="dim">0</span>
                                            )}
                                            {run.risky_operations != null && (
                                                <span className="dim"> /{run.risky_operations}</span>
                                            )}
                                        </td>
                                        <td className="num dim">{run.lifted_count ?? 0}</td>
                                        <td className="dim">{humanWhen(run.created_at)}</td>
                                        <td>
                                            <button
                                                className="xp"
                                                onClick={() => onOpenRun(run.run_id, run.file_name)}
                                                disabled={run.stage !== "done"}
                                            >
                                                Open
                                            </button>{" "}
                                            <button
                                                className="xp"
                                                onClick={() => void onDelete(run.run_id)}
                                                title="Delete this run and its stored output"
                                            >
                                                Delete
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}

                <h2>Reading the Impactful column</h2>
                <p>
                    The first number counts risky operations that are both reachable from
                    untrusted input <i>and</i> at least medium severity. The number after the
                    slash is every risky operation found, reachable or not.
                </p>
                <p className="dim">
                    A zero in the first column does not mean the binary is safe. It means no
                    call path from a known input source was found — which may be because none
                    exists, or because the path runs through an indirect call that static
                    analysis cannot resolve.
                </p>
            </div>
        </div>
    );
}
