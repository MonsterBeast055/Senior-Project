/*
 * MetricsBar.tsx - The overview, compressed to one line.
 *
 * Same numbers the card grid showed, but the cards cost ~90px of vertical space
 * that the assembly and decompiler panes need more. Sits just above the status
 * bar so it reads as chrome rather than content.
 *
 * Two values are worth colouring and the rest are not:
 *   coverage    amber below 80%, red below 50% - the packed-binary signal
 *   impactful   red when non-zero - the only count that warrants alarm
 */
import type { FindingsDocument, FunctionSummary, ImageInfo } from "../api/types";

interface Props {
    image: ImageInfo | null;
    functions: FunctionSummary[];
    findings: FindingsDocument | null;
    onShowFindings: () => void;
}

function Metric({
    label, value, tone,
}: {
    label: string;
    value: React.ReactNode;
    tone?: "alert" | "warn";
}) {
    return (
        <div className={`m${tone ? ` ${tone}` : ""}`}>
            <span className="mk">{label}</span>
            <span className="mv">{value}</span>
        </div>
    );
}

export default function MetricsBar({
    image, functions, findings, onShowFindings,
}: Props) {
    if (!image) return null;

    const coverage = image.coverage.code_fraction;
    const coverageTone = coverage < 0.5 ? "bad" : coverage < 0.8 ? "warn" : undefined;

    const impactful = findings?.summary.impactful ?? 0;
    const risky = findings?.summary.risky_operations ?? 0;
    const interesting = functions.filter((f) => (f.information_score ?? 0) >= 20).length;
    const packed = image.sections.find((s) => s.executable && s.entropy > 7.0);

    return (
        <div className="metrics">
            <Metric label="arch" value={image.arch} />
            <Metric label="base" value={<span className="mono">{image.image_base}</span>} />
            <Metric
                label="functions"
                value={
                    <>
                        {image.coverage.function_count}
                        <span className="mk"> ({interesting} to review)</span>
                    </>
                }
            />
            <Metric
                label="instructions"
                value={image.coverage.instruction_count.toLocaleString()}
            />

            <div className={`m${coverage < 0.5 ? " alert" : coverage < 0.8 ? " warn" : ""}`}>
                <span className="mk">coverage</span>
                <span className="mv">{(coverage * 100).toFixed(1)}%</span>
                <span className="minibar">
                    <i
                        className={coverageTone}
                        style={{ width: `${Math.min(100, coverage * 100)}%` }}
                    />
                </span>
            </div>

            <div className={`m${impactful > 0 ? " alert" : ""}`}>
                <span className="mk">impactful</span>
                <span className="mv">{impactful}</span>
                <span className="mk">of {risky} risky</span>
                {impactful > 0 && (
                    <button
                        className="xp"
                        style={{ height: 17, marginLeft: 4 }}
                        onClick={onShowFindings}
                        title="Reachability shows a call path exists, not that the operation is exploitable"
                    >
                        review
                    </button>
                )}
            </div>

            {/* Only rendered when there is something to say. A permanently
                present warning stops being read. */}
            {packed && (
                <Metric
                    label="entropy"
                    value={`${packed.name} ${packed.entropy.toFixed(2)}`}
                    tone="alert"
                />
            )}

            <div className="spacer" />
        </div>
    );
}
