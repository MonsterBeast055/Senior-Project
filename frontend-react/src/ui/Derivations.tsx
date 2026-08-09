/*
 * Derivations.tsx - The engine's reasoning, rendered.
 *
 * Two derived numbers drive most of what the UI shows: information_score decides
 * which functions are "worth review", and severity decides which findings matter.
 * Both are computed in C++ and arrive as bare numbers.
 *
 * These components reproduce the arithmetic on the client so a reader can see
 * where the number came from. That is a deliberate duplication of logic, and it
 * carries a real risk: if FunctionSummarizer.cpp changes its weights and this file
 * does not, the popup will confidently show wrong maths. The mitigation is that
 * the engine's own total is always displayed alongside, so a mismatch is visible
 * rather than silent — see the reconciliation line at the end of ScoreDerivation.
 */
import type { Finding, FunctionSummary } from "../api/types";
import { ExplainRow } from "./Explain";

/* Mirrors FunctionSummarizer::compute_information_score. Keep in step with it. */
const W_API = 7;
const W_API_CAP = 8;
const W_STRING = 6;
const W_STRING_CAP = 6;
const W_SIZE_STEP = 5;
const CX_CAP = 10;
const SCORE_CAP = 100;

export function ScoreDerivation({ fn }: { fn: FunctionSummary }) {
    const apis = fn.api_call_count ?? 0;
    const strings = fn.string_count ?? 0;
    const insns = fn.instruction_count ?? 0;
    const cx = fn.cyclomatic_complexity ?? 0;
    const callers = fn.caller_count ?? 0;

    const apiPoints = Math.min(apis, W_API_CAP) * W_API;
    const stringPoints = Math.min(strings, W_STRING_CAP) * W_STRING;
    const sizePoints =
        (insns >= 10 ? W_SIZE_STEP : 0)
        + (insns >= 40 ? W_SIZE_STEP : 0)
        + (insns >= 150 ? W_SIZE_STEP : 0);
    const cxPoints = Math.min(cx, CX_CAP);
    const callerPoints = (callers >= 3 ? 3 : 0) + (callers >= 10 ? 3 : 0);

    const raw = apiPoints + stringPoints + sizePoints + cxPoints + callerPoints;

    const zeroed = fn.is_thunk || fn.is_imported_stub;
    const quartered = !zeroed && fn.is_library_code;
    const predicted = zeroed
        ? 0
        : Math.min(quartered ? Math.floor(raw / 4) : raw, SCORE_CAP);

    const actual = fn.information_score ?? 0;
    const agrees = predicted === actual;

    return (
        <>
            <p className="explain-lead">
                A triage number, not a verdict. It exists so the AI layer can decide
                which functions are worth a model call instead of paying for all of
                them — anything at 20 or above lands in <b>Worth review</b>.
            </p>

            <ExplainRow
                label={`Imported API calls (${apis})`}
                value={`+${apiPoints}`}
                note={`${W_API} each, first ${W_API_CAP}`}
            />
            <ExplainRow
                label={`Referenced strings (${strings})`}
                value={`+${stringPoints}`}
                note={`${W_STRING} each, first ${W_STRING_CAP}`}
            />
            <ExplainRow
                label={`Size (${insns} instructions)`}
                value={`+${sizePoints}`}
                note="+5 at 10, 40, 150"
            />
            <ExplainRow
                label={`Branching (complexity ${cx})`}
                value={`+${cxPoints}`}
                note={`capped at ${CX_CAP}`}
            />
            <ExplainRow
                label={`Callers (${callers})`}
                value={`+${callerPoints}`}
                note="+3 at 3, +3 at 10"
            />
            <ExplainRow label="Subtotal" value={raw} strong />

            {zeroed && (
                <ExplainRow
                    label="Thunk or import stub"
                    value="→ 0"
                    note="one jump, nothing to explain"
                    strong
                />
            )}
            {quartered && (
                <ExplainRow
                    label="Library code"
                    value="÷ 4"
                    note="the CRT's, identical in every binary"
                    strong
                />
            )}

            <ExplainRow label="Engine score" value={actual} strong />

            {/* The honesty check. This file duplicates weights that live in C++, so
                it can drift. Saying so beats quietly showing wrong arithmetic. */}
            {!agrees && (
                <p className="explain-warn">
                    This breakdown totals {predicted}, but the engine reported {actual}.
                    The weights here are a copy of the ones in{" "}
                    <span className="mono">FunctionSummarizer.cpp</span> and have
                    drifted. Trust the engine's number.
                </p>
            )}

            <p className="explain-foot">
                API calls and strings dominate on purpose — they are the only signals
                that say what a function <i>does</i>. Size and branching only say it
                is big.
            </p>
        </>
    );
}

export function SeverityDerivation({ finding }: { finding: Finding }) {
    const promoted = finding.reachable_from_input;
    const demoted = !promoted && finding.base_severity !== finding.severity;

    return (
        <>
            <p className="explain-lead">
                Severity is <b>composed</b> from two facts, never asserted. Neither
                the model nor a rule table sets it directly.
            </p>

            <ExplainRow
                label="1. Sink kind"
                value={finding.kind}
                note={`base ${finding.base_severity}`}
            />
            <ExplainRow
                label="2. Reachable from input"
                value={promoted ? "yes" : "no"}
                note={
                    finding.sources.length > 0
                        ? finding.sources.join(", ")
                        : "no path found"
                }
            />
            <ExplainRow
                label="Call path length"
                value={finding.call_path.length || "—"}
                note={finding.call_path.length ? "functions from source to sink" : undefined}
            />
            <ExplainRow label="Result" value={finding.severity} strong />

            {demoted && (
                <p className="explain-foot">
                    Dropped from <b>{finding.base_severity}</b> because nothing
                    reachable from untrusted input calls it. A dangerous operation
                    nobody can reach is a style problem, not a vulnerability.
                </p>
            )}
            {promoted && (
                <p className="explain-foot">
                    Held at <b>{finding.severity}</b> because a call path exists from
                    a function that reads untrusted input.
                </p>
            )}

            <p className="explain-warn">
                This is call-graph reachability, not taint analysis. It shows a path
                exists — not that attacker data reaches the argument, and not that
                intervening length checks are absent.
            </p>
        </>
    );
}
