/*
 * types.ts - TypeScript mirror of docs/json-schema.md.
 *
 * This file is the contract with the C++ engine. If the engine adds a field,
 * add it here first — then the compiler tells you every place that could use it.
 *
 * Addresses are `string` throughout, never `number`. A 64-bit virtual address
 * does not survive JavaScript's number type (safe integers stop at 53 bits), so
 * the engine emits them as hex strings like "0x140001a20". Use BigInt if you
 * ever need arithmetic on one.
 */

export type Hex = string;

export type Confidence = "certain" | "high" | "medium" | "low" | "none";

export type FlowKind =
    | "sequential"
    | "conditional-jump"
    | "unconditional-jump"
    | "call"
    | "return"
    | "interrupt"
    | "halt"
    | "unknown";

export type EdgeKind =
    | "fall-through"
    | "taken"
    | "jump"
    | "indirect-jump"
    | "call"
    | "return";

export type Severity = "high" | "medium" | "low" | "informational";

export interface Provenance {
    kind: string;
    confidence: Confidence;
    source: Hex | null;
}

export interface Instruction {
    va: Hex;
    size: number;
    mnemonic: string;
    operands: string;
    flow: FlowKind;
    bytes?: string;
    target: Hex | null;
    /** Resolved symbol for the destination. Populated for direct calls AND for
     *  indirect calls through an IAT slot, which is how nearly every Windows API
     *  call actually appears. The single most useful field on the line. */
    target_name: string | null;
    indirect: boolean;
    memory_ref: Hex | null;
    confidence?: Confidence;
    provenance?: Provenance[];
}

export interface Successor {
    target: Hex;
    kind: EdgeKind;
    confidence?: Confidence;
}

export interface BasicBlock {
    id?: number;
    start: Hex;
    end: Hex;
    instruction_count: number;
    /** True when control leaves through an unresolved indirect branch — almost
     *  always an unresolved `switch` table. The block will have zero successors,
     *  but it is NOT a dead end. Must be rendered distinctly. */
    has_unresolved_exit: boolean;
    instructions: Instruction[];
    successors: Successor[];
    predecessors: Hex[];
}

export interface StackFrame {
    local_size: number;
    saved_regs_size: number;
    uses_frame_pointer: boolean;
}

export interface FunctionRef {
    va: Hex;
    name: string;
}

/** Row in the function index (`functions.json`). */
export interface FunctionSummary {
    va: Hex;
    name: string;
    extent_end?: Hex;
    block_count: number;
    instruction_count: number;
    is_thunk?: boolean;
    is_imported_stub?: boolean;
    is_library_code?: boolean;
    returns?: boolean;
    indirect_call_count?: number;
    callee_count?: number;
    caller_count?: number;
    confidence?: Confidence;

    /** Cache key for the AI layer. Computed from the mnemonic sequence rather
     *  than raw bytes, so identical library code hashes the same across
     *  binaries.
     *
     *  A hex string, not a number: 64 bits does not fit JavaScript's safe
     *  integer range, and a cache key that loses its low bits would produce
     *  wrong cache hits. */
    content_hash?: Hex;
    cyclomatic_complexity?: number;
    /** 0-100 triage hint. 0 means "not worth a model call".
     *
     *  The three fields below are its inputs. They are emitted by the engine
     *  alongside the total so the UI can show how the number was reached rather
     *  than asking anyone to take it on trust — see ScoreDerivation. */
    information_score?: number;
    api_call_count?: number;
    string_count?: number;
}

/** Full function document (`functions/func_<va>.json`). */
export interface FunctionDetail extends FunctionSummary {
    convention?: string;
    frame?: StackFrame;
    provenance?: Provenance[];
    /** Reverse post-order. Use as the vertical ordering hint for graph layout. */
    block_order: Hex[];
    blocks: BasicBlock[];
    callees: FunctionRef[];
    callers: FunctionRef[];
    unreachable_blocks: Hex[];
    api_calls?: string[];
    referenced_strings?: string[];
    reachable_from_input?: boolean;
    input_sources?: string[];
}

export interface Section {
    name: string;
    va: Hex;
    rva?: number;
    virtual_size: number;
    raw_size: number;
    raw_offset?: number;
    executable: boolean;
    readable: boolean;
    writable: boolean;
    entropy: number;
}

export interface ImportEntry {
    library: string;
    name: string;
    by_ordinal?: boolean;
    ordinal?: number;
    iat_slot: Hex;
}

export interface Coverage {
    executable_bytes: number;
    /** Share of executable bytes the engine could explain as code. Low values
     *  plus high section entropy is the classic packed-binary signal. */
    code_fraction: number;
    instruction_count: number;
    function_count: number;
    unclaimed_ranges?: { start: Hex; end: Hex; size: number }[];
}

export interface ImageInfo {
    schema_version: string;
    format: string;
    arch: string;
    image_base: Hex;
    entry_point: Hex;
    image_size: number;
    sections: Section[];
    imports: ImportEntry[];
    exports?: { name: string; ordinal: number; va: Hex | null; is_forwarder: boolean }[];
    coverage: Coverage;
    /** Image-wide string list. Same data as a function's referenced_strings,
     *  indexed the other way so a Strings pane needs one request, not 1700. */
    strings?: ExtractedString[];
    /** Reverse of api_calls: who calls each imported API. */
    api_xrefs?: ApiXref[];
    /** Reverse of referenced_strings: who uses each string. */
    string_xrefs?: StringXref[];
}

/** A function that uses something, for the xref lists below. */
export interface XrefSite {
    va: Hex;
    name: string;
}

export interface ApiXref {
    api: string;
    count: number;
    functions: XrefSite[];
}

export interface StringXref {
    address: Hex;
    count: number;
    functions: XrefSite[];
}

export interface ExtractedString {
    address: Hex;
    encoding: "ascii" | "utf16";
    text: string;
    /** How many instructions reference it. A string used from several places is
     *  usually a format string or a registry path — worth more attention. */
    refs?: number;
    /** Length in characters before truncation. */
    length?: number;
    truncated?: boolean;
    /** Every function referencing it is library code. These strings are real —
     *  "(null)", ".exe", "ERROR: Unable to initialize" are MSVC C-runtime
     *  literals — but they are identical in every binary built with MSVC and say
     *  nothing about this program. Folded away by default, never dropped. */
    library_only?: boolean;
}

export interface Finding {
    function: Hex;
    function_name: string;
    api: string;
    kind: string;
    /** Whether a call path exists from a function reading untrusted input.
     *  NOT a proof that attacker-controlled data reaches the argument. */
    reachable_from_input: boolean;
    base_severity: Severity;
    /** Composed from sink kind AND reachability, never asserted. */
    severity: Severity;
    sources: string[];
    /** The evidence. A reachability claim without the path is unverifiable. */
    call_path: FunctionRef[];
    /** What the analysis did not establish. Render it — do not drop it. */
    limitation: string;
}

export interface FindingsDocument {
    schema_version: string;
    methodology: {
        analysis: string;
        value_level_dataflow: boolean;
        proves_exploitability: boolean;
        note: string;
    };
    input_sources: { function: Hex; function_name: string; api: string; source: string }[];
    findings: Finding[];
    summary: { risky_operations: number; input_sources: number; impactful: number };
}

/* ======================================================================
 * n8n boundary
 *
 * Everything below is produced by the n8n workflow and stored by the backend.
 * The C++ engine never sees it. This is the seam between the two halves of the
 * system.
 * ====================================================================== */

export type LiftState = "not-run" | "queued" | "running" | "done" | "failed";

/** One line of generated C mapped back to the basic block it came from.
 *
 *  This is the field the whole side-by-side view depends on. Without it the
 *  decompiler pane, the disassembly and the graph are three unrelated text
 *  boxes. The n8n prompt must demand it in the model's response schema. */
export interface LineMapping {
    line: number;
    block: Hex;
}

export interface LiftedFunction {
    state?: LiftState;
    model?: string;
    suggested_name: string;
    description: string;
    confidence: Confidence;
    /** AI output is provisional until a human accepts it. */
    review: "not-reviewed" | "accepted" | "rejected";
    c_code: string[];
    line_mapping: LineMapping[];
    /** Populated when the validator agent (or the deterministic pre-checks)
     *  flagged something about this output. */
    warnings?: string[];

    /* --- Versioning ------------------------------------------------------
     * A function can be lifted twice: once by the automated pass, once by a user
     * pressing Lift with AI. The newest wins here, but the previous ones are kept
     * — findings were reasoned from specific text, and destroying it would leave
     * them justified by something nobody can retrieve. */
    origin?: "automated" | "manual";
    version_id?: string;
    /** Earlier versions, newest first. Empty on a first lift. */
    superseded?: { origin: string; version_id: string | null; received_at: string | null }[];
}

/* ======================================================================
 * Runs
 *
 * A "run" is one analysis of one uploaded binary. The backend stores each run's
 * exported JSON so a report can be reopened later without re-analysing — which
 * matters because analysis is seconds of CPU per binary and the AI pass costs
 * real money.
 * ====================================================================== */

export type RunStage =
    | "uploaded"
    | "loading"
    | "disassembling"
    | "discovering"
    | "building-cfgs"
    | "extracting-strings"
    | "analysing-reachability"
    | "exporting"
    | "done"
    | "failed";

export interface RunStatus {
    run_id: string;
    stage: RunStage;
    /** 0-100. The engine's stages are fast and roughly equal, so this is a
     *  step count rather than a true measure of work. */
    percent: number;
    message?: string;
    error?: string;
}

/** Row in the report history. */
export interface RunSummary {
    run_id: string;
    file_name: string;
    file_size: number;
    sha256?: string;
    /** ISO 8601. */
    created_at: string;
    arch?: string;
    stage: RunStage;

    function_count?: number;
    instruction_count?: number;
    code_fraction?: number;
    /** Findings that are both reachable from untrusted input and at least
     *  medium severity. The number a report leads with. */
    impactful_findings?: number;
    risky_operations?: number;
    /** How many functions the AI layer has lifted so far. */
    lifted_count?: number;
}

/* ======================================================================
 * Finding explanations  (n8n)
 *
 * Severity is NOT in here, deliberately. It is derived by the engine from sink
 * kind plus reachability, and it must stay that way — if a language model could
 * change a severity, the number stops meaning anything and the tool starts
 * overstating its own confidence.
 *
 * What the model contributes is the part it is genuinely good at: explaining
 * what the operation does, what an attacker could plausibly achieve, and what a
 * fix looks like. It reasons about a severity the engine already decided.
 * ====================================================================== */

export interface FindingExplanation {
    state?: LiftState;
    model?: string;

    /** One sentence: what this code is doing. */
    summary: string;
    /** Why the engine's severity is defensible, in prose. */
    why_severity: string;
    /** What an attacker could plausibly achieve, and under what conditions. */
    impact: string;
    /** What a fix would look like — advice, not a patch. */
    remediation: string;
    /** Preconditions an attacker would still need. Guards against the model
     *  presenting a theoretical path as trivially exploitable. */
    preconditions?: string[];

    /** The model's confidence in its own explanation — not in the severity. */
    confidence: Confidence;
    /** Always "engine". Present so a consumer cannot mistake the narrative for
     *  the source of the rating. */
    severity_source: "engine";
    review?: "not-reviewed" | "accepted" | "rejected";
}

/* ======================================================================
 * Binary context  (user-provided)
 *
 * Things a person knows that no amount of static analysis can recover: what the
 * program is for, whether it is trusted, which inputs matter. Fed into the AI
 * prompt, where it is worth more than any extra engine feature.
 *
 * The detected_* fields are shown so a user can correct them, but they come from
 * the PE header and are almost never wrong — the value here is the human fields.
 * ====================================================================== */

export type TrustLevel = "trusted" | "unknown" | "suspected-malware";

export interface BinaryContext {
    /** Free text: "config parser for an embedded device", "suspected loader". */
    purpose?: string;
    trust?: TrustLevel;
    /** Known packer or protector, if the user knows of one. */
    packer?: string;
    /** Which inputs the user believes matter. Sharpens reachability triage. */
    expected_inputs?: string[];
    /** Anything else worth telling the model. */
    notes?: string;

    /** Overrides for what the loader detected. Left unset unless the user
     *  actually disagrees. */
    arch_override?: string;
    /** Confirmed rather than overridden — recorded so the report can say the
     *  detected values were reviewed. */
    detected_confirmed?: boolean;
}
