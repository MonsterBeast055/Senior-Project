/*
 * mock-n8n.mjs — a stand-in for the n8n workflow, so the AI path can be
 * exercised before the workflow exists.
 *
 * Same idea as fake-engine.sh: replace the part someone else owns with
 * something that speaks the same protocol, so the half we own can be tested on
 * its own. This is not a simulation of the UI — it drives the real backend
 * through the real endpoints. What you see in the browser afterwards is the
 * genuine article with invented model text in it.
 *
 * It behaves the way the real workflow must:
 *
 *   1. accept the POST and answer 200 immediately, without waiting for a model
 *      (the backend aborts the forward after 10s and treats it as a failure)
 *   2. wait a moment, the way a real model call would
 *   3. POST the result to `callback` verbatim
 *
 * Run it:
 *     node backend/test/mock-n8n.mjs
 *
 * Point the backend at it and restart the API:
 *     N8N_WEBHOOK_URL=http://localhost:5678/webhook/analyze
 *
 * Then click "Start automated analysis" in the UI.
 *
 * Environment:
 *   PORT=5678          where to listen
 *   LATENCY_MS=700     pause before answering, to make progress visible
 *   FAIL_EVERY=0       fail every Nth request (0 = never), to see error handling
 */
import http from "node:http";

const PORT = Number(process.env.PORT || 5678);
const LATENCY_MS = Number(process.env.LATENCY_MS || 700);
const FAIL_EVERY = Number(process.env.FAIL_EVERY || 0);
const MODEL = "mock-n8n/offline";

let seen = 0;

/* --- canned answers, built from the payload ---------------------------
 *
 * Derived from the real request rather than hard-coded, so the output lines up
 * with the function actually on screen. A fixed blob of text would look right
 * in one pane and obviously wrong beside the disassembly. */

function decompileResult(payload) {
    const fn = payload.function ?? {};
    const name = fn.name || `sub_${String(fn.va ?? "").slice(2)}`;
    const apis = fn.api_calls ?? [];
    const strings = fn.referenced_strings ?? [];

    const body = [
        `int ${name}(void)`,
        "{",
        "    wchar_t buffer[32];",
        ...(strings.length > 0
            ? [`    /* references: ${strings[0].slice(0, 60)} */`]
            : []),
        ...apis.slice(0, 4).map((api) => `    ${api.split("!").pop()}(buffer);`),
        "    return 0;",
        "}",
    ];

    /* line_mapping is what ties the C to the graph and the listing. Mapping each
     * line onto a real block address demonstrates the wiring; a real workflow
     * gets these from the model.
     *
     * The field is `start`, not `va`. Blocks are the one entity in the schema
     * that does not use `va`, and reading the wrong name here fails silently:
     * every address comes back undefined, the mapping is empty, and the pane
     * just quietly stops highlighting. */
    const blocks = (fn.blocks ?? []).map((b) => b.start).filter(Boolean);
    const line_mapping = blocks.length > 0
        ? body.map((_, index) => ({
            line: index + 1,
            block: blocks[Math.min(index, blocks.length - 1)],
        }))
        : [];

    return {
        model: MODEL,
        suggested_name: name.startsWith("sub_") ? `${name}_guessed` : name,
        code: body.join("\n"),
        summary:
            apis.length > 0
                ? `Calls ${apis.slice(0, 2).map((a) => a.split("!").pop()).join(" and ")}`
                  + ` on a caller-supplied buffer; ${fn.block_count ?? "several"} blocks,`
                  + ` complexity ${fn.cyclomatic_complexity ?? "unknown"}.`
                : "Small helper with no imported calls; moves data between its"
                  + " arguments and returns a status.",
        confidence: (fn.information_score ?? 0) > 60 ? "high" : "medium",
        line_mapping,
    };
}

function bugsResult(payload) {
    const findings = payload.engine_findings ?? [];

    // One issue per engine finding: these carry `engine_finding`, so the backend
    // matches them and the UI badges them corroborated with the engine's severity.
    const issues = findings.slice(0, 3).map((finding) => ({
        title: `Unchecked ${String(finding.api ?? "").split("!").pop() || "operation"}`
            + (finding.reachable_from_input ? " on attacker-influenced data" : ""),
        detail:
            `${finding.api} is called without a length bound. The engine traced this`
            + ` to ${(finding.sources ?? []).join(", ") || "an input source"} across`
            + ` ${(finding.call_path ?? []).length} call(s), so the size is not`
            + " under the program's control.",
        engine_finding: finding.api,
        confidence: finding.severity === "high" ? "high" : "medium",
    }));

    /* One issue with no `engine_finding`, on purpose. The UI badges it
     * "unconfirmed" with no severity — it is worth seeing that path, because a
     * model raising something the engine missed is the case the badge exists
     * for, and it should look visibly different from a corroborated row. */
    issues.push({
        title: "Return value of the allocation is not checked",
        detail:
            "The allocated pointer is used on the next line with no NULL test."
            + " Nothing static flagged this; it is a lead, not a result.",
        confidence: "low",
    });

    return { model: MODEL, issues };
}

function behaviourResult(payload) {
    const apis = payload.function?.api_calls ?? [];
    const verbs = apis.map((a) => a.split("!").pop());
    return {
        model: MODEL,
        summary:
            verbs.length > 0
                ? `Uses ${verbs.slice(0, 3).join(", ")} — reads configuration it did`
                  + " not write and acts on the value, which is how a setting becomes"
                  + " an execution path."
                : "No imported calls; this function is arithmetic and control flow"
                  + " over data its caller supplies.",
    };
}

function explanationResult(payload) {
    const finding = payload.finding ?? {};
    return {
        model: MODEL,
        summary: `${finding.api ?? "The call"} writes into a fixed-size buffer with no`
            + " length argument.",
        why_severity:
            `The engine rated this ${finding.severity ?? "as it did"} because the sink`
            + " has no bound and the data reaching it is"
            + (finding.reachable_from_input ? "" : " not")
            + " reachable from an input the program does not control. Both halves are"
            + " required for that rating.",
        impact:
            "A value longer than the destination overwrites adjacent stack memory,"
            + " including the saved return address, which is enough to redirect"
            + " execution at the privilege of the running process.",
        remediation:
            "Use the length-bounded form of the same call and pass the destination"
            + " size, or validate the source length before copying.",
        preconditions: [
            "The attacker must be able to set the source value",
            "The build must not have a stack cookie covering this frame",
        ],
        confidence: "medium",
    };
}

const RESULT_FOR = {
    decompile: decompileResult,
    bugs: bugsResult,
    behaviour: behaviourResult,
    "explain-finding": explanationResult,
};

/* --- the server -------------------------------------------------------- */

async function deliver(payload) {
    const build = RESULT_FOR[payload.task];
    if (!build) {
        console.error(`  ! unknown task "${payload.task}" — nothing sent back`);
        return;
    }

    const body = build(payload);
    try {
        const upstream = await fetch(payload.callback, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        });
        const text = await upstream.text();
        console.log(`  -> ${upstream.status} ${payload.callback}`);
        if (!upstream.ok) console.error(`     ${text.slice(0, 200)}`);
    } catch (cause) {
        // Almost always the callback host being unreachable, which is the whole
        // class of bug PUBLIC_BASE_URL exists to prevent. Name it clearly.
        console.error(`  ! callback failed: ${cause.message}`);
        console.error(`    tried: ${payload.callback}`);
    }
}

http.createServer((request, response) => {
    if (request.method !== "POST") {
        response.writeHead(405).end("POST only");
        return;
    }

    let raw = "";
    request.on("data", (chunk) => { raw += chunk; });
    request.on("end", () => {
        let payload;
        try {
            payload = JSON.parse(raw);
        } catch {
            console.error("! body was not JSON");
            response.writeHead(400).end('{"error":"not json"}');
            return;
        }

        seen += 1;
        const failing = FAIL_EVERY > 0 && seen % FAIL_EVERY === 0;
        console.log(
            `[${seen}] ${payload.task} ${payload.va ?? ""}`
            + ` ${payload.function?.name ?? ""}${failing ? "  (failing on purpose)" : ""}`,
        );

        // Answer straight away. The real workflow must do the same: the backend
        // aborts this forward after 10 seconds, and a model call is often slower
        // than that. The result travels back on the callback, not this response.
        response.writeHead(200, { "Content-Type": "application/json" });
        response.end('{"accepted":true}');

        if (failing) return;
        setTimeout(() => void deliver(payload), LATENCY_MS);
    });
}).listen(PORT, () => {
    console.log(`mock n8n listening on http://localhost:${PORT}/webhook/analyze`);
    console.log(`latency ${LATENCY_MS}ms, failing every ${FAIL_EVERY || "never"}`);
    console.log("");
    console.log("Set this in backend/.env and restart the API:");
    console.log(`  N8N_WEBHOOK_URL=http://localhost:${PORT}/webhook/analyze`);
    console.log("");
});
