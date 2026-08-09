/* The Findings box merges engine and AI rows. Its correctness rests on the backend
 * shaping AI results like engine findings AND refusing to let a model set severity.
 * Both are asserted here. */
const B = process.argv[2], RUN = process.argv[3];
let bad = 0;
const need = (l, ok, saw) => {
    console.log(`${ok ? "ok  " : "FAIL"}  ${l}${ok ? "" : `   saw: ${JSON.stringify(saw)}`}`);
    if (!ok) bad++;
};
const j = async (p, init) => {
    const r = await fetch(`${B}/runs/${RUN}${p}`, init);
    return { status: r.status, body: await r.json().catch(() => null) };
};

// Empty, not an error, before anything has run.
let ai = await j("/ai-findings");
need("ai-findings answers 200 with nothing run", ai.status === 200, ai.status);
need("empty list rather than 404", Array.isArray(ai.body?.findings) && ai.body.findings.length === 0,
     ai.body?.findings);
need("reports n8n state", ai.body?.n8n_configured === false, ai.body?.n8n_configured);

// Queue, then deliver a result the way n8n would - including a severity the model
// must not be allowed to set, and a bogus one it invented with no engine backing.
await j("/ai/bugs", { method: "POST", headers: { "Content-Type": "application/json" },
                      body: JSON.stringify({ limit: 5 }) });
await j("/ai/bugs/0x1400023a0/result", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
        model: "test-model",
        issues: [
            { title: "Unbounded copy from registry value",
              detail: "lstrcpyW has no length argument.",
              engine_finding: "KERNEL32.dll!lstrcpyW", confidence: "high" },
            { title: "Invented issue with no engine finding",
              detail: "The model made this up.", confidence: "low" },
        ],
        severity: "critical",          // must be ignored
        severity_source: "ai",         // must be overwritten
    }),
});

ai = await j("/ai-findings");
const rows = ai.body?.findings ?? [];
need("AI rows now returned", rows.length === 2, rows.length);
need("row shape matches engine findings (function/api/kind/severity)",
     rows.every(r => "function" in r && "api" in r && "kind" in r && "severity" in r), rows[0]);
need("source tagged ai", rows.every(r => r.source === "ai"), rows.map(r => r.source));
need("severity_source forced to engine", rows.every(r => r.severity_source === "engine"),
     rows.map(r => r.severity_source));

const corroborated = rows.find(r => r.engine_corroborated);
const invented = rows.find(r => !r.engine_corroborated);
need("corroborated row exists", !!corroborated, null);
need("corroborated severity copied from the engine, not the model",
     corroborated?.severity === "high" || corroborated?.severity === "medium",
     corroborated?.severity);
need("model's 'critical' never appears anywhere",
     !JSON.stringify(rows).includes("critical"), null);
need("uncorroborated row is flagged, not hidden",
     !!invented && invented.engine_corroborated === false, invented);
need("uncorroborated row carries the engine's call path only when it has one",
     Array.isArray(invented?.call_path), invented?.call_path);
need("note explains the provenance rule", /engine/.test(ai.body?.note ?? ""), ai.body?.note);

console.log(bad === 0 ? "\nFINDINGS BOX CONTRACT OK" : `\n${bad} FAILURES`);
process.exit(bad === 0 ? 0 : 1);
