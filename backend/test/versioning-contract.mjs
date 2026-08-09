/* Versioning: a manual re-lift must supersede without destroying, and a finding
 * derived from the replaced version must be flagged rather than silently
 * re-pointed at text it never saw. */
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
const post = (p, body) => j(p, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
});
const V = "0x1400023a0";

// 1. Automated pass lifts the function.
await post(`/ai/decompile/${V}/result`,
    { model: "auto-model", code: "int f(){ /* v1 */ }", summary: "AUTOMATED SUMMARY" });
let lifted = (await j(`/functions/${V}/lifted`)).body;
need("automated lift is current", lifted.origin === "automated", lifted.origin);
const v1 = lifted.version_id;
need("it has a version id", typeof v1 === "string" && v1.startsWith("automated@"), v1);

// 2. Bug pass runs and is stamped with the version it read.
await post("/ai/bugs", { limit: 5 });
await post(`/ai/bugs/${V}/result`, {
    model: "auto-model",
    issues: [{ title: "Unbounded copy", detail: "no length argument",
               engine_finding: "KERNEL32.dll!lstrcpyW" }],
});
let ai = (await j("/ai-findings")).body;
need("the finding records what it was derived from",
     ai.findings[0]?.derived_from === v1, ai.findings[0]?.derived_from);
need("and is not stale yet", ai.findings[0]?.stale === false, ai.findings[0]?.stale);

// 3. The user presses Lift with AI. New result becomes current.
await post(`/functions/${V}/lifted`,
    { model: "manual-model", code: "int f(){ /* v2 */ }", summary: "MANUAL SUMMARY" });
lifted = (await j(`/functions/${V}/lifted`)).body;
need("manual lift wins in the pane", lifted.origin === "manual", lifted.origin);
need("the pane shows the new code",
     lifted.c_code.join("\n").includes("v2"), lifted.c_code);
need("description is the new summary",
     lifted.description === "MANUAL SUMMARY", lifted.description);

// 4. The automated version is NOT destroyed.
need("the automated version survives in history",
     (lifted.superseded ?? []).some((v) => v.version_id === v1),
     lifted.superseded);

// 5. The finding is now flagged stale, but still present.
ai = (await j("/ai-findings")).body;
need("the finding still exists", ai.findings.length >= 1, ai.findings.length);
need("it is flagged stale", ai.findings[0]?.stale === true, ai.findings[0]?.stale);
need("it still points at the version it actually used",
     ai.findings[0]?.derived_from === v1, ai.findings[0]?.derived_from);
need("its severity is still the engine's",
     ai.findings[0]?.severity_source === "engine", ai.findings[0]?.severity_source);

// 6. Re-running the automated pass does not clobber the manual one silently.
await post(`/ai/decompile/${V}/result`,
    { model: "auto-model", code: "int f(){ /* v3 */ }", summary: "AUTOMATED AGAIN" });
lifted = (await j(`/functions/${V}/lifted`)).body;
need("a later automated lift becomes current", lifted.origin === "automated", lifted.origin);
need("and the manual one is preserved in history",
     (lifted.superseded ?? []).some((v) => v.origin === "manual"),
     lifted.superseded);

console.log(bad === 0 ? "\nVERSIONING OK" : `\n${bad} FAILURES`);
process.exit(bad === 0 ? 0 : 1);
