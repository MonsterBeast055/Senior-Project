/* Exercises the xref indexes and the AI Analysis surface. Split from
 * contract.mjs because these routes are newer and their failure modes differ:
 * contract.mjs asks "is the shape right", this asks "does the queue behave". */
const B = process.argv[2], RUN = process.argv[3];
let bad = 0;
const need = (label, ok, saw) => {
    console.log(`${ok ? "ok  " : "FAIL"}  ${label}${ok ? "" : `   saw: ${JSON.stringify(saw)}`}`);
    if (!ok) bad++;
};
const j = async (p, init) => {
    const r = await fetch(`${B}/runs/${RUN}${p}`, init);
    return { status: r.status, body: await r.json().catch(() => null) };
};

// --- xref indexes reach the frontend via /image -------------------------
const image = (await j("/image")).body;
need("image.api_xrefs present", Array.isArray(image.api_xrefs), Object.keys(image));
need("image.string_xrefs present", Array.isArray(image.string_xrefs), Object.keys(image));
const ax = image.api_xrefs[0];
need("api_xref.api / count / functions[]",
     typeof ax?.api === "string" && typeof ax?.count === "number"
     && typeof ax?.functions?.[0]?.va === "string"
     && typeof ax?.functions?.[0]?.name === "string", ax);
need("api_xref count matches functions length",
     image.api_xrefs.every((x) => x.count === x.functions.length), null);
need("api_xref key is library!name (how the UI builds it)",
     image.api_xrefs.every((x) => x.api.includes("!")), image.api_xrefs.map(x=>x.api));
// The UI derives the key from imports; the two must agree or every row shows 0.
const derived = new Set(image.imports.map(
    (i) => `${i.library}!${i.name || `ordinal_${i.ordinal}`}`));
need("every api_xref key matches a key derivable from imports",
     image.api_xrefs.every((x) => derived.has(x.api)),
     image.api_xrefs.filter(x=>!derived.has(x.api)).map(x=>x.api));
const sx = image.string_xrefs[0];
need("string_xref.address matches a string in the global list",
     image.strings.some((s) => s.address === sx.address), sx);

// --- route ordering: the literal path must win over :task ---------------
const profile = await j("/ai/behaviour-profile");
need("behaviour-profile is not swallowed by /ai/:task", profile.status === 200,
     profile.status);
need("profile is labelled evidence, not a verdict",
     profile.body?.kind === "capability-evidence", profile.body?.kind);
need("profile carries a disclaimer", typeof profile.body?.disclaimer === "string", null);
need("persistence detected from the Run key string + RegSetValueExW",
     (profile.body?.capabilities ?? []).some((c) => c.id === "persistence"),
     (profile.body?.capabilities ?? []).map((c) => c.id));
const persistence = (profile.body?.capabilities ?? []).find((c) => c.id === "persistence");
need("evidence cites the actual api_calls / strings",
     persistence?.evidence?.[0]?.api_calls?.length > 0
     || persistence?.evidence?.[0]?.strings?.length > 0, persistence?.evidence?.[0]);
need("no verdict field anywhere in the profile",
     !JSON.stringify(profile.body).match(/"(verdict|is_malware|malicious)"/), null);

// --- AI tasks ----------------------------------------------------------
for (const task of ["decompile", "bugs", "behaviour"]) {
    const got = await j(`/ai/${task}`);
    need(`GET /ai/${task}`, got.status === 200 && got.body?.task === task, got);
}
need("unknown task rejected", (await j("/ai/nonsense")).status === 400, null);

// Batch selection must work even with no n8n - that is the whole point.
const batch = await j("/ai/bugs", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ limit: 5 }),
});
need("POST batch answers 200 without n8n", batch.status === 200, batch.status);
need("batch reports state not-run without n8n", batch.body?.state === "not-run",
     batch.body?.state);
need("batch still selected functions", batch.body?.total > 0, batch.body?.total);
need("bugs task ranks the engine-flagged function first",
     Object.keys(batch.body?.items ?? {})[0] === "0x1400023a0",
     Object.keys(batch.body?.items ?? {}));
need("batch says why nothing was sent",
     /N8N_WEBHOOK_URL/.test(batch.body?.message ?? ""), batch.body?.message);

need("per-function AI result absent is 404",
     (await j("/ai/decompile/0x140002418")).status === 404, null);
need("bad va rejected", (await j("/ai/decompile/notahex")).status === 400, null);

// n8n callback path, and the severity_source guarantee.
const delivered = await j("/ai/decompile/0x140002418/result", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code: "int f(){return 0;}", model: "test",
                           severity_source: "ai", severity: "critical" }),
});
need("callback accepted", delivered.status === 200, delivered);
const stored = await j("/ai/decompile/0x140002418");
need("result now readable", stored.status === 200, stored.status);
need("severity_source forced back to engine",
     stored.body?.severity_source === "engine", stored.body?.severity_source);
const after = (await j("/ai/decompile")).body;
need("job counted the completed item", after?.done >= 1, after);

console.log(bad === 0 ? "\nAI + XREF CONTRACT OK" : `\n${bad} FAILURES`);
process.exit(bad === 0 ? 0 : 1);
