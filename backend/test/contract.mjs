/* Replays exactly what App.tsx's loadRun does, then checks that every field the
 * UI components actually read is present. A route that answers 200 with the wrong
 * shape is the failure mode a status-code test misses. */
const B = process.argv[2];
const RUN = process.argv[3];
const j = async (p) => (await fetch(`${B}/runs/${RUN}${p}`)).json();

const [image, functions, findings, strings] = await Promise.all([
    j("/image"), j("/functions"), j("/findings"), j("/strings"),
]);

let bad = 0;
const need = (label, ok, saw) => {
    console.log(`${ok ? "ok  " : "FAIL"}  ${label}${ok ? "" : `   saw: ${JSON.stringify(saw)}`}`);
    if (!ok) bad++;
};

// App.tsx status bar + MetricsBar + Analysis menu
need("image.arch", typeof image.arch === "string", image.arch);
need("image.image_base is a hex string, not a number", typeof image.image_base === "string", image.image_base);
need("image.coverage.code_fraction", typeof image.coverage?.code_fraction === "number", image.coverage);
need("image.coverage.function_count", typeof image.coverage?.function_count === "number", image.coverage);
// SymbolTree: imports grouped by library; SectionsPane
need("image.imports[].library", Array.isArray(image.imports) && typeof image.imports[0]?.library === "string", image.imports?.[0]);
need("image.sections[].name", Array.isArray(image.sections) && typeof image.sections[0]?.name === "string", image.sections?.[0]);

// getFunctions unwraps { functions: [...] }
need("functions.functions is an array", Array.isArray(functions.functions), Object.keys(functions));
const f = functions.functions[0];
for (const k of ["va", "name", "block_count", "instruction_count"]) {
    need(`function.${k}`, f?.[k] !== undefined, f);
}
need("function.va is hex string", typeof f?.va === "string" && f.va.startsWith("0x"), f?.va);

// The score popup reproduces the engine's arithmetic, so it needs the inputs and
// not just the total. Missing any of these makes the breakdown silently show
// zeroes that do not add up to the score beside them.
for (const k of ["api_call_count", "string_count", "cyclomatic_complexity",
                 "caller_count", "information_score"]) {
    need(`function.${k} (input to the score derivation)`, f?.[k] !== undefined, f);
}

// getStrings unwraps { strings: [...] } - the field this session added to the engine
need("strings.strings is an array", Array.isArray(strings.strings), Object.keys(strings));
const s = strings.strings[0];
need("string.address", typeof s?.address === "string", s);
need("string.encoding is 'ascii' or 'utf16'", ["ascii", "utf16"].includes(String(s?.encoding).toLowerCase()), s?.encoding);
need("string.text", typeof s?.text === "string", s);

// FindingsPane + FindingWindow
need("findings.summary.impactful", typeof findings.summary?.impactful === "number", findings.summary);
need("findings.summary.risky_operations", typeof findings.summary?.risky_operations === "number", findings.summary);
const g = findings.findings[0];
for (const k of ["function", "function_name", "api", "kind", "severity", "base_severity",
                 "reachable_from_input", "sources", "call_path", "limitation"]) {
    need(`finding.${k}`, g?.[k] !== undefined, g);
}

// The explain route is built from finding.function + finding.api, so that exact
// pair must be the one the backend can look up again.
const url = `${B}/runs/${RUN}/findings/${g.function}/${encodeURIComponent(g.api)}/explanation`;
need("explanation URL from finding.function/api is routable (404 = absent, not 400)",
     [200, 404].includes((await fetch(url)).status), url);

// getFunction(va) with the va straight out of the function list
const detail = await j(`/functions/${f.va}`);
need("functions/{va} from the list resolves", detail?.va === f.va, detail);

console.log(bad === 0 ? "\nCONTRACT OK - every field the UI reads is present"
                      : `\n${bad} CONTRACT FAILURES`);
process.exit(bad === 0 ? 0 : 1);
