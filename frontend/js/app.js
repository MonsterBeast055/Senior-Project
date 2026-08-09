/*
 * app.js - Panes, selection and the links between them.
 *
 * The feature that justifies the whole layout is the three-way link: click a
 * line of decompiled C, and the corresponding basic block highlights in both the
 * disassembly and the graph. That is what Ghidra's dual view gets right, and it
 * only works because the AI layer returns `line_mapping` alongside the C.
 * Without that field the panes are three disconnected text boxes.
 */

(function () {
    "use strict";

    const state = {
        image: null,
        functions: [],
        findings: null,
        strings: [],
        current: null,        // function detail
        lifted: null,         // AI output for the current function
        selectedBlock: null,
        sortKey: "va",
        sortDesc: false
    };

    const $  = function (id) { return document.getElementById(id); };
    const esc = function (t) {
        return String(t == null ? "" : t)
            .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    };

    function status(message) { $("st-msg").textContent = message; }

    // --- Tabs ------------------------------------------------------------
    function wireTabs(stripId) {
        const strip = $(stripId);
        strip.addEventListener("click", function (event) {
            const tab = event.target.closest(".tab");
            if (!tab) return;

            strip.querySelectorAll(".tab").forEach(function (t) {
                t.classList.toggle("active", t === tab);
            });
            const container = strip.parentElement;
            container.querySelectorAll(".tabpage").forEach(function (page) {
                page.classList.toggle("active", page.id === tab.getAttribute("data-page"));
            });

            // The graph needs a real size to lay out into, so it is rendered on
            // first reveal rather than while hidden.
            if (tab.getAttribute("data-page") === "page-graph") drawGraph();
        });
    }

    // --- Function list ----------------------------------------------------
    function visibleFunctions() {
        const needle = $("filter").value.trim().toLowerCase();
        const hideThunks = $("hide-thunks").checked;
        const onlyInteresting = $("only-interesting").checked;

        let rows = state.functions.filter(function (f) {
            if (hideThunks && (f.is_thunk || f.is_imported_stub)) return false;
            if (onlyInteresting && (f.information_score || 0) < 20) return false;
            if (!needle) return true;
            return f.name.toLowerCase().indexOf(needle) !== -1 ||
                   f.va.toLowerCase().indexOf(needle) !== -1;
        });

        const key = state.sortKey;
        rows.sort(function (a, b) {
            let x = a[key], y = b[key];
            if (key === "va") { x = parseInt(a.va, 16); y = parseInt(b.va, 16); }
            if (typeof x === "string") return state.sortDesc ? y.localeCompare(x) : x.localeCompare(y);
            return state.sortDesc ? (y - x) : (x - y);
        });
        return rows;
    }

    function renderFunctionList() {
        const rows = visibleFunctions();
        const body = document.querySelector("#fn-table tbody");

        body.innerHTML = rows.map(function (f) {
            const selected = state.current && state.current.va === f.va ? " class=\"selected\"" : "";
            // Score 0 means "not worth a model call" - dim it so the eye skips it.
            const scoreClass = (f.information_score || 0) === 0 ? " dim" : "";
            return '<tr' + selected + ' data-va="' + f.va + '">' +
                   '<td class="mono">' + esc(f.va) + '</td>' +
                   '<td>' + esc(f.name) + '</td>' +
                   '<td class="num' + scoreClass + '">' + (f.information_score || 0) + '</td>' +
                   '<td class="num dim">' + (f.block_count || 0) + '</td>' +
                   '</tr>';
        }).join("");

        $("fn-count").textContent = rows.length + " of " + state.functions.length;

        body.querySelectorAll("tr").forEach(function (tr) {
            tr.addEventListener("click", function () { openFunction(tr.getAttribute("data-va")); });
        });
    }

    // --- Disassembly listing ----------------------------------------------
    function renderListing() {
        const detail = state.current;
        const host = $("page-listing");
        if (!detail) { host.innerHTML = '<div class="empty">Select a function.</div>'; return; }

        let html = '<div class="code">';
        detail.blocks.forEach(function (block) {
            const warn = block.has_unresolved_exit
                ? ' <span class="warn">[unresolved exit]</span>' : "";
            html += '<div class="blockhdr" data-block="' + block.start + '">' +
                    esc(block.start) + warn + '</div>';

            block.instructions.forEach(function (insn) {
                let line = '<span class="asm-addr">' + esc(insn.va) + '</span>  ' +
                           '<span class="asm-mnem">' + esc(insn.mnemonic.padEnd(7)) + '</span>' +
                           '<span class="asm-ops">' + esc(insn.operands) + '</span>';

                // The resolved name is the single most useful thing on the line.
                // It is what turns `call qword [rip+0x1f0ce]` into CreateFileW.
                if (insn.target_name) {
                    line += '  <span class="asm-api">; ' + esc(insn.target_name) + '</span>';
                }
                html += '<div class="row" data-block="' + block.start +
                        '" data-va="' + insn.va + '">' + line + '</div>';
            });
        });
        html += "</div>";
        host.innerHTML = html;

        host.querySelectorAll("[data-block]").forEach(function (element) {
            element.addEventListener("click", function () {
                selectBlock(element.getAttribute("data-block"), "listing");
            });
        });
        applyBlockHighlight();
    }

    // --- Graph -------------------------------------------------------------
    function drawGraph() {
        if (!state.current) return;
        CFGView.render($("graph-host"), state.current, state.selectedBlock, function (va) {
            selectBlock(va, "graph");
        });
    }

    // --- Decompiler --------------------------------------------------------
    function renderDecompiler() {
        const host = $("decomp");
        const lifted = state.lifted;

        if (!state.current) { host.innerHTML = '<div class="empty">Select a function.</div>'; return; }

        if (!lifted) {
            // Expected state, not an error. The AI pass runs separately and may
            // not have reached this function yet.
            host.innerHTML =
                '<div class="notice">No lifted output for this function yet.<br><br>' +
                'Decompiled C is produced by the n8n workflow and stored by the backend. ' +
                'It appears here once that pass has run.</div>';
            $("decomp-hint").textContent = "";
            return;
        }

        let html = '<div class="notice">' +
            '<b>' + esc(lifted.suggested_name) + '</b> &mdash; ' +
            'AI-generated, confidence <b>' + esc(lifted.confidence) + '</b>, ' +
            esc(lifted.review) + '.<br>' + esc(lifted.description) + '</div>';

        // Which C line belongs to which block, so clicking links the panes.
        const lineToBlock = {};
        (lifted.line_mapping || []).forEach(function (m) { lineToBlock[m.line] = m.block; });

        html += '<div class="code">';
        lifted.c_code.forEach(function (text, index) {
            const number = index + 1;
            const block = lineToBlock[number];
            html += '<div class="row"' + (block ? ' data-block="' + block + '"' : "") + '>' +
                    '<span class="asm-addr">' + String(number).padStart(3) + '</span>  ' +
                    esc(text) + '</div>';
        });
        html += "</div>";
        host.innerHTML = html;

        $("decomp-hint").textContent = (lifted.line_mapping || []).length
            ? "click a line to locate it" : "no line mapping";

        host.querySelectorAll("[data-block]").forEach(function (element) {
            element.addEventListener("click", function () {
                selectBlock(element.getAttribute("data-block"), "decomp");
            });
        });
        applyBlockHighlight();
    }

    // --- The three-way link ------------------------------------------------
    function selectBlock(va, origin) {
        state.selectedBlock = va;
        applyBlockHighlight();

        // Re-render the graph only when the click came from elsewhere; doing it
        // on a graph click would rebuild the SVG under the cursor.
        if (origin !== "graph" && $("page-graph").classList.contains("active")) {
            drawGraph();
        }
        $("st-sel").textContent = "Block " + va;

        if (origin !== "listing") {
            const target = document.querySelector('#page-listing [data-block="' + va + '"]');
            if (target) target.scrollIntoView({ block: "center" });
        }
    }

    function applyBlockHighlight() {
        document.querySelectorAll('#page-listing [data-block], #decomp [data-block]')
            .forEach(function (element) {
                element.classList.toggle("highlight",
                    element.getAttribute("data-block") === state.selectedBlock);
            });
    }

    // --- Cross-references --------------------------------------------------
    function renderXrefs() {
        const detail = state.current;
        const host = $("page-xrefs");
        if (!detail) { host.innerHTML = '<div class="empty">Select a function.</div>'; return; }

        function table(title, list) {
            if (!list || list.length === 0) {
                return '<div class="empty">No ' + title.toLowerCase() + '.</div>';
            }
            return '<table class="grid"><thead><tr><th style="width:110px">Address</th>' +
                   '<th>' + title + '</th></tr></thead><tbody>' +
                   list.map(function (r) {
                       return '<tr data-va="' + r.va + '"><td class="mono">' + esc(r.va) +
                              '</td><td>' + esc(r.name) + '</td></tr>';
                   }).join("") + "</tbody></table>";
        }

        host.innerHTML =
            '<div style="display:flex;gap:6px;align-items:flex-start">' +
            '<div style="flex:1">' + table("Called by", detail.callers) + '</div>' +
            '<div style="flex:1">' + table("Calls", detail.callees) + '</div>' +
            '</div>';

        host.querySelectorAll("tr[data-va]").forEach(function (tr) {
            tr.addEventListener("click", function () { openFunction(tr.getAttribute("data-va")); });
        });
    }

    // --- Findings ----------------------------------------------------------
    function renderFindings() {
        const host = $("page-findings");
        const data = state.findings;
        if (!data) { host.innerHTML = '<div class="empty">No findings.</div>'; return; }

        // The methodology banner is not decoration. Rendering severity without
        // it would present graph reachability as proven exploitability, which is
        // exactly what makes a security tool harmful rather than useful.
        let html = '<div class="notice"><b>Requires review.</b> ' +
            esc(data.methodology.note) + '</div>';

        html += '<table class="grid"><thead><tr>' +
                '<th style="width:74px">Severity</th>' +
                '<th style="width:104px">Function</th>' +
                '<th style="width:120px">Kind</th>' +
                '<th>API</th>' +
                '<th style="width:150px">Reachable from</th>' +
                '<th style="width:56px" class="num">Path</th>' +
                '</tr></thead><tbody>';

        data.findings.forEach(function (f) {
            const sources = f.sources && f.sources.length ? f.sources.join(", ")
                                                          : '<span class="dim">not reachable</span>';
            html += '<tr data-va="' + f.function + '" title="' + esc(f.limitation) + '">' +
                    '<td><span class="sev ' + esc(f.severity) + '">' + esc(f.severity) + '</span></td>' +
                    '<td class="mono">' + esc(f.function) + '</td>' +
                    '<td>' + esc(f.kind) + '</td>' +
                    '<td class="mono">' + esc(f.api) + '</td>' +
                    '<td>' + sources + '</td>' +
                    '<td class="num dim">' + (f.call_path ? f.call_path.length : 0) + '</td>' +
                    '</tr>';
        });
        html += "</tbody></table>";
        host.innerHTML = html;

        host.querySelectorAll("tr[data-va]").forEach(function (tr) {
            tr.addEventListener("click", function () { openFunction(tr.getAttribute("data-va")); });
        });
    }

    // --- Strings, imports, sections ---------------------------------------
    function renderStrings() {
        $("page-strings").innerHTML =
            '<table class="grid"><thead><tr>' +
            '<th style="width:110px">Address</th><th style="width:56px">Enc</th>' +
            '<th style="width:44px" class="num">Refs</th><th>Text</th>' +
            '</tr></thead><tbody>' +
            state.strings.map(function (s) {
                return '<tr><td class="mono">' + esc(s.address) + '</td>' +
                       '<td class="dim">' + esc(s.encoding) + '</td>' +
                       '<td class="num dim">' + (s.refs || 0) + '</td>' +
                       '<td class="mono asm-str">' + esc(s.text) + '</td></tr>';
            }).join("") + "</tbody></table>";
    }

    function renderImports() {
        $("page-imports").innerHTML =
            '<table class="grid"><thead><tr>' +
            '<th style="width:110px">IAT slot</th><th style="width:280px">Library</th><th>Function</th>' +
            '</tr></thead><tbody>' +
            (state.image.imports || []).map(function (i) {
                return '<tr><td class="mono">' + esc(i.iat_slot) + '</td>' +
                       '<td class="dim">' + esc(i.library) + '</td>' +
                       '<td class="mono">' + esc(i.name) + '</td></tr>';
            }).join("") + "</tbody></table>";
    }

    function renderSections() {
        $("page-sections").innerHTML =
            '<table class="grid"><thead><tr>' +
            '<th style="width:80px">Name</th><th style="width:110px">Address</th>' +
            '<th style="width:90px" class="num">Virtual</th>' +
            '<th style="width:90px" class="num">Raw</th>' +
            '<th style="width:70px">Flags</th>' +
            '<th style="width:70px" class="num">Entropy</th><th></th>' +
            '</tr></thead><tbody>' +
            (state.image.sections || []).map(function (s) {
                const flags = (s.readable ? "R" : "-") + (s.writable ? "W" : "-") +
                              (s.executable ? "X" : "-");
                // High entropy in an executable section is the classic packing
                // signal, so it is worth calling out rather than just printing.
                const packed = (s.entropy > 7.0 && s.executable)
                    ? '<span class="badge warn">high entropy</span>' : "";
                return '<tr><td class="mono">' + esc(s.name) + '</td>' +
                       '<td class="mono">' + esc(s.va) + '</td>' +
                       '<td class="num">' + s.virtual_size + '</td>' +
                       '<td class="num">' + s.raw_size + '</td>' +
                       '<td class="mono">' + flags + '</td>' +
                       '<td class="num">' + s.entropy.toFixed(3) + '</td>' +
                       '<td>' + packed + '</td></tr>';
            }).join("") + "</tbody></table>";
    }

    // --- Opening a function ------------------------------------------------
    async function openFunction(va) {
        status("Loading " + va + " ...");
        try {
            state.current = await SP.getFunction(va);
            state.lifted = await SP.getLifted(va);
        } catch (error) {
            status("Load failed: " + error.message);
            return;
        }

        if (!state.current) {
            status("No detail available for " + va +
                   " (the sample only includes 0x140002418 and 0x1400023a0)");
            return;
        }

        state.selectedBlock = null;
        $("center-title").textContent = state.current.name;
        $("center-hint").textContent =
            state.current.blocks.length + " blocks, " +
            state.current.instruction_count + " instructions, complexity " +
            state.current.cyclomatic_complexity;

        renderFunctionList();
        renderListing();
        renderDecompiler();
        renderXrefs();
        if ($("page-graph").classList.contains("active")) drawGraph();

        $("st-sel").textContent = state.current.va;
        status("Loaded " + state.current.name);
    }

    // --- Boot --------------------------------------------------------------
    async function load() {
        status("Loading analysis ...");
        SP.configure($("source-select").value, $("api-base").value);

        try {
            state.image     = await SP.getImage();
            const list      = await SP.getFunctions();
            state.functions = list.functions || [];
            state.findings  = await SP.getFindings();
            const strings   = await SP.getStrings();
            state.strings   = strings.strings || [];
        } catch (error) {
            status("Load failed: " + error.message +
                   " (is the backend running? switch Data to Sample to browse offline)");
            return;
        }

        $("st-file").textContent = "notepad.exe";
        $("st-arch").textContent = state.image.arch + "  base " + state.image.image_base;
        $("st-coverage").textContent =
            "coverage " + (state.image.coverage.code_fraction * 100).toFixed(1) + "%  " +
            state.image.coverage.function_count + " functions";

        renderFunctionList();
        renderFindings();
        renderStrings();
        renderImports();
        renderSections();

        status("Ready" + (SP.currentMode() === "sample" ? " (sample data)" : ""));
    }

    function init() {
        wireTabs("center-tabs");
        wireTabs("dock-tabs");

        $("filter").addEventListener("input", renderFunctionList);
        $("btn-clear").addEventListener("click", function () {
            $("filter").value = "";
            renderFunctionList();
        });
        $("hide-thunks").addEventListener("change", renderFunctionList);
        $("only-interesting").addEventListener("change", renderFunctionList);
        $("btn-reload").addEventListener("click", load);
        $("source-select").addEventListener("change", load);

        document.querySelectorAll("#fn-table thead th").forEach(function (th) {
            th.addEventListener("click", function () {
                const key = th.getAttribute("data-sort");
                if (!key) return;
                state.sortDesc = (state.sortKey === key) ? !state.sortDesc : false;
                state.sortKey = key;
                document.querySelectorAll("#fn-table thead th").forEach(function (other) {
                    other.classList.toggle("sorted", other === th);
                });
                renderFunctionList();
            });
        });

        load().then(function () { openFunction("0x1400023a0"); });
    }

    document.addEventListener("DOMContentLoaded", init);
})();
