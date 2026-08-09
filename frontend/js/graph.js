/*
 * graph.js - CFG rendering, Ghidra style.
 *
 * A layered ("Sugiyama-lite") layout written by hand rather than pulled from
 * dagre or ELK. Three reasons: no build step and no npm for a team where not
 * everyone is a JS developer; it works offline from a file:// URL; and the
 * engine already emits `block_order` (reverse post-order), which does most of
 * the hard part - deciding what goes above what.
 *
 * Layout is static. No physics, no animation. A control-flow graph you are
 * reading for twenty minutes should not move.
 */

const CFGView = (function () {

    const NODE_WIDTH      = 300;
    const LINE_HEIGHT     = 13;
    const HEADER_HEIGHT   = 17;
    const NODE_PADDING    = 6;
    const LAYER_GAP       = 46;
    const SIBLING_GAP     = 28;
    const MARGIN          = 24;
    const MAX_LINES       = 14;   // per node, before eliding

    // Above this, a layered graph is unreadable at any zoom and the browser
    // struggles. notepad.exe has a real 1620-block function.
    const MAX_BLOCKS      = 200;

    function esc(text) {
        return String(text)
            .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }

    function shortAddr(va) {
        return String(va).replace(/^0x/, "").slice(-6);
    }

    /*
     * Assign each block a layer.
     *
     * Longest-path from the entry, computed over `block_order` (reverse
     * post-order). Because RPO visits every node after its non-back-edge
     * predecessors, one pass is enough - no iteration to a fixed point needed.
     *
     * Back edges (loops) point to an already-assigned lower layer and are simply
     * not allowed to push it down, which is what keeps loop headers at the top
     * of their loop where a reader expects them.
     */
    function assignLayers(blocks, order) {
        const layer = new Map();
        order.forEach(function (va) { layer.set(va, 0); });

        order.forEach(function (va) {
            const block = blocks.get(va);
            if (!block) return;
            const here = layer.get(va) || 0;

            (block.successors || []).forEach(function (edge) {
                if (!layer.has(edge.target)) return;
                if (layer.get(edge.target) <= here) {
                    // Only push forward. A back edge would otherwise drag its
                    // target down and turn the loop inside out.
                    const isBackEdge = order.indexOf(edge.target) < order.indexOf(va);
                    if (!isBackEdge) layer.set(edge.target, here + 1);
                }
            });
        });
        return layer;
    }

    function nodeHeight(block) {
        const shown = Math.min(block.instructions.length, MAX_LINES);
        const elided = block.instructions.length > MAX_LINES ? 1 : 0;
        const warn = block.has_unresolved_exit ? 1 : 0;
        return HEADER_HEIGHT + (shown + elided + warn) * LINE_HEIGHT + NODE_PADDING * 2;
    }

    function layout(detail) {
        const blocks = new Map();
        detail.blocks.forEach(function (b) { blocks.set(b.start, b); });

        // Prefer the engine's ordering; fall back to address order.
        let order = (detail.block_order || []).filter(function (va) { return blocks.has(va); });
        detail.blocks.forEach(function (b) {
            if (order.indexOf(b.start) === -1) order.push(b.start);
        });

        const layerOf = assignLayers(blocks, order);

        // Group by layer, keeping within-layer order stable.
        const layers = [];
        order.forEach(function (va) {
            const index = layerOf.get(va) || 0;
            while (layers.length <= index) layers.push([]);
            layers[index].push(va);
        });

        const placed = new Map();
        let y = MARGIN;
        let widest = 0;

        layers.forEach(function (row) {
            let rowHeight = 0;
            const totalWidth = row.length * NODE_WIDTH + (row.length - 1) * SIBLING_GAP;
            let x = MARGIN;

            row.forEach(function (va) {
                const block = blocks.get(va);
                const h = nodeHeight(block);
                placed.set(va, { va: va, block: block, x: x, y: y, w: NODE_WIDTH, h: h });
                x += NODE_WIDTH + SIBLING_GAP;
                if (h > rowHeight) rowHeight = h;
            });

            if (totalWidth > widest) widest = totalWidth;
            y += rowHeight + LAYER_GAP;
        });

        return {
            nodes: placed,
            order: order,
            width: widest + MARGIN * 2,
            height: y + MARGIN
        };
    }

    function renderNode(node, entryVa, selectedVa) {
        const b = node.block;
        const classes = ["gnode"];
        if (b.start === entryVa) classes.push("entry");
        if (b.has_unresolved_exit) classes.push("unresolved");
        if (b.start === selectedVa) classes.push("selected");

        let out = '<g class="' + classes.join(" ") + '" data-block="' + b.start + '">';
        out += '<rect x="' + node.x + '" y="' + node.y + '" width="' + node.w +
               '" height="' + node.h + '" rx="0"/>';

        let ty = node.y + NODE_PADDING + 11;
        out += '<text class="ghdr" x="' + (node.x + NODE_PADDING) + '" y="' + ty + '">' +
               esc(b.start) + '  (' + b.instructions.length + ')</text>';
        ty += HEADER_HEIGHT - 2;

        const shown = b.instructions.slice(0, MAX_LINES);
        shown.forEach(function (insn) {
            const text = shortAddr(insn.va) + "  " + insn.mnemonic +
                         (insn.operands ? " " + insn.operands : "");
            const clipped = text.length > 40 ? text.slice(0, 39) + "…" : text;
            out += '<text class="t" x="' + (node.x + NODE_PADDING) + '" y="' + ty + '">' +
                   esc(clipped) + '</text>';
            ty += LINE_HEIGHT;
        });

        if (b.instructions.length > MAX_LINES) {
            out += '<text class="t" x="' + (node.x + NODE_PADDING) + '" y="' + ty +
                   '" fill="#808080">... ' + (b.instructions.length - MAX_LINES) +
                   ' more</text>';
            ty += LINE_HEIGHT;
        }

        // Stated on the node itself. A block with no successors that is not a
        // `ret` is an unresolved switch, and a reader must not mistake it for a
        // dead end.
        if (b.has_unresolved_exit) {
            out += '<text class="t" x="' + (node.x + NODE_PADDING) + '" y="' + ty +
                   '" fill="#A00000">[unresolved exit]</text>';
        }

        out += '</g>';
        return out;
    }

    function renderEdge(from, to, kind) {
        // Route down out of the source and up into the target. When the target
        // sits above the source (a loop back edge) the path swings out to the
        // left so it does not overlap the forward edges.
        const x1 = from.x + from.w / 2;
        const y1 = from.y + from.h;
        const x2 = to.x + to.w / 2;
        const y2 = to.y;

        let d;
        if (y2 >= y1) {
            const mid = y1 + (y2 - y1) / 2;
            d = "M" + x1 + "," + y1 + " L" + x1 + "," + mid +
                " L" + x2 + "," + mid + " L" + x2 + "," + y2;
        } else {
            const side = Math.min(from.x, to.x) - 18;
            d = "M" + x1 + "," + y1 +
                " L" + x1 + "," + (y1 + 12) +
                " L" + side + "," + (y1 + 12) +
                " L" + side + "," + (y2 - 12) +
                " L" + x2 + "," + (y2 - 12) +
                " L" + x2 + "," + y2;
        }

        const cls = kind === "taken" ? "taken"
                  : kind === "jump" ? "jump"
                  : kind === "indirect-jump" ? "indirect"
                  : "fallthrough";

        let out = '<path class="gedge ' + cls + '" d="' + d + '" marker-end="url(#arrow-' +
                  cls + ')"/>';

        // Only the taken branch gets a label. Marking both sides of every
        // conditional doubles the ink for no extra information.
        if (kind === "taken") {
            out += '<text class="glabel" x="' + (x1 + 4) + '" y="' + (y1 + 11) + '">T</text>';
        }
        return out;
    }

    function marker(id, color) {
        return '<marker id="arrow-' + id + '" viewBox="0 0 10 10" refX="9" refY="5" ' +
               'markerWidth="6" markerHeight="6" orient="auto-start-reverse">' +
               '<path d="M0,1 L9,5 L0,9 z" fill="' + color + '"/></marker>';
    }

    /* Render `detail` into `host`. `onSelectBlock` fires when a node is clicked. */
    function render(host, detail, selectedVa, onSelectBlock) {
        if (!detail || !detail.blocks || detail.blocks.length === 0) {
            host.innerHTML = '<div class="empty">No blocks.</div>';
            return;
        }

        if (detail.blocks.length > MAX_BLOCKS) {
            host.innerHTML =
                '<div class="graph-warning">' +
                '<b>Graph not rendered.</b><br><br>' +
                'This function has ' + detail.blocks.length + ' basic blocks. A layered ' +
                'graph is not readable beyond roughly ' + MAX_BLOCKS + ', so the ' +
                'Disassembly tab is the better view here.<br><br>' +
                '<span class="dim">Large functions like this are usually the result of ' +
                'aggressive inlining by the optimiser rather than an analysis error - check ' +
                'the .pdata extent if in doubt.</span>' +
                '</div>';
            return;
        }

        const model = layout(detail);
        let svg = '<svg width="' + model.width + '" height="' + model.height + '" ' +
                  'xmlns="http://www.w3.org/2000/svg">';

        svg += '<defs>' +
               marker("taken", "#007000") +
               marker("fallthrough", "#707070") +
               marker("jump", "#000080") +
               marker("indirect", "#A06000") +
               '</defs>';

        // Edges first so nodes paint over them.
        model.nodes.forEach(function (node) {
            (node.block.successors || []).forEach(function (edge) {
                const target = model.nodes.get(edge.target);
                if (target) svg += renderEdge(node, target, edge.kind);
            });
        });

        model.order.forEach(function (va) {
            const node = model.nodes.get(va);
            if (node) svg += renderNode(node, detail.va, selectedVa);
        });

        svg += "</svg>";
        host.innerHTML = svg;

        if (onSelectBlock) {
            host.querySelectorAll(".gnode").forEach(function (element) {
                element.addEventListener("click", function () {
                    onSelectBlock(element.getAttribute("data-block"));
                });
            });
        }
    }

    return { render: render, MAX_BLOCKS: MAX_BLOCKS };
})();
