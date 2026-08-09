/*
 * CfgGraph.tsx - Control-flow graph, React Flow + dagre.
 *
 * Layout choices worth knowing about:
 *
 *   rankdir TB           control flows downward, like every disassembler
 *   ranker network-simplex  best vertical compaction of the three dagre offers
 *   no animation         a graph you are tracing must not move under the cursor
 *   nodes draggable      IDA lets you rearrange; sometimes you need to
 *
 * `block_order` from the engine is reverse post-order, and dagre respects
 * insertion order when breaking ties within a rank — so feeding nodes in that
 * order gives a left-to-right arrangement that matches execution order for free.
 */
import { useCallback, useEffect, useMemo } from "react";
import ReactFlow, {
    Background, BackgroundVariant, Controls, Handle, MarkerType, Position,
    ReactFlowProvider, useEdgesState, useNodesState, useReactFlow,
    type Edge, type Node, type NodeProps,
} from "reactflow";
import dagre from "dagre";
import "reactflow/dist/style.css";

import type { BasicBlock, EdgeKind, FunctionDetail } from "../api/types";

/* Above this a layered graph is unreadable at any zoom, and the browser starts
 * to struggle. notepad.exe contains a real 1620-block function. */
const MAX_BLOCKS = 200;

const NODE_WIDTH = 320;
const HEADER_HEIGHT = 18;
const LINE_HEIGHT = 13;
const BODY_PADDING = 5;
const MAX_LINES = 12;

interface BlockNodeData {
    block: BasicBlock;
    isEntry: boolean;
    isSelected: boolean;
}

function nodeHeight(block: BasicBlock): number {
    const shown = Math.min(block.instructions.length, MAX_LINES);
    const extra = (block.instructions.length > MAX_LINES ? 1 : 0)
                + (block.has_unresolved_exit ? 1 : 0);
    return HEADER_HEIGHT + (shown + extra) * LINE_HEIGHT + BODY_PADDING * 2;
}

function shortAddr(va: string): string {
    return va.replace(/^0x/, "").slice(-6);
}

/* --- Custom node -------------------------------------------------------- */

function BlockNode({ data }: NodeProps<BlockNodeData>) {
    const { block, isEntry, isSelected } = data;
    const shown = block.instructions.slice(0, MAX_LINES);
    const hidden = block.instructions.length - shown.length;

    const classes = ["blocknode"];
    if (isEntry) classes.push("entry");
    if (block.has_unresolved_exit) classes.push("unresolved");
    if (isSelected) classes.push("selected");

    return (
        <div className={classes.join(" ")} style={{ width: NODE_WIDTH }}>
            {/* Handles are mandatory on a custom node, and their absence was why
                the graph drew no edges at all.

                React Flow attaches every edge to a handle. Built-in node types
                render their own, which is what `sourcePosition` / `targetPosition`
                on the node object configure — but a custom component has to render
                them itself. Without them React Flow finds no endpoint, drops the
                edge silently, and you get correctly laid-out blocks floating with
                nothing between them.

                They are styled invisible in xp.css: this graph is for reading, not
                editing, so the connection dots must not be visible or draggable. */}
            <Handle type="target" position={Position.Top} isConnectable={false} />
            <Handle type="source" position={Position.Bottom} isConnectable={false} />

            <div className="bn-head">
                {block.start} ({block.instructions.length})
            </div>
            <div className="bn-body">
                {shown.map((insn) => {
                    const text = `${shortAddr(insn.va)}  ${insn.mnemonic}` +
                                 (insn.operands ? ` ${insn.operands}` : "");
                    return (
                        <div key={insn.va}>
                            {text.length > 42 ? `${text.slice(0, 41)}…` : text}
                        </div>
                    );
                })}
                {hidden > 0 && <div className="bn-more">... {hidden} more</div>}
                {/* Stated on the node itself. A successor-less block that is not
                    a `ret` is an unresolved switch, and a reader must not take
                    it for a dead end. */}
                {block.has_unresolved_exit && (
                    <div className="bn-warn">[unresolved exit]</div>
                )}
            </div>
        </div>
    );
}

const nodeTypes = { block: BlockNode };

/* --- Layout ------------------------------------------------------------- */

function edgeClass(kind: EdgeKind): string {
    switch (kind) {
        case "taken":         return "e-taken";
        case "jump":          return "e-jump";
        case "indirect-jump": return "e-indirect";
        default:              return "e-fallthrough";
    }
}

function edgeColor(kind: EdgeKind): string {
    switch (kind) {
        case "taken":         return "#007000";
        case "jump":          return "#000080";
        case "indirect-jump": return "#A06000";
        default:              return "#707070";
    }
}

function buildGraph(detail: FunctionDetail, selected: string | null) {
    const graph = new dagre.graphlib.Graph();
    graph.setDefaultEdgeLabel(() => ({}));
    graph.setGraph({
        rankdir: "TB",
        ranksep: 44,
        nodesep: 26,
        edgesep: 12,
        marginx: 20,
        marginy: 20,
        ranker: "network-simplex",
    });

    const byStart = new Map(detail.blocks.map((b) => [b.start, b]));

    // Insertion order is block_order (reverse post-order) so dagre's tie-break
    // within a rank lines up with execution order.
    const order = [
        ...detail.block_order.filter((va) => byStart.has(va)),
        ...detail.blocks.map((b) => b.start)
            .filter((va) => !detail.block_order.includes(va)),
    ];

    order.forEach((va) => {
        const block = byStart.get(va)!;
        graph.setNode(va, { width: NODE_WIDTH, height: nodeHeight(block) });
    });

    const edges: Edge[] = [];
    order.forEach((va) => {
        const block = byStart.get(va)!;
        block.successors.forEach((successor, index) => {
            if (!byStart.has(successor.target)) return;
            graph.setEdge(va, successor.target);
            edges.push({
                id: `${va}->${successor.target}#${index}`,
                source: va,
                target: successor.target,
                className: edgeClass(successor.kind),
                // smoothstep with zero radius gives the sharp orthogonal
                // corners disassemblers use, rather than curves.
                type: "smoothstep",
                pathOptions: { borderRadius: 0 },
                animated: false,
                // Only the taken branch is labelled. Marking both sides of every
                // conditional doubles the ink for no extra information.
                label: successor.kind === "taken" ? "T" : undefined,
                // Stroke set inline as well as in CSS. The colour has to match the
                // arrowhead's, and an arrowhead whose line is a different colour
                // looks like a rendering fault.
                style: { stroke: edgeColor(successor.kind), strokeWidth: 1.4 },
                markerEnd: {
                    type: MarkerType.ArrowClosed,
                    // `userSpaceOnUse`, not the default `strokeWidth`.
                    //
                    // React Flow's arrow is a polyline spanning 5 units of a
                    // 20-unit viewBox, so the visible head is a quarter of
                    // markerWidth. With the default markerUnits that quarter is
                    // then multiplied by the edge's stroke width - 1.4 here - and
                    // 14 × 1.4 / 4 comes out at about 4px. The arrows were being
                    // drawn the whole time; they were simply too small to see.
                    //
                    // In user space the size is absolute and scales with zoom like
                    // the nodes do: 28 / 20 × 5 gives a 7px head, 11px across.
                    markerUnits: "userSpaceOnUse",
                    width: 28,
                    height: 28,
                    color: edgeColor(successor.kind),
                    strokeWidth: 1,
                },
            });
        });
    });

    dagre.layout(graph);

    const nodes: Node<BlockNodeData>[] = order.map((va) => {
        const block = byStart.get(va)!;
        const placed = graph.node(va);
        return {
            id: va,
            type: "block",
            // dagre reports centres; React Flow wants top-left.
            position: {
                x: placed.x - NODE_WIDTH / 2,
                y: placed.y - nodeHeight(block) / 2,
            },
            data: {
                block,
                isEntry: va === detail.va,
                isSelected: va === selected,
            },
            sourcePosition: Position.Bottom,
            targetPosition: Position.Top,
            draggable: true,
            selectable: true,
        };
    });

    return { nodes, edges };
}

/* --- Component ---------------------------------------------------------- */

interface Props {
    detail: FunctionDetail;
    selectedBlock: string | null;
    onSelectBlock: (va: string) => void;
}

function Graph({ detail, selectedBlock, onSelectBlock }: Props) {
    const { nodes: initialNodes, edges: initialEdges } = useMemo(
        () => buildGraph(detail, selectedBlock),
        // Rebuild only when the function changes. Selection is applied below
        // without a relayout, so clicking a node cannot make the graph jump.
        [detail],
    );

    const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
    const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
    const { fitView } = useReactFlow();

    useEffect(() => {
        setNodes(initialNodes);
        setEdges(initialEdges);
        // duration 0 - a fit that animates is a fit you have to wait for.
        window.setTimeout(() => fitView({ padding: 0.12, duration: 0 }), 0);
    }, [initialNodes, initialEdges, setNodes, setEdges, fitView]);

    // Selection updates node data in place. No relayout, no movement.
    useEffect(() => {
        setNodes((current) =>
            current.map((node) =>
                node.data.isSelected === (node.id === selectedBlock)
                    ? node
                    : { ...node, data: { ...node.data, isSelected: node.id === selectedBlock } },
            ),
        );
    }, [selectedBlock, setNodes]);

    const handleNodeClick = useCallback(
        (_event: React.MouseEvent, node: Node) => onSelectBlock(node.id),
        [onSelectBlock],
    );

    return (
        <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={handleNodeClick}
            minZoom={0.1}
            maxZoom={2}
            nodesConnectable={false}
            elementsSelectable
            proOptions={{ hideAttribution: true }}
            defaultEdgeOptions={{ animated: false }}
        >
            <Background variant={BackgroundVariant.Dots} gap={18} size={1} color="#E4E2D4" />
            <Controls showInteractive={false} />
        </ReactFlow>
    );
}

export default function CfgGraph({ detail, selectedBlock, onSelectBlock }: Props) {
    if (!detail.blocks.length) {
        return <div className="empty">No blocks.</div>;
    }

    if (detail.blocks.length > MAX_BLOCKS) {
        return (
            <div className="graph-warning">
                <b>Graph not rendered.</b>
                <br />
                <br />
                This function has {detail.blocks.length} basic blocks. A layered graph is
                not readable beyond roughly {MAX_BLOCKS}, so the Disassembly tab is the
                better view here.
                <br />
                <br />
                <span className="dim">
                    Large functions like this are usually the result of aggressive inlining
                    by the optimiser rather than an analysis error — check the .pdata extent
                    if in doubt.
                </span>
            </div>
        );
    }

    return (
        <ReactFlowProvider>
            <Graph
                detail={detail}
                selectedBlock={selectedBlock}
                onSelectBlock={onSelectBlock}
            />
        </ReactFlowProvider>
    );
}
