/*
 * FloatingWindow.tsx - A movable, resizable XP window.
 *
 * Deliberately NOT an <iframe>. An iframe is a separate document with its own
 * React root, so the graph inside it could not share `selectedBlock` with the
 * listing — and click-a-C-line-to-highlight-the-block is the whole reason the
 * panes sit side by side. A floating panel gives the same drag-anywhere
 * behaviour while staying in one component tree.
 *
 * Position is tracked in a ref during a drag and committed to state on each
 * move, but the element is positioned with `left/top` rather than a transform so
 * there is nothing to animate. No easing, no inertia.
 */
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";

interface Rect {
    x: number;
    y: number;
    width: number;
    height: number;
}

interface Props {
    title: string;
    hint?: string;
    initial?: Partial<Rect>;
    onClose: () => void;
    children: ReactNode;
}

const MIN_WIDTH = 320;
const MIN_HEIGHT = 200;

function clampToViewport(rect: Rect): Rect {
    const maxX = Math.max(0, window.innerWidth - 120);
    const maxY = Math.max(0, window.innerHeight - 60);
    return {
        // Leave part of the title bar reachable, so a window can never be
        // dragged somewhere it cannot be dragged back from.
        x: Math.min(Math.max(rect.x, -(rect.width - 120)), maxX),
        y: Math.min(Math.max(rect.y, 0), maxY),
        width: Math.max(MIN_WIDTH, Math.min(rect.width, window.innerWidth)),
        height: Math.max(MIN_HEIGHT, Math.min(rect.height, window.innerHeight)),
    };
}

export default function FloatingWindow({
    title, hint, initial, onClose, children,
}: Props) {
    const [rect, setRect] = useState<Rect>(() =>
        clampToViewport({
            x: initial?.x ?? Math.max(20, window.innerWidth - 700),
            y: initial?.y ?? 120,
            width: initial?.width ?? 640,
            height: initial?.height ?? 480,
        }),
    );
    const [maximised, setMaximised] = useState(false);
    const [dragging, setDragging] = useState(false);

    // Kept in a ref so the move handler is not recreated on every pixel.
    const gesture = useRef<{
        mode: "move" | "resize";
        startX: number;
        startY: number;
        origin: Rect;
    } | null>(null);

    const onPointerDown = useCallback(
        (mode: "move" | "resize") => (event: React.PointerEvent) => {
            if (maximised) return;
            event.preventDefault();
            (event.target as HTMLElement).setPointerCapture?.(event.pointerId);
            gesture.current = {
                mode,
                startX: event.clientX,
                startY: event.clientY,
                origin: rect,
            };
            setDragging(true);
            document.body.classList.add("dragging-window");
        },
        [rect, maximised],
    );

    useEffect(() => {
        if (!dragging) return;

        function onMove(event: PointerEvent) {
            const active = gesture.current;
            if (!active) return;
            const dx = event.clientX - active.startX;
            const dy = event.clientY - active.startY;

            setRect(
                clampToViewport(
                    active.mode === "move"
                        ? { ...active.origin, x: active.origin.x + dx, y: active.origin.y + dy }
                        : {
                              ...active.origin,
                              width: active.origin.width + dx,
                              height: active.origin.height + dy,
                          },
                ),
            );
        }

        function onUp() {
            gesture.current = null;
            setDragging(false);
            document.body.classList.remove("dragging-window");
        }

        window.addEventListener("pointermove", onMove);
        window.addEventListener("pointerup", onUp);
        window.addEventListener("pointercancel", onUp);
        return () => {
            window.removeEventListener("pointermove", onMove);
            window.removeEventListener("pointerup", onUp);
            window.removeEventListener("pointercancel", onUp);
        };
    }, [dragging]);

    // A window left off-screen after the browser is resized would be
    // unreachable, so re-clamp whenever the viewport changes.
    useEffect(() => {
        function onResize() {
            setRect((current) => clampToViewport(current));
        }
        window.addEventListener("resize", onResize);
        return () => window.removeEventListener("resize", onResize);
    }, []);

    useEffect(() => {
        function onKey(event: KeyboardEvent) {
            if (event.key === "Escape") onClose();
        }
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [onClose]);

    const style: React.CSSProperties = maximised
        ? { left: 6, top: 6, width: "calc(100vw - 14px)", height: "calc(100vh - 14px)" }
        : { left: rect.x, top: rect.y, width: rect.width, height: rect.height };

    return (
        <div className="floatwin" style={style}>
            <div
                className={`fw-title${dragging ? " dragging" : ""}`}
                onPointerDown={onPointerDown("move")}
                onDoubleClick={() => setMaximised((m) => !m)}
            >
                <span>{title}</span>
                {hint && <span className="fw-hint">{hint}</span>}
                <span style={{ flex: 1 }} />
                <button
                    className="fw-btn"
                    title={maximised ? "Restore" : "Maximize"}
                    onPointerDown={(event) => event.stopPropagation()}
                    onClick={() => setMaximised((m) => !m)}
                >
                    {maximised ? "❐" : "□"}
                </button>
                <button
                    className="fw-btn close"
                    title="Close (Esc)"
                    onPointerDown={(event) => event.stopPropagation()}
                    onClick={onClose}
                >
                    ×
                </button>
            </div>

            <div className="fw-body">{children}</div>

            {!maximised && (
                <div className="fw-grip" onPointerDown={onPointerDown("resize")} />
            )}
        </div>
    );
}
