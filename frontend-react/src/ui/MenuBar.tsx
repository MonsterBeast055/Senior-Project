/*
 * MenuBar.tsx - Working menus and the global search.
 *
 * The previous version was decoration: six labels that did nothing, hidden
 * entirely below 560px. Now every item maps to a real action, and the bar
 * survives at every width — hiding it removed the only route to the actions
 * inside it.
 *
 * Search lives here rather than in the workspace toolbar. It searches the whole
 * run — functions, imports, strings, findings — so it belongs to the window, not
 * to one pane. Ctrl+K or "/" focuses it.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import type {
    ExtractedString, FindingsDocument, FunctionSummary, ImageInfo,
} from "../api/types";

export interface MenuAction {
    label: string;
    accel?: string;
    enabled?: boolean;
    checked?: boolean;
    run?: () => void;
    separator?: boolean;
}

export interface MenuDefinition {
    title: string;
    items: MenuAction[];
}

/* --- Global search ------------------------------------------------------ */

type HitKind = "function" | "import" | "string" | "finding" | "section";

interface Hit {
    kind: HitKind;
    label: string;
    detail: string;
    va?: string;
}

const MAX_HITS_PER_GROUP = 8;

function search(
    query: string,
    functions: FunctionSummary[],
    image: ImageInfo | null,
    strings: ExtractedString[],
    findings: FindingsDocument | null,
): Hit[] {
    const needle = query.trim().toLowerCase();
    if (needle.length < 2) return [];
    const hits: Hit[] = [];

    // An exact address typed in should win outright — that is what a person
    // pasting a VA from a crash dump wants.
    const asAddress = needle.startsWith("0x") ? needle : `0x${needle}`;
    const exact = functions.find((f) => f.va.toLowerCase() === asAddress);
    if (exact) {
        hits.push({
            kind: "function",
            label: exact.name,
            detail: `${exact.va} · exact address`,
            va: exact.va,
        });
    }

    functions
        .filter((f) => f.name.toLowerCase().includes(needle) || f.va.toLowerCase().includes(needle))
        .filter((f) => f.va.toLowerCase() !== asAddress)
        .slice(0, MAX_HITS_PER_GROUP)
        .forEach((f) =>
            hits.push({
                kind: "function",
                label: f.name,
                detail: `${f.va} · ${f.block_count} blk · sc ${f.information_score ?? 0}`,
                va: f.va,
            }),
        );

    (findings?.findings ?? [])
        .filter((f) =>
            f.api.toLowerCase().includes(needle) || f.kind.toLowerCase().includes(needle))
        .slice(0, MAX_HITS_PER_GROUP)
        .forEach((f) =>
            hits.push({
                kind: "finding",
                label: `${f.kind} — ${f.api.split("!").pop()}`,
                detail: `${f.severity} · ${f.function}`,
                va: f.function,
            }),
        );

    (image?.imports ?? [])
        .filter((entry) => entry.name.toLowerCase().includes(needle))
        .slice(0, MAX_HITS_PER_GROUP)
        .forEach((entry) =>
            hits.push({
                kind: "import",
                label: entry.name,
                detail: `${entry.library} · ${entry.iat_slot}`,
            }),
        );

    strings
        .filter((entry) => entry.text.toLowerCase().includes(needle))
        .slice(0, MAX_HITS_PER_GROUP)
        .forEach((entry) =>
            hits.push({
                kind: "string",
                label: entry.text,
                detail: `${entry.address} · ${entry.encoding}`,
            }),
        );

    (image?.sections ?? [])
        .filter((section) => section.name.toLowerCase().includes(needle))
        .forEach((section) =>
            hits.push({
                kind: "section",
                label: section.name,
                detail: `${section.va} · entropy ${section.entropy.toFixed(2)}`,
            }),
        );

    return hits;
}

interface Props {
    menus: MenuDefinition[];
    functions: FunctionSummary[];
    image: ImageInfo | null;
    strings: ExtractedString[];
    findings: FindingsDocument | null;
    onOpenFunction: (va: string) => void;
    searchEnabled: boolean;
}

export default function MenuBar({
    menus, functions, image, strings, findings, onOpenFunction, searchEnabled,
}: Props) {
    const [openMenu, setOpenMenu] = useState<string | null>(null);
    const [query, setQuery] = useState("");
    const [highlight, setHighlight] = useState(0);
    const inputRef = useRef<HTMLInputElement>(null);

    const hits = useMemo(
        () => (searchEnabled ? search(query, functions, image, strings, findings) : []),
        [query, functions, image, strings, findings, searchEnabled],
    );

    useEffect(() => setHighlight(0), [query]);

    // Ctrl+K, or "/" when not already typing in a field.
    useEffect(() => {
        function onKey(event: KeyboardEvent) {
            const typing = ["INPUT", "TEXTAREA", "SELECT"].includes(
                (event.target as HTMLElement)?.tagName,
            );
            if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
                event.preventDefault();
                inputRef.current?.focus();
            } else if (event.key === "/" && !typing) {
                event.preventDefault();
                inputRef.current?.focus();
            } else if (event.key === "Escape") {
                setOpenMenu(null);
                setQuery("");
            }
        }
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, []);

    function choose(hit: Hit) {
        if (hit.va) onOpenFunction(hit.va);
        setQuery("");
        inputRef.current?.blur();
    }

    function onSearchKey(event: React.KeyboardEvent) {
        if (hits.length === 0) return;
        if (event.key === "ArrowDown") {
            event.preventDefault();
            setHighlight((current) => Math.min(current + 1, hits.length - 1));
        } else if (event.key === "ArrowUp") {
            event.preventDefault();
            setHighlight((current) => Math.max(current - 1, 0));
        } else if (event.key === "Enter") {
            event.preventDefault();
            choose(hits[highlight]);
        }
    }

    // Group hits so a long function list cannot bury the one string match.
    const grouped = useMemo(() => {
        const order: HitKind[] = ["function", "finding", "import", "string", "section"];
        const map = new Map<HitKind, Hit[]>();
        hits.forEach((hit) => {
            const list = map.get(hit.kind) ?? [];
            list.push(hit);
            map.set(hit.kind, list);
        });
        return order.filter((kind) => map.has(kind)).map((kind) => [kind, map.get(kind)!] as const);
    }, [hits]);

    let flatIndex = -1;

    return (
        <div className="menubar">
            {openMenu && <div className="menu-scrim" onClick={() => setOpenMenu(null)} />}

            {menus.map((menu) => (
                <div key={menu.title} style={{ position: "relative" }}>
                    <div
                        className={`item${openMenu === menu.title ? " open" : ""}`}
                        onClick={() =>
                            setOpenMenu((current) => (current === menu.title ? null : menu.title))
                        }
                        // Hovering a sibling while a menu is open switches to it,
                        // as menus have always worked.
                        onMouseEnter={() => openMenu && setOpenMenu(menu.title)}
                    >
                        {menu.title}
                    </div>

                    {openMenu === menu.title && (
                        <div className="menu-pop">
                            {menu.items.map((item, index) =>
                                item.separator ? (
                                    <div className="msep" key={`sep${index}`} />
                                ) : (
                                    <div
                                        key={item.label}
                                        className={
                                            "mi" +
                                            (item.enabled === false ? " disabled" : "") +
                                            (item.checked ? " checked" : "")
                                        }
                                        onClick={() => {
                                            if (item.enabled === false) return;
                                            item.run?.();
                                            setOpenMenu(null);
                                        }}
                                    >
                                        <span>{item.label}</span>
                                        {item.accel && <span className="accel">{item.accel}</span>}
                                    </div>
                                ),
                            )}
                        </div>
                    )}
                </div>
            ))}

            <div className="globalsearch">
                <input
                    ref={inputRef}
                    className="xp"
                    style={{ width: 210 }}
                    placeholder={searchEnabled ? "Go to…  (Ctrl+K)" : "Open a run to search"}
                    value={query}
                    disabled={!searchEnabled}
                    onChange={(event) => setQuery(event.target.value)}
                    onKeyDown={onSearchKey}
                />
                {query && <button className="xp" onClick={() => setQuery("")}>×</button>}

                {hits.length > 0 && (
                    <div className="searchpop">
                        {grouped.map(([kind, list]) => (
                            <div key={kind}>
                                <div className="sgroup">
                                    {kind}
                                    {list.length >= MAX_HITS_PER_GROUP ? " (first 8)" : ""}
                                </div>
                                {list.map((hit) => {
                                    flatIndex += 1;
                                    const index = flatIndex;
                                    return (
                                        <div
                                            key={`${kind}${index}`}
                                            className={`sitem${index === highlight ? " active" : ""}`}
                                            onMouseEnter={() => setHighlight(index)}
                                            onClick={() => choose(hit)}
                                        >
                                            <span className="skind">{hit.kind}</span>
                                            <span className="mono">{hit.label}</span>
                                            <span className="dim" style={{ marginLeft: "auto" }}>
                                                {hit.detail}
                                            </span>
                                        </div>
                                    );
                                })}
                            </div>
                        ))}
                    </div>
                )}

                {searchEnabled && query.trim().length >= 2 && hits.length === 0 && (
                    <div className="searchpop">
                        <div className="empty">No match for “{query}”.</div>
                    </div>
                )}
            </div>
        </div>
    );
}
