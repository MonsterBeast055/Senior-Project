/*
 * Chrome.tsx - The XP window furniture. Purely presentational.
 */
import type { ReactNode } from "react";

/* The XP title bar, minus the window buttons.
 *
 * Minimise, maximise and close were pure decoration: this runs in a browser tab,
 * so the browser already owns those actions and ours could not do anything. A
 * control that looks clickable and does nothing is worse than no control — the
 * floating windows inside the app have real ones, which made these actively
 * misleading by comparison. */
export function TitleBar({ title }: { title: string }) {
    return (
        <div className="titlebar">
            <div className="icon">SP</div>
            <div>{title}</div>
            <div className="spacer" />
        </div>
    );
}

export function Panel({
    caption, hint, children, tabs,
}: {
    caption: ReactNode;
    hint?: ReactNode;
    children: ReactNode;
    tabs?: ReactNode;
}) {
    return (
        <div className="panel">
            <div className="caption">
                {caption}
                <span className="spacer" />
                {hint && <span className="hint">{hint}</span>}
            </div>
            {tabs}
            <div className="body">{children}</div>
        </div>
    );
}

export function TabStrip<T extends string>({
    tabs, active, onChange,
}: {
    tabs: readonly T[];
    active: T;
    onChange: (tab: T) => void;
}) {
    return (
        <div className="tabstrip">
            {tabs.map((tab) => (
                <div
                    key={tab}
                    className={`tab${tab === active ? " active" : ""}`}
                    onClick={() => onChange(tab)}
                >
                    {tab}
                </div>
            ))}
        </div>
    );
}

export function StatusBar({ cells }: { cells: { text: string; grow?: boolean }[] }) {
    return (
        <div className="statusbar">
            {cells.map((cell, index) => (
                <div key={index} className={`cell${cell.grow ? " grow" : ""}`}>
                    {cell.text}
                </div>
            ))}
        </div>
    );
}

export function Severity({ level }: { level: string }) {
    return <span className={`sev ${level}`}>{level}</span>;
}
