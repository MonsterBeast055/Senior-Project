/*
 * BackendStatus.tsx - Is the API up, and does it have the engine?
 *
 * This exists because of a specific, wasteful failure: the frontend was running,
 * the backend was not, and the only evidence was ECONNREFUSED in the Vite
 * terminal. The app itself said nothing useful. Two processes have to be running
 * for this to work, so the app should say which one is missing.
 *
 * Polls slowly. The point is to notice the backend coming up a few seconds after
 * you start it, not to monitor it.
 */
import { useCallback, useEffect, useState } from "react";
import { currentMode, getHealth, type HealthReport } from "../api/client";

interface Props {
    /** Bumped by the shell when the data mode or base URL changes, to force a
     *  recheck rather than waiting out the poll interval. */
    nonce?: unknown;
}

export default function BackendStatus({ nonce }: Props) {
    const [health, setHealth] = useState<HealthReport | null>(null);
    const [checking, setChecking] = useState(false);

    const check = useCallback(async () => {
        setChecking(true);
        try {
            setHealth(await getHealth());
        } finally {
            setChecking(false);
        }
    }, []);

    useEffect(() => {
        void check();
        const timer = window.setInterval(() => void check(), 5000);
        return () => window.clearInterval(timer);
    }, [check, nonce]);

    if (currentMode() === "sample") {
        return <span className="dim" title="No backend is being used.">sample data</span>;
    }

    if (!health) {
        return <span className="dim">checking…</span>;
    }

    // Three states, not two. A reachable API with a missing engine is a real and
    // distinct situation — uploads will fail, and the fix is different.
    if (!health.reachable) {
        return (
            <span className="health down">
                <span className="dot" />
                API down
                <button
                    className="xp"
                    style={{ marginLeft: 5 }}
                    disabled={checking}
                    onClick={() => void check()}
                    title={health.detail}
                >
                    Retry
                </button>
            </span>
        );
    }

    if (health.engine_ok === false) {
        return (
            <span className="health warn" title={`Not found: ${health.engine_path}`}>
                <span className="dot" />
                engine missing
            </span>
        );
    }

    return (
        <span
            className="health up"
            title={
                `API up · engine ${health.engine_path ?? "found"}`
                + (health.n8n_configured ? " · n8n configured" : " · n8n not configured")
            }
        >
            <span className="dot" />
            API up
        </span>
    );
}
