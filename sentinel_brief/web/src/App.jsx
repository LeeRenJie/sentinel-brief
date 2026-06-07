import { useCallback, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import AlertQueue from "./components/AlertQueue.jsx";
import AgentWarRoom from "./components/AgentWarRoom.jsx";
import IncidentBrief from "./components/IncidentBrief.jsx";
import { sampleBrief } from "./lib/brief.js";
import { Shield } from "./components/icons.jsx";

// Three-phase state machine: queue -> war room -> brief.
export default function App() {
  const [phase, setPhase] = useState("queue");
  const brief = sampleBrief; // demo default: bundled, instant, offline-safe

  const investigate = useCallback(() => setPhase("warroom"), []);
  const reveal = useCallback(() => setPhase("brief"), []);
  const reset = useCallback(() => setPhase("queue"), []);

  return (
    <div className="console-atmosphere grain min-h-screen text-chalk">
      {/* Top status bar */}
      <header className="sticky top-0 z-50 border-b border-line/60 bg-ink-900/80 backdrop-blur-md">
        <div className="mx-auto flex max-w-6xl items-center gap-3 px-5 py-3 md:px-6">
          <button
            onClick={reset}
            className="flex items-center gap-2.5 text-left"
            title="Back to queue"
          >
            <span className="flex h-7 w-7 items-center justify-center rounded-md bg-signal/15 text-signal">
              <Shield width={16} height={16} />
            </span>
            <span className="font-display text-sm font-bold tracking-tight text-chalk">
              Sentinel<span className="text-mist-dim">Brief</span>
            </span>
          </button>

          <nav className="ml-4 hidden items-center gap-2 font-mono text-[10px] uppercase tracking-widest text-mist-faint sm:flex">
            {["queue", "warroom", "brief"].map((p, i) => (
              <span key={p} className="flex items-center gap-2">
                {i > 0 && <span className="text-line">/</span>}
                <span className={phase === p ? "text-signal" : ""}>
                  {p === "warroom" ? "war room" : p}
                </span>
              </span>
            ))}
          </nav>

          <div className="ml-auto flex items-center gap-2 font-mono text-[10px] text-mist-faint">
            <span className="hidden md:inline">queried live Splunk via MCP</span>
            <span className="flex items-center gap-1.5 rounded-full border border-verdant/30 bg-verdant/10 px-2 py-1 text-verdant">
              <span className="h-1.5 w-1.5 animate-pulseDot rounded-full bg-verdant" />
              demo · cached brief
            </span>
          </div>
        </div>
      </header>

      <main className="relative">
        <AnimatePresence mode="wait">
          {phase === "queue" && (
            <AlertQueue key="queue" brief={brief} onInvestigate={investigate} />
          )}
          {phase === "warroom" && (
            <AgentWarRoom key="warroom" onComplete={reveal} />
          )}
          {phase === "brief" && <IncidentBrief key="brief" brief={brief} />}
        </AnimatePresence>
      </main>

      {/* Provenance footer */}
      {phase === "brief" && (
        <motion.footer
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.6 }}
          className="border-t border-line/50 bg-ink-900/60"
        >
          <div className="mx-auto flex max-w-5xl flex-col items-center gap-2 px-6 py-6 text-center font-mono text-[10px] text-mist-faint sm:flex-row sm:justify-between sm:text-left">
            <span>
              queried live Splunk via the MCP Server · splunklib.ai supervisor + 4
              subagents · Gemini 2.5 on Vertex AI
            </span>
            <button
              onClick={reset}
              className="rounded border border-line px-2.5 py-1 text-mist-dim transition-colors hover:border-signal/50 hover:text-signal"
            >
              replay demo
            </button>
          </div>
        </motion.footer>
      )}
    </div>
  );
}
