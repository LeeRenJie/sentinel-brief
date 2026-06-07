import { useState } from "react";
import { motion } from "framer-motion";
import { Check, X, Bolt } from "./icons.jsx";

function ActionCard({ action, i }) {
  const [state, setState] = useState("pending"); // pending | approved | dismissed

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.1 + i * 0.07, duration: 0.5 }}
      className={`rounded-xl border p-4 transition-colors ${
        state === "approved"
          ? "border-verdant/40 bg-verdant/[0.05]"
          : state === "dismissed"
          ? "border-line/50 bg-ink-800/30 opacity-55"
          : "border-line bg-ink-800/50"
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-display text-sm font-semibold text-chalk">
              {action.title}
            </span>
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-1.5 font-mono text-[10px]">
            <span className="rounded bg-signal/15 px-1.5 py-0.5 font-semibold uppercase tracking-wider text-signal">
              dry-run
            </span>
            <span className="rounded bg-ink-700 px-1.5 py-0.5 text-mist-dim">
              {action.tool}
            </span>
            <span className="text-mist-faint">approval required</span>
          </div>
        </div>
        {state === "pending" ? (
          <div className="flex shrink-0 gap-1.5">
            <button
              onClick={() => setState("approved")}
              className="flex h-8 w-8 items-center justify-center rounded-lg border border-verdant/30 bg-verdant/10 text-verdant transition-colors hover:bg-verdant/20"
              title="Approve (dry-run)"
            >
              <Check width={15} height={15} />
            </button>
            <button
              onClick={() => setState("dismissed")}
              className="flex h-8 w-8 items-center justify-center rounded-lg border border-line bg-ink-700/60 text-mist-dim transition-colors hover:text-ember"
              title="Dismiss"
            >
              <X width={15} height={15} />
            </button>
          </div>
        ) : (
          <span
            className={`shrink-0 rounded-md px-2.5 py-1.5 font-mono text-[10px] font-bold uppercase tracking-wider ${
              state === "approved"
                ? "bg-verdant/15 text-verdant"
                : "bg-ink-700 text-mist-faint"
            }`}
          >
            {state === "approved" ? "queued · dry-run" : "dismissed"}
          </span>
        )}
      </div>
      <p className="mt-3 text-xs leading-relaxed text-mist-dim">{action.rationale}</p>
    </motion.div>
  );
}

export default function ProposedActions({ brief }) {
  return (
    <div>
      <div className="mb-4 flex items-center gap-2">
        <Bolt width={15} height={15} className="text-signal" />
        <h3 className="font-display text-sm font-semibold uppercase tracking-wider text-chalk">
          Proposed actions
        </h3>
        <span className="font-mono text-[10px] text-mist-faint">
          human-in-the-loop · nothing executes without approval
        </span>
      </div>
      <div className="grid gap-3 md:grid-cols-3">
        {brief.proposed_actions.map((a, i) => (
          <ActionCard key={a.action_id} action={a} i={i} />
        ))}
      </div>
    </div>
  );
}
