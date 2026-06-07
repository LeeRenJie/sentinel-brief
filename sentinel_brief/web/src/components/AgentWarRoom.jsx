import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Branch, Crosshair, Shield, Bolt, Spark, Check } from "./icons.jsx";

const EXPO = [0.16, 1, 0.3, 1];

const AGENTS = [
  {
    id: "correlator",
    name: "Correlator",
    color: "#5cc8ff",
    icon: Crosshair,
    steps: [
      "Querying index=edr for remote-exec signals",
      "Joining auth logons by account",
      "Stitching cross-index kill chain",
    ],
  },
  {
    id: "adjudicator",
    name: "Adjudicator",
    color: "#f5a623",
    icon: Shield,
    steps: [
      "Scoring fan-out against baseline",
      "Weighing PsExec precursor signal",
      "Verdict: true positive · 100%",
    ],
  },
  {
    id: "responder",
    name: "Responder",
    color: "#ff5c49",
    icon: Bolt,
    steps: [
      "Ranking blast radius by exposure",
      "Drafting containment actions",
      "Marking all actions DRY-RUN",
    ],
  },
  {
    id: "detection-engineer",
    name: "Detection Engineer",
    color: "#34e0a1",
    icon: Spark,
    steps: [
      "Diagnosing false-positive class",
      "Rewriting SPL with EDR correlation",
      "Backtesting over last 7 days",
    ],
  },
];

function AgentCard({ agent, index, done }) {
  const [step, setStep] = useState(0);
  const Icon = agent.icon;

  useEffect(() => {
    if (done) {
      setStep(agent.steps.length - 1);
      return;
    }
    const timers = agent.steps.map((_, i) =>
      setTimeout(() => setStep(i), 700 + i * 1050 + index * 220)
    );
    return () => timers.forEach(clearTimeout);
  }, [agent.steps, index, done]);

  const complete = done || step >= agent.steps.length - 1;

  return (
    <motion.div
      initial={{ opacity: 0, y: 22, scale: 0.97 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ duration: 0.6, ease: EXPO, delay: 0.2 + index * 0.12 }}
      className="relative overflow-hidden rounded-xl border bg-ink-800/70 p-4"
      style={{ borderColor: `${agent.color}33` }}
    >
      <div
        className="pointer-events-none absolute -right-10 -top-10 h-24 w-24 rounded-full blur-2xl"
        style={{ background: `${agent.color}22` }}
      />
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <span
            className="flex h-8 w-8 items-center justify-center rounded-lg"
            style={{ background: `${agent.color}1a`, color: agent.color }}
          >
            <Icon width={16} height={16} />
          </span>
          <div className="font-display text-sm font-semibold text-chalk">
            {agent.name}
          </div>
        </div>
        {complete ? (
          <motion.span
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ type: "spring", stiffness: 380, damping: 18 }}
            className="flex h-5 w-5 items-center justify-center rounded-full"
            style={{ background: `${agent.color}26`, color: agent.color }}
          >
            <Check width={12} height={12} />
          </motion.span>
        ) : (
          <span className="flex gap-1">
            {[0, 1, 2].map((d) => (
              <span
                key={d}
                className="h-1.5 w-1.5 rounded-full animate-pulseDot"
                style={{ background: agent.color, animationDelay: `${d * 0.18}s` }}
              />
            ))}
          </span>
        )}
      </div>

      <div className="mt-3 h-5 overflow-hidden">
        <AnimatePresence mode="wait">
          <motion.div
            key={step}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.3 }}
            className="font-mono text-[11px] leading-5 text-mist-dim"
          >
            <span style={{ color: agent.color }}>›</span> {agent.steps[step]}
          </motion.div>
        </AnimatePresence>
      </div>

      <div className="mt-3 flex gap-1">
        {agent.steps.map((_, i) => (
          <div
            key={i}
            className="h-0.5 flex-1 rounded-full transition-colors duration-500"
            style={{ background: i <= step ? agent.color : "#1b2233" }}
          />
        ))}
      </div>
    </motion.div>
  );
}

// Investigating state: supervisor fans out to 4 subagents (~4.5s of theatre).
export default function AgentWarRoom({ onComplete, durationMs = 4600 }) {
  const [done, setDone] = useState(false);

  useEffect(() => {
    const finish = setTimeout(() => setDone(true), durationMs - 700);
    const next = setTimeout(() => onComplete(), durationMs);
    return () => {
      clearTimeout(finish);
      clearTimeout(next);
    };
  }, [durationMs, onComplete]);

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0, transition: { duration: 0.3 } }}
      className="mx-auto flex min-h-[78vh] max-w-4xl flex-col justify-center px-6"
    >
      <div className="mb-6 flex items-center gap-3 text-xs uppercase tracking-[0.25em] text-mist-dim">
        <span className="h-px w-8 bg-line" />
        War room · live
        <span className="ml-auto font-mono text-[10px] normal-case tracking-normal text-mist-faint">
          splunklib.ai · supervisor + 4 subagents
        </span>
      </div>

      {/* Supervisor node */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: EXPO }}
        className="mx-auto mb-6 flex w-full max-w-md items-center gap-3 rounded-xl border border-violetcue/30 bg-ink-800/80 px-5 py-4 shadow-panel"
      >
        <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-violetcue/15 text-violetcue">
          <Branch width={18} height={18} />
        </span>
        <div>
          <div className="font-display text-sm font-semibold text-chalk">
            Supervisor
          </div>
          <div className="font-mono text-[11px] text-mist-dim">
            fanning out · gathering 4 reports
          </div>
        </div>
        <span className="ml-auto flex gap-1">
          {[0, 1, 2].map((d) => (
            <span
              key={d}
              className="h-1.5 w-1.5 rounded-full bg-violetcue animate-pulseDot"
              style={{ animationDelay: `${d * 0.2}s` }}
            />
          ))}
        </span>
      </motion.div>

      {/* Connector */}
      <div className="mx-auto mb-6 h-6 w-px bg-gradient-to-b from-violetcue/40 to-transparent" />

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        {AGENTS.map((a, i) => (
          <AgentCard key={a.id} agent={a} index={i} done={done} />
        ))}
      </div>
    </motion.div>
  );
}
