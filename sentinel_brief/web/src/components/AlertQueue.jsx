import { motion } from "framer-motion";
import { Pulse, Shield, Arrow } from "./icons.jsx";

const EXPO = [0.16, 1, 0.3, 1];

// Opening state: a fired Splunk detection sitting in the triage queue.
export default function AlertQueue({ brief, onInvestigate }) {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0, transition: { duration: 0.25 } }}
      className="mx-auto flex min-h-[78vh] max-w-3xl flex-col justify-center px-6"
    >
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.7, ease: EXPO }}
        className="mb-7 flex items-center gap-3 text-xs uppercase tracking-[0.25em] text-mist-dim"
      >
        <span className="h-px w-8 bg-line" />
        Detection Queue
        <span className="font-mono text-[10px] text-mist-faint">/ index=notable</span>
      </motion.div>

      <motion.article
        initial={{ opacity: 0, y: 18 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8, ease: EXPO, delay: 0.08 }}
        className="relative overflow-hidden rounded-xl border border-line bg-ink-800/80 shadow-panel"
      >
        {/* Live scan line for "actively firing" feel */}
        <div className="pointer-events-none absolute inset-x-0 top-0 h-px overflow-hidden">
          <div className="h-px w-full animate-scanline bg-gradient-to-r from-transparent via-signal/70 to-transparent" />
        </div>

        <div className="flex items-start gap-4 border-b border-line/70 px-6 py-5">
          <span className="relative mt-0.5 flex h-2.5 w-2.5 shrink-0">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-ember/70" />
            <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-ember" />
          </span>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2 font-mono text-[10px] uppercase tracking-widest">
              <span className="rounded bg-ember/15 px-1.5 py-0.5 text-ember">
                Critical
              </span>
              <span className="text-mist-dim">Splunk Enterprise Security</span>
              <span className="text-mist-faint">· fired 2 min ago</span>
            </div>
            <h1 className="mt-2 font-display text-2xl font-semibold leading-tight tracking-tightest text-chalk md:text-3xl">
              {brief.detection_name}
            </h1>
          </div>
        </div>

        <div className="grid grid-cols-2 divide-x divide-line/70 border-b border-line/70 sm:grid-cols-4">
          {[
            ["Source indices", "auth · edr"],
            ["Trigger", "dc(dest) > 3"],
            ["Entity", "svc_backup"],
            ["Origin", "WKS-014"],
          ].map(([k, v]) => (
            <div key={k} className="px-5 py-4">
              <div className="text-[10px] uppercase tracking-widest text-mist-faint">
                {k}
              </div>
              <div className="mt-1 font-mono text-sm text-mist">{v}</div>
            </div>
          ))}
        </div>

        <div className="flex flex-col gap-4 px-6 py-5 sm:flex-row sm:items-center sm:justify-between">
          <p className="max-w-md text-sm leading-relaxed text-mist-dim">
            A single account fanned out across admin shares. Raw, unadjudicated.
            Dispatch the war room to correlate, adjudicate, and propose a fix.
          </p>
          <motion.button
            onClick={onInvestigate}
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            className="group inline-flex shrink-0 items-center gap-2.5 rounded-lg bg-signal px-5 py-3 font-display text-sm font-semibold text-ink-900 shadow-glowSignal transition-shadow hover:shadow-[0_0_0_1px_rgba(245,166,35,0.4),0_0_60px_-6px_rgba(245,166,35,0.65)]"
          >
            <Shield width={17} height={17} />
            Run war room
            <Arrow
              width={16}
              height={16}
              className="transition-transform group-hover:translate-x-0.5"
            />
          </motion.button>
        </div>
      </motion.article>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.6, delay: 0.5 }}
        className="mt-5 flex items-center gap-2 px-1 font-mono text-[11px] text-mist-faint"
      >
        <Pulse width={14} height={14} className="text-mist-dim" />
        5 agents standing by · supervisor + correlator · adjudicator · responder ·
        detection engineer
      </motion.div>
    </motion.div>
  );
}
