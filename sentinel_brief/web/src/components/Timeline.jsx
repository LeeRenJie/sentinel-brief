import { motion } from "framer-motion";
import { fmtTime, fmtDate } from "../lib/brief.js";

const INDEX_STYLE = {
  edr: { color: "#5cc8ff", label: "edr" },
  auth: { color: "#f5a623", label: "auth" },
};

function Row({ ev, i, last }) {
  const idx = INDEX_STYLE[ev.source_index] ?? { color: "#9aa7c2", label: ev.source_index };
  return (
    <motion.li
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: 0.1 + i * 0.06, duration: 0.5 }}
      className="relative grid grid-cols-[auto_1fr] gap-x-4 pb-5 last:pb-0"
    >
      <div className="relative flex flex-col items-center">
        <span
          className="z-10 mt-1 h-3 w-3 rounded-full ring-4 ring-ink-850"
          style={{ background: idx.color }}
        />
        {!last && <span className="mt-1 w-px flex-1 bg-line" />}
      </div>
      <div className="-mt-0.5">
        <div className="flex items-center gap-2">
          <span className="tabular font-mono text-xs font-semibold text-chalk">
            {fmtTime(ev.timestamp)}
          </span>
          <span
            className="rounded px-1.5 py-0.5 font-mono text-[9px] font-semibold uppercase tracking-wider"
            style={{ background: `${idx.color}1a`, color: idx.color }}
          >
            {idx.label}
          </span>
          <span className="font-mono text-[10px] text-mist-faint">{ev.host}</span>
        </div>
        <div className="mt-1 text-sm leading-snug text-mist">{ev.description}</div>
        <div className="mt-0.5 font-mono text-[10px] text-mist-faint">
          user={ev.user}
        </div>
      </div>
    </motion.li>
  );
}

export default function Timeline({ brief }) {
  const events = brief.timeline;
  return (
    <div className="rounded-xl border border-line bg-ink-850/70 p-5">
      <div className="mb-4 flex items-baseline justify-between">
        <h3 className="font-display text-sm font-semibold uppercase tracking-wider text-chalk">
          Kill chain
        </h3>
        <span className="font-mono text-[10px] text-mist-faint">
          {fmtDate(events[0].timestamp)} · multi-index
        </span>
      </div>
      <ol className="relative">
        {events.map((ev, i) => (
          <Row key={i} ev={ev} i={i} last={i === events.length - 1} />
        ))}
      </ol>
    </div>
  );
}
