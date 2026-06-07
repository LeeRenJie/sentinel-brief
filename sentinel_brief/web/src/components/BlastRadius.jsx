import { motion } from "framer-motion";
import { Host, Account } from "./icons.jsx";

const ROLE_TONE = {
  origin: "#ff5c49",
  "credential-used": "#f5a623",
  "initial-compromise": "#f5a623",
  "pivoted-to": "#5cc8ff",
};

export default function BlastRadius({ brief }) {
  const entities = brief.blast_radius;
  const max = entities.length;

  return (
    <div className="rounded-xl border border-line bg-ink-850/70 p-5">
      <div className="mb-4 flex items-baseline justify-between">
        <h3 className="font-display text-sm font-semibold uppercase tracking-wider text-chalk">
          Blast radius
        </h3>
        <span className="font-mono text-[10px] text-mist-faint">
          {max} entities · ranked
        </span>
      </div>
      <ul className="space-y-2">
        {entities.map((e, i) => {
          const tone = ROLE_TONE[e.role] ?? "#9aa7c2";
          const origin = e.role === "origin";
          const Icon = e.entity_type === "host" ? Host : Account;
          // Exposure bar inversely proportional to rank.
          const width = ((max - e.exposure_rank + 1) / max) * 100;
          return (
            <motion.li
              key={e.entity}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 + i * 0.05, duration: 0.45 }}
              className={`relative flex items-center gap-3 overflow-hidden rounded-lg border px-3 py-2.5 ${
                origin
                  ? "border-ember/40 bg-ember/[0.06]"
                  : "border-line/60 bg-ink-800/40"
              }`}
            >
              <div
                className="absolute inset-y-0 left-0 -z-0"
                style={{
                  width: `${width}%`,
                  background: `linear-gradient(90deg, ${tone}14, transparent)`,
                }}
              />
              <span className="tabular relative z-10 w-5 text-center font-mono text-xs font-bold text-mist-faint">
                {e.exposure_rank}
              </span>
              <span
                className="relative z-10 flex h-7 w-7 shrink-0 items-center justify-center rounded-md"
                style={{ background: `${tone}1a`, color: tone }}
              >
                <Icon width={14} height={14} />
              </span>
              <div className="relative z-10 min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="truncate font-mono text-sm font-semibold text-chalk">
                    {e.entity}
                  </span>
                  {origin && (
                    <span className="rounded bg-ember/20 px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase tracking-wider text-ember">
                      origin
                    </span>
                  )}
                </div>
                <div className="font-mono text-[10px] text-mist-faint">
                  {e.entity_type} · {e.role}
                </div>
              </div>
            </motion.li>
          );
        })}
      </ul>
    </div>
  );
}
