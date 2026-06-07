import { motion } from "framer-motion";
import { Spark } from "./icons.jsx";

// Lightweight SPL token highlighter — commands, pipes, fields. No dependency.
const COMMANDS = /\b(index|search|stats|where|join|fields|dc|by|as|process_name|action|logon_type)\b/g;

function highlight(text) {
  const out = [];
  let last = 0;
  text.replace(COMMANDS, (m, _g, off) => {
    if (off > last) out.push(text.slice(last, off));
    out.push(
      <span key={off} className="text-ice">
        {m}
      </span>
    );
    last = off + m.length;
    return m;
  });
  if (last < text.length) out.push(text.slice(last));
  return out;
}

function DiffLine({ line, i }) {
  const sign = line[0];
  const isAdd = sign === "+" && !line.startsWith("+++");
  const isDel = sign === "-" && !line.startsWith("---");
  const isMeta = line.startsWith("+++") || line.startsWith("---");

  const tone = isAdd
    ? "bg-verdant/[0.07] text-verdant"
    : isDel
    ? "bg-ember/[0.07] text-ember"
    : isMeta
    ? "text-mist-faint"
    : "text-mist";

  return (
    <motion.div
      initial={{ opacity: 0, x: isAdd ? 6 : isDel ? -6 : 0 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: 0.15 + i * 0.035, duration: 0.4 }}
      className={`flex items-baseline gap-3 px-4 ${tone}`}
    >
      <span className="w-3 shrink-0 select-none text-center font-bold opacity-70">
        {isMeta ? "" : sign === "+" ? "+" : sign === "-" ? "-" : ""}
      </span>
      <code className="whitespace-pre-wrap break-words py-0.5 text-[12.5px] leading-6">
        {isMeta ? line : highlight(line.replace(/^[+-]\s?/, ""))}
      </code>
    </motion.div>
  );
}

export default function SplDiff({ brief }) {
  const d = brief.proposed_detection;
  const lines = d.spl_diff.split("\n");

  return (
    <motion.section
      initial={{ opacity: 0, y: 16 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-80px" }}
      transition={{ duration: 0.7 }}
      className="overflow-hidden rounded-2xl border border-line bg-ink-850/80 shadow-panel"
    >
      <div className="flex flex-wrap items-center gap-2 border-b border-line/70 px-5 py-4">
        <Spark width={16} height={16} className="text-verdant" />
        <h3 className="font-display text-base font-semibold tracking-tight text-chalk">
          Proposed detection fix
        </h3>
        <span className="ml-auto font-mono text-[10px] text-mist-faint">
          detection engineer · SPL diff
        </span>
      </div>

      <p className="px-5 py-4 text-sm leading-relaxed text-mist-dim">
        {d.problem}
      </p>

      <div className="border-y border-line/70 bg-ink-900/60 py-3 font-mono">
        {lines.map((line, i) => (
          <DiffLine key={i} line={line} i={i} />
        ))}
      </div>

      <div className="flex items-start gap-2.5 px-5 py-4">
        <span className="mt-0.5 rounded bg-verdant/15 px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase tracking-wider text-verdant">
          effect
        </span>
        <p className="text-sm leading-relaxed text-mist">{d.expected_effect}</p>
      </div>
    </motion.section>
  );
}
