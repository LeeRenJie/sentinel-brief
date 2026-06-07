import { motion } from "framer-motion";
import { Shield } from "./icons.jsx";
import { MITRE_NAMES } from "../lib/brief.js";
import { useCountUp } from "../lib/useCountUp.js";

const EXPO = [0.16, 1, 0.3, 1];

export default function VerdictBanner({ brief }) {
  const conf = Math.round(useCountUp(brief.confidence * 100, { duration: 900 }));
  const tp = brief.verdict === "true_positive";

  return (
    <motion.section
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.7, ease: EXPO }}
      className="relative overflow-hidden rounded-2xl border border-ember/30 bg-ink-800/80 shadow-glowEmber"
    >
      <div className="pointer-events-none absolute inset-0 bg-gradient-to-br from-ember/[0.08] via-transparent to-transparent" />
      <div className="relative grid gap-px bg-line/40 md:grid-cols-[1fr_auto]">
        <div className="bg-ink-800/90 p-6 md:p-7">
          <div className="flex flex-wrap items-center gap-2 font-mono text-[10px] uppercase tracking-widest">
            <span className="inline-flex items-center gap-1.5 rounded bg-ember/15 px-2 py-1 font-semibold text-ember">
              <Shield width={12} height={12} />
              {brief.verdict.replace("_", " ")}
            </span>
            <span className="rounded bg-ember/10 px-2 py-1 text-ember/90">
              {brief.severity}
            </span>
            <span className="text-mist-faint">Adjudicated · war room</span>
          </div>
          <h2 className="mt-4 max-w-2xl font-display text-xl font-semibold leading-snug tracking-tight text-chalk md:text-2xl">
            {brief.summary}
          </h2>
          <div className="mt-5 flex flex-wrap gap-2">
            {brief.mitre_techniques.map((t, i) => (
              <motion.a
                key={t}
                href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}/`}
                target="_blank"
                rel="noreferrer"
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 + i * 0.08 }}
                className="group inline-flex items-center gap-2 rounded-md border border-line bg-ink-700/60 px-2.5 py-1.5 font-mono text-[11px] text-mist transition-colors hover:border-ice/50 hover:text-ice"
              >
                <span className="font-semibold text-chalk group-hover:text-ice">
                  {t}
                </span>
                <span className="text-mist-faint group-hover:text-ice/70">
                  {MITRE_NAMES[t] ?? "ATT&CK"}
                </span>
              </motion.a>
            ))}
          </div>
        </div>

        <div className="flex flex-row items-stretch divide-x divide-line/40 bg-ink-850/90 md:flex-col md:divide-x-0 md:divide-y">
          <div className="flex flex-1 flex-col justify-center px-7 py-5">
            <div className="text-[10px] uppercase tracking-widest text-mist-faint">
              Confidence
            </div>
            <div className="tabular mt-1 font-display text-4xl font-bold leading-none text-verdant md:text-5xl">
              {conf}
              <span className="text-xl text-verdant/70">%</span>
            </div>
          </div>
          <div className="flex flex-1 flex-col justify-center px-7 py-5">
            <div className="text-[10px] uppercase tracking-widest text-mist-faint">
              Severity
            </div>
            <div className="mt-1 font-display text-2xl font-bold uppercase leading-none text-ember">
              {brief.severity}
            </div>
          </div>
        </div>
      </div>
    </motion.section>
  );
}
