import { useEffect, useRef, useState } from "react";
import { motion, useInView } from "framer-motion";
import { useCountUp } from "../lib/useCountUp.js";
import { Check, X } from "./icons.jsx";

const EXPO = [0.16, 1, 0.3, 1];

// Stacked before/after bar: each unit is one alert. False positives in ember,
// the true positive in verdant. The whole point lands visually in one glance.
function AlertColumn({ label, total, falsePositives, animate, delay }) {
  const units = Array.from({ length: total });
  return (
    <div className="flex flex-1 flex-col items-center gap-3">
      <div className="flex h-44 w-full max-w-[120px] flex-col-reverse gap-1.5">
        {units.map((_, i) => {
          const isFalse = i < falsePositives;
          return (
            <motion.div
              key={i}
              initial={{ scaleY: 0, opacity: 0 }}
              animate={animate ? { scaleY: 1, opacity: 1 } : {}}
              transition={{ delay: delay + i * 0.12, duration: 0.5, ease: EXPO }}
              style={{ originY: 1 }}
              className={`flex flex-1 items-center justify-center rounded-md border ${
                isFalse
                  ? "border-ember/40 bg-ember/15 text-ember"
                  : "border-verdant/50 bg-verdant/20 text-verdant shadow-glowVerdant"
              }`}
            >
              {isFalse ? <X width={14} height={14} /> : <Check width={14} height={14} />}
            </motion.div>
          );
        })}
      </div>
      <div className="text-center">
        <div className="tabular font-display text-2xl font-bold text-chalk">
          {total}
        </div>
        <div className="font-mono text-[10px] uppercase tracking-widest text-mist-faint">
          {label}
        </div>
      </div>
    </div>
  );
}

export default function Backtest({ brief }) {
  const bt = brief.detection_backtest;
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-120px" });
  const [run, setRun] = useState(false);

  useEffect(() => {
    if (inView) setRun(true);
  }, [inView]);

  const pct = Math.round(useCountUp(bt.alert_reduction_pct * 100, { duration: 1400, run }));

  return (
    <motion.section
      ref={ref}
      initial={{ opacity: 0, y: 24 }}
      animate={inView ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.8, ease: EXPO }}
      className="relative overflow-hidden rounded-3xl border border-verdant/30 bg-ink-850/90 shadow-glowVerdant"
    >
      {/* Atmospheric wash + sweeping scan to make this the emotional peak. */}
      <div className="pointer-events-none absolute inset-0 bg-gradient-to-br from-verdant/[0.1] via-transparent to-ice/[0.05]" />
      <div className="pointer-events-none absolute inset-x-0 top-0 h-px overflow-hidden">
        <div className="h-px w-full animate-scanline bg-gradient-to-r from-transparent via-verdant/70 to-transparent" />
      </div>

      <div className="relative grid gap-px bg-line/30 lg:grid-cols-[1.1fr_1fr]">
        {/* Hero number side */}
        <div className="flex flex-col justify-center bg-ink-850/95 p-7 md:p-9">
          <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.25em] text-verdant">
            <span className="h-1.5 w-1.5 animate-pulseDot rounded-full bg-verdant" />
            Backtest · {bt.window}
          </div>

          <div className="mt-4 flex items-end gap-3">
            <span className="tabular font-display text-[5.5rem] font-bold leading-[0.85] tracking-tightest text-verdant md:text-[7rem]">
              {pct}
              <span className="text-4xl md:text-5xl">%</span>
            </span>
          </div>
          <div className="mt-1 font-display text-xl font-semibold tracking-tight text-chalk md:text-2xl">
            fewer alerts
          </div>
          <p className="mt-3 max-w-md text-sm leading-relaxed text-mist-dim">
            Replayed over {bt.window.toLowerCase()}, the rewritten detection cut the
            queue from <span className="font-mono text-ember">{bt.old_alert_count}</span> to{" "}
            <span className="font-mono text-verdant">{bt.new_alert_count}</span> alert
            {bt.new_alert_count === 1 ? "" : "s"}.
          </p>

          <div className="mt-5 inline-flex w-fit items-center gap-2 rounded-lg border border-verdant/40 bg-verdant/10 px-3 py-2">
            <Check width={15} height={15} className="text-verdant" />
            <span className="font-display text-sm font-semibold text-verdant">
              True positive retained
            </span>
          </div>
        </div>

        {/* Evidence side: before/after bars + eliminated FPs */}
        <div className="flex flex-col gap-6 bg-ink-900/70 p-7 md:p-9">
          <div className="flex items-end gap-6">
            <AlertColumn
              label="before"
              total={bt.old_alert_count}
              falsePositives={bt.false_positives_eliminated}
              animate={run}
              delay={0.3}
            />
            <div className="mb-12 flex flex-col items-center gap-1 text-mist-faint">
              <svg width="28" height="20" viewBox="0 0 28 20" fill="none">
                <path
                  d="M2 10h22M18 4l6 6-6 6"
                  stroke="#34e0a1"
                  strokeWidth="1.8"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
            </div>
            <AlertColumn
              label="after"
              total={bt.new_alert_count}
              falsePositives={0}
              animate={run}
              delay={0.8}
            />
          </div>

          <div className="rounded-xl border border-ember/25 bg-ember/[0.05] p-4">
            <div className="flex items-center gap-2">
              <span className="font-display text-2xl font-bold text-ember tabular">
                {bt.false_positives_eliminated}
              </span>
              <span className="text-sm font-semibold text-chalk">
                false positives eliminated
              </span>
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              {bt.eliminated_accounts.map((acc, i) => (
                <motion.span
                  key={acc}
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={run ? { opacity: 1, scale: 1 } : {}}
                  transition={{ delay: 1.2 + i * 0.12 }}
                  className="inline-flex items-center gap-1.5 rounded-md border border-line bg-ink-800/70 px-2 py-1 font-mono text-[11px] text-mist line-through decoration-ember/60"
                >
                  <X width={11} height={11} className="text-ember no-underline" />
                  {acc}
                </motion.span>
              ))}
            </div>
            <p className="mt-2 font-mono text-[10px] text-mist-faint">
              legitimate service accounts, no longer paged
            </p>
          </div>
        </div>
      </div>
    </motion.section>
  );
}
