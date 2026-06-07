import { motion } from "framer-motion";
import VerdictBanner from "./VerdictBanner.jsx";
import Timeline from "./Timeline.jsx";
import BlastRadius from "./BlastRadius.jsx";
import ProposedActions from "./ProposedActions.jsx";
import SplDiff from "./SplDiff.jsx";
import Backtest from "./Backtest.jsx";

const stagger = {
  hidden: {},
  show: { transition: { staggerChildren: 0.12, delayChildren: 0.1 } },
};
const item = {
  hidden: { opacity: 0, y: 14 },
  show: { opacity: 1, y: 0, transition: { duration: 0.6, ease: [0.16, 1, 0.3, 1] } },
};

function SectionLabel({ n, children }) {
  return (
    <div className="mb-3 flex items-center gap-3">
      <span className="font-mono text-[10px] text-mist-faint">{n}</span>
      <span className="h-px flex-1 bg-line/60" />
      <span className="font-display text-[11px] font-semibold uppercase tracking-[0.2em] text-mist-dim">
        {children}
      </span>
    </div>
  );
}

export default function IncidentBrief({ brief }) {
  return (
    <motion.div
      variants={stagger}
      initial="hidden"
      animate="show"
      exit={{ opacity: 0, transition: { duration: 0.25 } }}
      className="mx-auto max-w-5xl space-y-10 px-5 pb-24 pt-8 md:px-6"
    >
      <motion.div variants={item}>
        <VerdictBanner brief={brief} />
      </motion.div>

      <motion.div variants={item} className="grid gap-5 lg:grid-cols-2">
        <div>
          <SectionLabel n="01">Cross-index timeline</SectionLabel>
          <Timeline brief={brief} />
        </div>
        <div>
          <SectionLabel n="02">Impact</SectionLabel>
          <BlastRadius brief={brief} />
        </div>
      </motion.div>

      <motion.div variants={item}>
        <SectionLabel n="03">Containment</SectionLabel>
        <ProposedActions brief={brief} />
      </motion.div>

      <motion.div variants={item}>
        <SectionLabel n="04">Detection fix</SectionLabel>
        <SplDiff brief={brief} />
      </motion.div>

      <motion.div variants={item}>
        <SectionLabel n="05">Proof · backtest</SectionLabel>
        <Backtest brief={brief} />
      </motion.div>
    </motion.div>
  );
}
