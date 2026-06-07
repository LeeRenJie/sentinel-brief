import { useEffect, useRef, useState } from "react";

// Count-up driven by rAF with an ease-out-expo curve. Respects reduced motion.
export function useCountUp(target, { duration = 1100, start = 0, run = true } = {}) {
  const [value, setValue] = useState(start);
  const frame = useRef(0);

  useEffect(() => {
    if (!run) return;
    const prefersReduced =
      typeof window !== "undefined" &&
      window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    if (prefersReduced) {
      setValue(target);
      return;
    }
    const t0 = performance.now();
    const tick = (now) => {
      const p = Math.min(1, (now - t0) / duration);
      const eased = 1 - Math.pow(2, -10 * p); // ease-out-expo
      setValue(start + (target - start) * (p >= 1 ? 1 : eased));
      if (p < 1) frame.current = requestAnimationFrame(tick);
      else setValue(target);
    };
    frame.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame.current);
  }, [target, duration, start, run]);

  return value;
}
