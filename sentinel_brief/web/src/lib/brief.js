import bundled from "../sample_brief.json";

// The demo default is the bundled brief: instant, offline, never fails on camera.
export const sampleBrief = bundled;

// Optional live path. The UI never blocks on this — it's only reached when the
// operator explicitly opts into the live pipeline. Falls back to the bundled
// brief on any error so a demo can't break.
export async function fetchBriefLive() {
  try {
    const res = await fetch("/api/run", { method: "POST" });
    if (!res.ok) throw new Error(`run failed: ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn("Live run unavailable, using bundled brief:", err);
    return bundled;
  }
}

// Human-readable formatting helpers shared across the console.
const TZ_LABEL = "+08";

export function fmtTime(iso) {
  const d = new Date(iso);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

export function fmtDate(iso) {
  const d = new Date(iso);
  return d.toLocaleDateString("en-US", {
    month: "short",
    day: "2-digit",
    year: "numeric",
  });
}

export { TZ_LABEL };

// ATT&CK technique names for the chips (static reference, not secret).
export const MITRE_NAMES = {
  "T1021.002": "SMB/Windows Admin Shares",
  "T1569.002": "Service Execution",
  "T1078.002": "Domain Accounts",
};
