/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        // OKLCH-derived, cool-tinted neutrals (no pure #000/#fff).
        ink: {
          900: "#06080d", // base void
          850: "#0a0d15",
          800: "#0e121c",
          700: "#141926",
          600: "#1b2233",
          500: "#28304399",
        },
        line: "#222c40",
        mist: {
          DEFAULT: "#9aa7c2",
          dim: "#6b7895",
          faint: "#48536d",
        },
        chalk: "#e8edf7",
        // Signal accents
        signal: "#f5a623", // amber — the threat / active investigation
        ember: "#ff5c49", // red-orange — critical severity / removed lines
        verdant: "#34e0a1", // decisive green — the win / retained TP / added lines
        ice: "#5cc8ff", // cool cyan — info / indices / agents
        violetcue: "#8b8bf0", // restrained — supervisor node only
      },
      fontFamily: {
        display: ['"Space Grotesk"', "ui-sans-serif", "system-ui", "sans-serif"],
        sans: ['"Inter Tight"', "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "SFMono-Regular", "monospace"],
      },
      letterSpacing: {
        tightest: "-0.04em",
      },
      boxShadow: {
        glowSignal: "0 0 0 1px rgba(245,166,35,0.25), 0 0 40px -8px rgba(245,166,35,0.4)",
        glowVerdant: "0 0 0 1px rgba(52,224,161,0.3), 0 0 60px -10px rgba(52,224,161,0.45)",
        glowEmber: "0 0 0 1px rgba(255,92,73,0.3), 0 0 50px -12px rgba(255,92,73,0.4)",
        panel: "0 1px 0 0 rgba(255,255,255,0.03) inset, 0 24px 60px -30px rgba(0,0,0,0.9)",
      },
      keyframes: {
        scanline: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100%)" },
        },
        pulseDot: {
          "0%,100%": { opacity: "1", transform: "scale(1)" },
          "50%": { opacity: "0.4", transform: "scale(0.7)" },
        },
      },
      animation: {
        scanline: "scanline 6s linear infinite",
        pulseDot: "pulseDot 1.4s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
