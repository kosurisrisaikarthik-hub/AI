/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      fontFamily: {
        display: ['"Barlow Condensed"', "sans-serif"],
        body: ['"JetBrains Mono"', '"DM Sans"', "monospace"],
      },
      colors: {
        ink: "#0A0A0A",
        surface: "#121212",
        stroke: "#222222",
        kinetic: "#FF3B30",
        signal: "#007AFF",
        ok: "#34C759",
        warn: "#FF9500",
        mute: "#A0A0A0",
      },
      boxShadow: {
        terminal: "0 0 8px rgba(255,59,48,0.3)",
      },
    },
  },
  plugins: [],
};
