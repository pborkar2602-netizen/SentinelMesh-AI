/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        bg: '#0c0f14',
        bg2: '#12161d',
        pan: 'rgba(21, 26, 34, 0.85)',
        line: '#262d39',
        ink: '#e6eaf0',
        mut: '#8a94a3',
        cy: '#4fb3c7',
        vi: '#7f8fd6',
        rd: '#e5484d',
        am: '#d9a441',
        gr: '#3fb68b',
      },
      fontFamily: {
        sans: ['Sora', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'Menlo', 'monospace'],
      }
    },
  },
  plugins: [],
}
