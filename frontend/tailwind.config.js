/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        bg: 'var(--bg)',
        bg2: 'var(--bg2)',
        pan: 'var(--pan)',
        line: 'var(--line)',
        ink: 'var(--ink)',
        mut: 'var(--mut)',
        cy: 'var(--cy)',
        vi: 'var(--vi)',
        ro: 'var(--ro)',
        rd: 'var(--ro)',
        am: 'var(--am)',
        gr: 'var(--gr)',
      },
      fontFamily: {
        display: ['Unbounded', 'sans-serif'],
        sans: ['Manrope', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      }
    },
  },
  plugins: [],
}
