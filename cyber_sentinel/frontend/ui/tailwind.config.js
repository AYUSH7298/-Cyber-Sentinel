/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'surface': '#101415',
        'surface-dim': '#101415',
        'surface-bright': '#363a3b',
        'primary': '#8aebff',
        'primary-container': '#22d3ee',
        'error': '#ffb4ab',
        'error-container': '#93000a',
      },
      fontFamily: {
        outfit: ['Outfit', 'sans-serif'],
        inter: ['Inter', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      }
    },
  },
  plugins: [],
}
