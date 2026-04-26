/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        panel: '#101827',
        panelSoft: '#1f2937',
      },
    },
  },
  plugins: [],
}

