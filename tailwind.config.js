/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        surface: {
          DEFAULT: '#0f1117',
          raised: '#161822',
          overlay: '#1c1f2e',
        },
        ash: {
          50: '#f6f6f8',
          100: '#e4e4e9',
          200: '#c9c9d2',
          300: '#a3a3b1',
          400: '#7d7d8f',
          500: '#626275',
          600: '#4e4e5e',
          700: '#40404d',
          800: '#2a2a33',
          900: '#1a1a21',
        },
        accent: {
          teal: '#2dd4bf',
          blue: '#60a5fa',
          purple: '#a78bfa',
          rose: '#f43f5e',
          amber: '#fbbf24',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
}
