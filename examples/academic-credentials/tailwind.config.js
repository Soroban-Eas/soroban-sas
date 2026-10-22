/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        stellar: {
          50: '#f0f5ff',
          100: '#e0ecff',
          200: '#b9d5ff',
          300: '#7cb5ff',
          400: '#388eff',
          500: '#0062ff',
          600: '#004fd1',
          700: '#003ea6',
          800: '#00358a',
          900: '#002f73',
          950: '#001c47',
        },
        ivy: {
          50: '#f6f7f6',
          100: '#e3e8e4',
          500: '#234e32',
          600: '#1b3f28',
          700: '#14311f',
          800: '#0e2316',
          900: '#09170e',
        }
      },
      fontFamily: {
        serif: ['Georgia', 'Cambria', '"Times New Roman"', 'serif'],
      }
    },
  },
  plugins: [],
};
