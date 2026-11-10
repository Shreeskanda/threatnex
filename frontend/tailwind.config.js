/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        navy: { 50: '#f0f4ff', 100: '#e0eaff', 600: '#1e3a8a', 700: '#1e3270', 800: '#152558', 900: '#0f1a3d' },
        sentinel: { red: '#dc2626', orange: '#ea580c', amber: '#d97706', green: '#16a34a', blue: '#2563eb' }
      },
      fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'] }
    }
  },
  plugins: [],
}
