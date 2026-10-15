/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
      },
      colors: {
        ink: "#172033",
        muted: "#707b8e",
        brand: "#5366e8",
        canvas: "#f6f7fb",
      },
      boxShadow: {
        card: "0 10px 35px rgba(25, 37, 66, .055)",
      },
    },
  },
  plugins: [],
}
