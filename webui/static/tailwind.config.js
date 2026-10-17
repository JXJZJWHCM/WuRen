module.exports = {
  content: [
    './webui/static/index.html'
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Plus Jakarta Sans', 'Noto Sans SC', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace']
      },
      colors: {
        brand: {
          50: '#eff6ff',
          100: '#dbeafe',
          200: '#bfdbfe',
          300: '#93c5fd',
          400: '#60a5fa',
          500: '#3b82f6',
          600: '#2563eb',
          700: '#1d4ed8',
          800: '#1e40af',
          900: '#1e3a8a'
        },
        surface: '#ffffff',
        background: '#ffffff',
        textMain: '#111827',
        textSub: '#4b5563',
        border: '#e5e7eb',
        borderHover: '#d1d5db',
        success: '#10b981',
        warning: '#f59e0b',
        danger: '#ef4444',
        sidebar: {
          900: '#1e3a8a',
          800: '#1e40af',
          700: '#1d4ed8',
          600: '#2563eb',
          200: '#bfdbfe',
          100: '#dbeafe'
        }
      },
      boxShadow: {
        soft: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
        card: '0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06)',
        glow: '0 0 16px rgba(37, 99, 235, 0.4)'
      }
    }
  },
  plugins: []
};
