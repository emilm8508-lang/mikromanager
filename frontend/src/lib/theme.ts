// Light / dark / follow the system. The choice is kept in localStorage; the class "dark" on <html> switches the palette (src/theme.css).
export type ThemeMode = 'light' | 'dark' | 'auto'
const KEY = 'mikromanager_theme'

export function loadTheme(): ThemeMode {
  try { const v = localStorage.getItem(KEY); return v === 'dark' || v === 'auto' ? v : 'light' } catch { return 'light' }
}

export function isDark(mode: ThemeMode = loadTheme()): boolean {
  return mode === 'dark' || (mode === 'auto' && typeof window !== 'undefined' && window.matchMedia?.('(prefers-color-scheme: dark)').matches)
}

export function applyTheme(mode: ThemeMode = loadTheme()): void {
  document.documentElement.classList.toggle('dark', isDark(mode))
}

export function saveTheme(mode: ThemeMode): void {
  try { localStorage.setItem(KEY, mode) } catch { /* storage unavailable */ }
  applyTheme(mode)
}

// "auto" follows the system while the page is open
if (typeof window !== 'undefined' && window.matchMedia) {
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener?.('change', () => { if (loadTheme() === 'auto') applyTheme('auto') })
}
