import { useRef, useState } from 'react'
import { cn } from '../lib/utils'

// Chart pieces of the Security Summary dashboard — plain SVG/HTML, light surface only (the app has no dark mode).
// Rules followed: thin marks (bars <= 24px, 4px rounded data end), a 2px surface gap between touching marks, 2px lines,
// hairline solid grid, labels in text ink (never in the series colour), a legend wherever there is more than one series,
// and a hover readout on every mark. Palette: the reference categorical order + fixed status colours.

export const INK = { primary: '#0b0b0b', secondary: '#52514e', muted: '#898781', grid: '#e1e0d9', axis: '#c3c2b7', surface: '#fcfcfb' }

// Fixed status colours (severity is a status, not a category)
export const SEV_COLOR = { critical: '#d03b3b', high: '#ec835a', medium: '#fab219', low: '#2a78d6' } as const

// Categorical order — slots 1..8 of the reference palette, never cycled (callers fold the rest into "other")
export const CAT = ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4', '#008300', '#4a3aa7', '#e34948']
export const OTHER = '#898781'

export const fmt = (n: number): string => (n >= 10000 ? `${(n / 1000).toFixed(n >= 100000 ? 0 : 1)}K` : n.toLocaleString())

// ── Widget frame ─────────────────────────────────────────────────────────────

export function Widget({ title, subtitle, right, children, className }: {
  title: string; subtitle?: string; right?: React.ReactNode; children: React.ReactNode; className?: string
}) {
  return (
    <section className={cn('bg-white border border-slate-200 rounded-xl shadow-sm flex flex-col min-w-0', className)}>
      <header className="px-4 pt-3 pb-2 flex items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-slate-800 truncate">{title}</h3>
          {subtitle && <p className="text-[11px] text-slate-400 truncate">{subtitle}</p>}
        </div>
        {right}
      </header>
      <div className="px-4 pb-4 flex-1 min-h-0">{children}</div>
    </section>
  )
}

export function Empty({ text }: { text: string }) {
  return <div className="h-full min-h-[90px] flex items-center justify-center text-sm text-slate-400 text-center px-4">{text}</div>
}

// ── Donut with legend ────────────────────────────────────────────────────────

export interface Seg { key: string; label: string; value: number; color: string }

function arc(cx: number, cy: number, r: number, a0: number, a1: number): string {
  const p = (a: number) => [cx + r * Math.sin(a), cy - r * Math.cos(a)]
  const [x0, y0] = p(a0), [x1, y1] = p(a1)
  return `M${x0.toFixed(2)} ${y0.toFixed(2)} A${r} ${r} 0 ${a1 - a0 > Math.PI ? 1 : 0} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}`
}

export function Donut({ segs, center, centerLabel, size = 150, hole = 0.68 }: {
  segs: Seg[]; center?: string; centerLabel?: string; size?: number; hole?: number
}) {
  const [hover, setHover] = useState<string | null>(null)
  const live = segs.filter(s => s.value > 0)
  const total = live.reduce((a, s) => a + s.value, 0)
  const r = (size / 2) * (1 + hole) / 2, w = (size / 2) * (1 - hole), cx = size / 2
  const gap = live.length > 1 ? 0.035 : 0                          // the surface gap between segments, in radians
  let a = 0
  const h = hover ? live.find(s => s.key === hover) : null
  return (
    <div className="flex items-center gap-4 flex-wrap">
      <div className="relative shrink-0" style={{ width: size, height: size }}>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={live.map(s => `${s.label}: ${s.value}`).join(', ')}>
          <circle cx={cx} cy={cx} r={r} fill="none" stroke="#f1f0ec" strokeWidth={w} />
          {live.length === 1 && <circle cx={cx} cy={cx} r={r} fill="none" stroke={live[0].color} strokeWidth={w} />}
          {live.length > 1 && live.map(s => {
            const sweep = (s.value / total) * Math.PI * 2
            const d = arc(cx, cx, r, a + gap / 2, a + sweep - gap / 2)
            a += sweep
            return (
              <path key={s.key} d={d} fill="none" stroke={s.color} strokeWidth={hover === s.key ? w + 4 : w} opacity={hover && hover !== s.key ? 0.35 : 1}
                style={{ transition: 'opacity .15s' }} onPointerEnter={() => setHover(s.key)} onPointerLeave={() => setHover(null)} />
            )
          })}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none text-center px-4">
          <div className="font-semibold text-slate-900 leading-none" style={{ fontSize: size / 4.6 }}>{h ? fmt(h.value) : center ?? fmt(total)}</div>
          <div className="text-[10px] text-slate-500 mt-1 leading-tight truncate max-w-full">{h ? `${h.label} · ${Math.round((h.value / total) * 100)}%` : centerLabel}</div>
        </div>
      </div>
      <ul className="text-xs space-y-1 min-w-[110px] flex-1">
        {segs.map(s => (
          <li key={s.key} className="flex items-center gap-2" onPointerEnter={() => setHover(s.key)} onPointerLeave={() => setHover(null)}>
            <i className="inline-block w-2.5 h-2.5 rounded-sm shrink-0" style={{ background: s.color }} />
            <span className="text-slate-600 truncate flex-1" title={s.label}>{s.label}</span>
            <span className="tabular-nums text-slate-900 font-medium">{fmt(s.value)}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

// ── Bars ─────────────────────────────────────────────────────────────────────

export interface Bar { key: string; label: string; value: number; color?: string }

/** Horizontal bars: label on the left, value at the tip. */
export function HBars({ bars, color = CAT[0], unit = '' }: { bars: Bar[]; color?: string; unit?: string }) {
  const max = Math.max(1, ...bars.map(b => b.value))
  return (
    <ul className="space-y-2">
      {bars.map(b => (
        <li key={b.key} className="group flex items-center gap-2 text-xs" title={`${b.label}: ${b.value}${unit}`}>
          <span className="w-28 shrink-0 truncate text-slate-600" title={b.label}>{b.label}</span>
          <div className="flex-1 h-3 flex items-center">
            <div className="h-3 transition-all group-hover:brightness-110" style={{ width: `${Math.max(1.5, (b.value / max) * 100)}%`, background: b.color ?? color, borderRadius: '0 4px 4px 0' }} />
          </div>
          <span className="w-12 text-right tabular-nums text-slate-900 font-medium">{fmt(b.value)}{unit}</span>
        </li>
      ))}
    </ul>
  )
}

/** Vertical columns with the value on the cap; labels underneath. */
export function VBars({ bars, color = CAT[0], height = 150 }: { bars: Bar[]; color?: string; height?: number }) {
  const max = Math.max(1, ...bars.map(b => b.value))
  const [hover, setHover] = useState<string | null>(null)
  return (
    <div>
      <div className="flex items-end gap-2" style={{ height }}>
        {bars.map(b => (
          <div key={b.key} className="flex-1 min-w-0 flex flex-col items-center justify-end h-full" onPointerEnter={() => setHover(b.key)} onPointerLeave={() => setHover(null)} title={`${b.label}: ${b.value}`}>
            <span className="text-[11px] tabular-nums text-slate-900 font-medium mb-0.5">{fmt(b.value)}</span>
            <div className="w-full max-w-[24px]" style={{ height: `${Math.max(2, (b.value / max) * (height - 22))}px`, background: b.color ?? color, borderRadius: '4px 4px 0 0', opacity: hover && hover !== b.key ? 0.5 : 1, transition: 'opacity .15s' }} />
          </div>
        ))}
      </div>
      <div className="flex gap-2 border-t border-slate-200 pt-1 mt-0">
        {bars.map(b => <span key={b.key} className="flex-1 min-w-0 text-center text-[10px] text-slate-500 truncate" title={b.label}>{b.label}</span>)}
      </div>
    </div>
  )
}

/** Stacked horizontal bar per row (passed vs failed). */
export function StackRows({ rows, a, b }: { rows: Array<{ key: string; label: string; a: number; b: number }>; a: { label: string; color: string }; b: { label: string; color: string } }) {
  return (
    <div className="space-y-2.5">
      {rows.map(r => {
        const t = Math.max(1, r.a + r.b)
        return (
          <div key={r.key} className="text-xs" title={`${r.label}: ${a.label} ${r.a}, ${b.label} ${r.b}`}>
            <div className="flex justify-between mb-0.5 text-slate-600"><span>{r.label}</span><span className="tabular-nums text-slate-900 font-medium">{r.a} / {r.b}</span></div>
            <div className="flex h-3 gap-[2px] rounded overflow-hidden bg-slate-100">
              {r.a > 0 && <div style={{ width: `${(r.a / t) * 100}%`, background: a.color }} />}
              {r.b > 0 && <div style={{ width: `${(r.b / t) * 100}%`, background: b.color }} />}
            </div>
          </div>
        )
      })}
      <div className="flex gap-4 text-[11px] text-slate-500 pt-1">
        {[a, b].map(x => <span key={x.label} className="flex items-center gap-1"><i className="inline-block w-2.5 h-2.5 rounded-sm" style={{ background: x.color }} />{x.label}</span>)}
      </div>
    </div>
  )
}

// ── Area / line over time ────────────────────────────────────────────────────

export function AreaChart({ points, color = CAT[0], height = 170, label, tickEvery = 4, tickLabel }: {
  points: Array<{ t: string; n: number }>; color?: string; height?: number; label: string; tickEvery?: number; tickLabel: (iso: string) => string
}) {
  const ref = useRef<SVGSVGElement>(null)
  const [i, setI] = useState<number | null>(null)
  const W = 600, padL = 34, padR = 10, padT = 10, padB = 20
  const max = Math.max(1, ...points.map(p => p.n))
  const nice = max <= 4 ? 4 : Math.ceil(max / 4 / Math.pow(10, Math.floor(Math.log10(max / 4)))) * Math.pow(10, Math.floor(Math.log10(max / 4))) * 4
  const x = (k: number) => padL + (points.length > 1 ? (k / (points.length - 1)) * (W - padL - padR) : 0)
  const y = (v: number) => padT + (1 - v / nice) * (height - padT - padB)
  if (points.length < 2) return <Empty text="—" />
  const line = points.map((p, k) => `${k ? 'L' : 'M'}${x(k).toFixed(1)} ${y(p.n).toFixed(1)}`).join(' ')
  const move = (e: React.PointerEvent) => {
    const r = ref.current!.getBoundingClientRect()
    const px = ((e.clientX - r.left) / r.width) * W
    setI(Math.min(points.length - 1, Math.max(0, Math.round(((px - padL) / (W - padL - padR)) * (points.length - 1)))))
  }
  const cur = i != null ? points[i] : null
  return (
    <div className="relative">
      <svg ref={ref} viewBox={`0 0 ${W} ${height}`} className="w-full" style={{ height }} role="img" aria-label={label} onPointerMove={move} onPointerLeave={() => setI(null)}>
        {[0, 1, 2, 3, 4].map(g => (
          <g key={g}>
            <line x1={padL} x2={W - padR} y1={y((nice / 4) * g)} y2={y((nice / 4) * g)} stroke={g === 0 ? INK.axis : INK.grid} strokeWidth="1" />
            <text x={padL - 6} y={y((nice / 4) * g) + 3} textAnchor="end" fontSize="10" fill={INK.muted}>{fmt(Math.round((nice / 4) * g))}</text>
          </g>
        ))}
        {points.map((p, k) => k % tickEvery === 0 && <text key={p.t} x={x(k)} y={height - 4} textAnchor="middle" fontSize="10" fill={INK.muted}>{tickLabel(p.t)}</text>)}
        <path d={`${line} L${x(points.length - 1)} ${y(0)} L${x(0)} ${y(0)} Z`} fill={color} opacity="0.1" />
        <path d={line} fill="none" stroke={color} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
        {cur && i != null && (
          <g>
            <line x1={x(i)} x2={x(i)} y1={padT} y2={y(0)} stroke={INK.axis} strokeWidth="1" />
            <circle cx={x(i)} cy={y(cur.n)} r="4.5" fill={color} stroke={INK.surface} strokeWidth="2" />
          </g>
        )}
        {!cur && <circle cx={x(points.length - 1)} cy={y(points[points.length - 1].n)} r="4.5" fill={color} stroke={INK.surface} strokeWidth="2" />}
      </svg>
      {cur && i != null && (
        <div className="absolute pointer-events-none bg-white border border-slate-200 rounded-md shadow px-2 py-1 text-xs" style={{ left: `${(x(i) / W) * 100}%`, top: 0, transform: `translate(${i > points.length / 2 ? '-105%' : '5%'}, 0)` }}>
          <div className="font-semibold text-slate-900 tabular-nums"><i className="inline-block w-3 h-0.5 align-middle mr-1.5" style={{ background: color }} />{cur.n.toLocaleString()}</div>
          <div className="text-slate-500">{tickLabel(cur.t)}</div>
        </div>
      )}
    </div>
  )
}

// ── Number tiles / hero / gauge ──────────────────────────────────────────────

export function NumberTiles({ tiles }: { tiles: Array<{ label: string; value: number | string; tone?: 'plain' | 'critical' | 'high' }> }) {
  return (
    <div className="grid gap-2 h-full" style={{ gridTemplateColumns: `repeat(${tiles.length}, minmax(0, 1fr))` }}>
      {tiles.map(t => (
        <div key={t.label} className="rounded-lg px-3 py-2 flex flex-col justify-center min-h-[96px]"
          style={t.tone === 'critical' ? { background: '#d03b3b', color: '#fff' } : t.tone === 'high' ? { background: '#ec835a', color: '#0b0b0b' } : { background: '#f4f3ef' }}>
          <div className="text-4xl font-semibold leading-none">{typeof t.value === 'number' ? fmt(t.value) : t.value}</div>
          <div className="text-xs mt-1.5 opacity-90">{t.label}</div>
        </div>
      ))}
    </div>
  )
}

/** Score 0-100 on a green -> amber -> red scale with a marker. */
export function RiskGauge({ score, caption, scale }: { score: number | null; caption: string; scale: [string, string] }) {
  if (score == null) return <Empty text="—" />
  const p = Math.min(100, Math.max(0, score))
  return (
    <div className="pt-3">
      <div className="text-center text-4xl font-semibold text-slate-900 leading-none">{score}</div>
      <div className="relative mt-5 mb-1">
        <div className="h-3 rounded-full" style={{ background: 'linear-gradient(90deg,#0ca30c 0%,#fab219 50%,#d03b3b 100%)' }} />
        <div className="absolute -top-3 -translate-x-1/2" style={{ left: `${p}%` }}>
          <svg width="14" height="10" viewBox="0 0 14 10"><path d="M0 0H14L7 10Z" fill={INK.primary} /></svg>
        </div>
      </div>
      <div className="flex justify-between text-[10px] text-slate-400"><span>{scale[0]}</span><span>{scale[1]}</span></div>
      <p className="text-[10px] text-slate-400 mt-2 leading-snug">{caption}</p>
    </div>
  )
}
