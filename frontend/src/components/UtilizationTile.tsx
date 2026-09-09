// Percentage-based sibling to DellHealthTile's ComponentTile — used for
// Windows/Linux hosts in Central (CPU/RAM/disk load), where the underlying
// value is a numeric utilization percentage rather than a discrete health
// enum (OK/Warning/Critical) like Dell/iDRAC reports. Same tile shape/
// spacing as ComponentTile so both read as one visual family — this is
// the "graficznie zajętość dysków i pamięci oraz procesory" view for
// Windows/Linux hosts, mirroring what Central already shows for iDRAC.

export function utilizationColor(pct: number | null | undefined): string {
  if (pct === null || pct === undefined) return 'bg-slate-100 text-slate-400'
  if (pct >= 90) return 'bg-red-500 text-white'
  if (pct >= 75) return 'bg-amber-500 text-white'
  return 'bg-green-500 text-white'
}

// Same three-band look as utilizationColor, but for a raw °C value instead
// of a 0-100 percentage — a 0-100 scale would be meaningless for a router's
// board temperature (e.g. a healthy 40°C would wrongly render as "40%
// used", nearly full amber territory). Thresholds mirror
// resource_monitor.py's TEMP_ALERT_C default (70°C) and its 5-degree
// hysteresis band, so the tile's color and the alert that fires roughly agree.
export function temperatureColor(celsius: number | null | undefined): string {
  if (celsius === null || celsius === undefined) return 'bg-slate-100 text-slate-400'
  if (celsius >= 70) return 'bg-red-500 text-white'
  if (celsius >= 60) return 'bg-amber-500 text-white'
  return 'bg-green-500 text-white'
}

export function UtilizationTile({ label, pct, sublabel, Icon, colorFn, formatValue }: {
  label: string
  pct: number | null | undefined
  sublabel?: string
  Icon: React.ComponentType<any>
  colorFn?: (v: number | null | undefined) => string
  formatValue?: (v: number) => string
}) {
  const color = (colorFn ?? utilizationColor)(pct)
  const value = pct === null || pct === undefined ? '—' : (formatValue ?? ((v: number) => `${Math.round(v)}%`))(pct)
  return (
    <div className={`flex flex-col items-center justify-center gap-1 rounded-lg py-3 px-2 min-w-[84px] flex-1 ${color}`}>
      <Icon size={20} />
      <span className="text-[10px] font-medium text-center leading-tight opacity-90">{label}</span>
      <span className="text-xs font-bold">{value}</span>
      {sublabel && <span className="text-[9px] opacity-80 leading-tight text-center">{sublabel}</span>}
    </div>
  )
}

function formatBytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return ''
  const gb = n / (1024 ** 3)
  if (gb >= 1) return `${gb.toFixed(1)} GB`
  const mb = n / (1024 ** 2)
  return `${mb.toFixed(0)} MB`
}

// One row of tiles for a Windows/Linux host: CPU, RAM, then one tile per
// disk/mount. Used inside both LinuxCentralPanel and WindowsCentralPanel.
export function HostUtilizationRow({ cpuPct, memPct, memTotalBytes, disks, cpuLabel, memLabel, diskLabel,
  CpuIcon, MemIcon, DiskIcon }: {
  cpuPct: number | null | undefined
  memPct: number | null | undefined
  memTotalBytes?: number | null
  disks: Array<{ label: string; pct: number | null; totalBytes?: number | null }>
  cpuLabel: string
  memLabel: string
  diskLabel: string
  CpuIcon: React.ComponentType<any>
  MemIcon: React.ComponentType<any>
  DiskIcon: React.ComponentType<any>
}) {
  return (
    <div className="flex flex-wrap gap-2 bg-slate-50 border border-slate-200 rounded-xl p-2">
      <UtilizationTile label={cpuLabel} pct={cpuPct} Icon={CpuIcon} />
      <UtilizationTile label={memLabel} pct={memPct} sublabel={memTotalBytes ? formatBytes(memTotalBytes) : undefined} Icon={MemIcon} />
      {disks.length === 0 ? (
        <UtilizationTile label={diskLabel} pct={null} Icon={DiskIcon} />
      ) : (
        disks.map((d, i) => (
          <UtilizationTile key={i} label={d.label} pct={d.pct} sublabel={d.totalBytes ? formatBytes(d.totalBytes) : undefined} Icon={DiskIcon} />
        ))
      )}
    </div>
  )
}
