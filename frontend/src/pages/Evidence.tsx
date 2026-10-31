import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { FileCheck2, FileDown, Table2 } from 'lucide-react'
import { evidenceApi, type EvidenceCheck, type EvidenceReq } from '../lib/api'
import { cn } from '../lib/utils'

const PILL: Record<string, string> = {
  ok: 'bg-green-50 text-green-700 border-green-300', warn: 'bg-amber-50 text-amber-800 border-amber-300', gap: 'bg-red-50 text-red-700 border-red-300',
  manual: 'bg-slate-50 text-slate-600 border-slate-300', external: 'bg-sky-50 text-sky-700 border-sky-300', na: 'bg-slate-50 text-slate-400 border-slate-200',
}
const DOT: Record<string, string> = { ok: 'bg-green-500', warn: 'bg-amber-500', gap: 'bg-red-500', manual: 'bg-slate-400', external: 'bg-sky-500', na: 'bg-slate-300' }

function download(name: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }))
  const a = document.createElement('a'); a.href = url; a.download = name; a.click(); URL.revokeObjectURL(url)
}

// The requirements of NIS2 art. 21(2) and ISO 27001:2022 set against what the application measures: a map of evidence for an audit, with a status per check and an export.
export function Evidence() {
  const { t, i18n } = useTranslation()
  const q = useQuery({ queryKey: ['evidence'], queryFn: evidenceApi.get, refetchInterval: 120000 })
  const d = q.data
  const label = (c: EvidenceCheck) => {
    const none = `evidence.check.${c.key}_none`
    const params = Object.fromEntries(Object.entries(c.params).map(([k, v]) => [k, v ?? '—']))
    return (c.status === 'na' && i18n.exists(none)) ? t(none, params) : t(`evidence.check.${c.key}`, params)
  }
  const title = (r: EvidenceReq) => t(`evidence.req.${r.id}`)
  const when = d ? new Date(d.at).toLocaleString() : ''
  const exportMd = () => {
    if (!d) return
    const bars = t('evidence.bars', { ok: d.bars.ok, warn: d.bars.warn, backup: d.bars.backup_days, key: d.bars.key_rotation_days, log: d.bars.log_retention_days })
    const lines = [`# ${t('evidence.title')}`, '', `${t('evidence.generated')}: ${when}`, '', `> ${t('evidence.subtitle')}`, '', `> ${bars}`, '']
    for (const r of d.requirements) {
      lines.push(`## ${title(r)} — ${t(`evidence.status.${r.status}`)}`, '', `${t('evidence.refs')} ${r.nis2} · ${t('evidence.iso')}: ${r.iso.join(', ')} · ${t('evidence.automated', { pct: r.automated })}`, '')
      lines.push('| | |', '|---|---|')
      for (const c of r.checks) lines.push(`| ${t(`evidence.status.${c.status}`)} | ${label(c).replace(/\|/g, '/')}${c.error ? ` (${t('evidence.error')}: ${c.error})` : ''} |`)
      lines.push('')
    }
    download(`evidence-${d.at.slice(0, 10)}.md`, lines.join('\n'), 'text/markdown;charset=utf-8')
  }
  const exportCsv = () => {
    if (!d) return
    const esc = (s: string) => `"${String(s).replace(/"/g, '""')}"`
    const rows = [['requirement', 'nis2', 'iso', 'requirement_status', 'check', 'check_status', 'link'].map(esc).join(',')]
    for (const r of d.requirements) for (const c of r.checks) rows.push([title(r), r.nis2, r.iso.join(' '), r.status, label(c), c.status, c.link ?? ''].map(esc).join(','))
    download(`evidence-${d.at.slice(0, 10)}.csv`, '﻿' + rows.join('\n'), 'text/csv;charset=utf-8')
  }
  return (
    <div className="p-6 space-y-4 max-w-[1100px]">
      <div className="flex flex-wrap items-start gap-3">
        <div className="min-w-0 flex-1">
          <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><FileCheck2 size={20} className="text-indigo-600" /> {t('evidence.title')}</h1>
          <p className="text-sm text-slate-500 mt-0.5">{t('evidence.subtitle')}</p>
        </div>
        <div className="flex gap-2 text-xs">
          <button onClick={exportMd} disabled={!d} className="inline-flex items-center gap-1.5 border border-slate-300 rounded-lg px-2.5 py-1.5 text-slate-700 hover:bg-slate-50 disabled:opacity-40"><FileDown size={13} /> {t('evidence.exportMd')}</button>
          <button onClick={exportCsv} disabled={!d} className="inline-flex items-center gap-1.5 border border-slate-300 rounded-lg px-2.5 py-1.5 text-slate-700 hover:bg-slate-50 disabled:opacity-40"><Table2 size={13} /> {t('evidence.exportCsv')}</button>
        </div>
      </div>
      {q.isLoading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : d && (
        <>
          <div className="flex flex-wrap gap-2">
            {(['ok', 'warn', 'gap', 'manual'] as const).map(s => (
              <div key={s} className="bg-white border border-slate-200 rounded-xl px-4 py-2 min-w-[8rem]"><div className="text-xs text-slate-500">{t(`evidence.sum.${s}`)}</div>
                <div className={cn('text-2xl font-bold tabular-nums', d.summary[s] ? (s === 'ok' ? 'text-green-600' : s === 'warn' ? 'text-amber-600' : s === 'gap' ? 'text-red-600' : 'text-slate-600') : 'text-slate-300')}>{d.summary[s]}</div></div>
            ))}
            <div className="text-xs text-slate-400 self-end pb-2">{t('evidence.generated')}: {when}</div>
          </div>
          <p className="text-xs text-slate-500">{t('evidence.bars', { ok: d.bars.ok, warn: d.bars.warn, backup: d.bars.backup_days, key: d.bars.key_rotation_days, log: d.bars.log_retention_days })}</p>
          <div className="space-y-3">
            {d.requirements.map(r => (
              <section key={r.id} className="bg-white border border-slate-200 rounded-xl overflow-hidden">
                <div className="px-4 py-3 flex flex-wrap items-center gap-3 border-b border-slate-100">
                  <h2 className="text-sm font-semibold text-slate-900 flex-1 min-w-[12rem]">{title(r)}</h2>
                  <span className="text-[11px] text-slate-500">{t('evidence.refs')} {r.nis2}</span>
                  <span className="text-[11px] text-slate-400" title={t('evidence.iso') as string}>{r.iso.join(' · ')}</span>
                  <span className="text-[11px] text-slate-400">{t('evidence.automated', { pct: r.automated })}</span>
                  <span className={cn('text-xs font-medium border rounded-full px-2.5 py-0.5', PILL[r.status])}>{t(`evidence.status.${r.status}`)}</span>
                </div>
                <ul className="divide-y divide-slate-100 text-sm">
                  {r.checks.map(c => (
                    <li key={c.key} className="px-4 py-2 flex items-start gap-3">
                      <span className={cn('mt-1.5 h-2 w-2 rounded-full shrink-0', DOT[c.status])} title={t(`evidence.status.${c.status}`) as string} />
                      <span className="flex-1 min-w-0 text-slate-800">{label(c)}{c.error && <span className="block text-xs text-red-600">{t('evidence.error')}: {c.error}</span>}</span>
                      <span className={cn('text-[11px] border rounded-full px-2 py-0.5 shrink-0', PILL[c.status])}>{t(`evidence.status.${c.status}`)}</span>
                      {c.link && <Link to={c.link} className="text-xs text-indigo-600 hover:underline shrink-0">{t('evidence.show')}</Link>}
                    </li>
                  ))}
                </ul>
              </section>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
