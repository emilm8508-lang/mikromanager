import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ArrowLeft, Printer } from 'lucide-react'
import { labelsApi } from '../lib/api'
import { cn } from '../lib/utils'

// Printable asset labels with a QR code of each asset's phone page (services/asset_labels.py, docs/plan-itam.md stage F).
export function Labels() {
  const { t } = useTranslation()
  const [params] = useSearchParams()
  const ids = params.get('ids') ?? ''
  const [size, setSize] = useState<'a4' | 'single'>((params.get('size') as 'a4' | 'single') ?? 'a4')
  const q = useQuery({ queryKey: ['labels', ids], queryFn: () => labelsApi.labels(ids, window.location.origin), enabled: !!ids })
  const rows = q.data?.labels ?? []
  return (
    <div className="min-h-screen bg-slate-100 print:bg-white">
      <style>{`@media print { @page { size: ${size === 'a4' ? 'A4' : '62mm 40mm'}; margin: ${size === 'a4' ? '8mm' : '0'}; } .no-print { display: none !important } }`}</style>
      <div className="no-print flex flex-wrap items-center gap-3 p-4 bg-white border-b border-slate-200">
        <Link to="/inventory/list" className="inline-flex items-center gap-1 text-sm text-indigo-600"><ArrowLeft size={14} /> {t('lbl.back')}</Link>
        <span className="text-sm text-slate-600">{t('lbl.count', { n: rows.length })}</span>
        <select value={size} onChange={e => setSize(e.target.value as 'a4' | 'single')} className="border border-slate-300 rounded-lg px-2 py-1 text-sm bg-white">
          <option value="a4">{t('lbl.a4')}</option><option value="single">{t('lbl.single')}</option>
        </select>
        <button onClick={() => window.print()} disabled={!rows.length} className="flex items-center gap-1.5 px-3 py-1.5 text-sm rounded-lg bg-indigo-600 text-white disabled:opacity-50"><Printer size={14} /> {t('lbl.print')}</button>
        <span className="text-xs text-slate-500">{t('lbl.hint')}</span>
      </div>
      {q.isError && <p className="p-4 text-sm text-red-700">{String((q.error as Error).message)}</p>}
      <div className={cn(size === 'a4' ? 'grid grid-cols-3 gap-[4mm] p-[4mm] print:p-0' : 'flex flex-col items-start gap-4 p-4 print:p-0 print:gap-0')}>
        {rows.map(l => (
          <div key={l.id} className={cn('bg-white border border-slate-300 rounded-md flex gap-[2mm] items-center overflow-hidden break-inside-avoid',
            size === 'a4' ? 'h-[36mm] p-[2mm]' : 'w-[62mm] h-[40mm] p-[2mm] print:border-0 print:rounded-none print:break-after-page')}>
            <img src={l.qr} alt="" className="h-[30mm] w-[30mm] shrink-0" />
            <div className="min-w-0 text-[8pt] leading-tight">
              <div className="font-bold text-[9pt] break-words">{l.name}</div>
              {l.asset_tag && <div className="font-mono text-[10pt] font-bold mt-[1mm]">{l.asset_tag}</div>}
              {(l.manufacturer || l.model) && <div className="text-slate-700">{[l.manufacturer, l.model].filter(Boolean).join(' ')}</div>}
              {l.serial && <div className="text-slate-600">S/N {l.serial}</div>}
              {l.location && <div className="text-slate-500">{l.location}</div>}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
