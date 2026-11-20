import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Boxes } from 'lucide-react'
import { cmdbApi } from '../lib/api'
import { CiClassSelect } from '../components/Cmdb'
import { cn } from '../lib/utils'

// The configuration items with their classes and relation counts (services/cmdb.py, docs/plan-itam.md stage B).
export function Cmdb() {
  const { t } = useTranslation()
  const q = useQuery({ queryKey: ['cmdb'], queryFn: cmdbApi.overview })
  const [cls, setCls] = useState('')
  const [search, setSearch] = useState('')
  const d = q.data
  const items = (d?.items ?? []).filter(x => (!cls || x.class === cls) && (!search.trim() || `${x.name} ${x.ip ?? ''}`.toLowerCase().includes(search.trim().toLowerCase())))
  return (
    <div className="p-6 space-y-4 max-w-[1300px]">
      <div>
        <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><Boxes size={20} className="text-indigo-600" /> {t('cmdb.title')}</h1>
        <p className="text-sm text-slate-500 mt-0.5">{t('cmdb.subtitle')}</p>
      </div>
      {d && (
        <>
          <p className="text-xs text-slate-500">{t('cmdb.relCounts', { manual: d.relations.manual, auto: d.relations.auto })}</p>
          <div className="space-y-2">
            {Object.entries(d.classes).map(([g, cs]) => {
              const present = cs.filter(c => d.counts[c])
              if (!present.length) return null
              return (
                <div key={g} className="flex flex-wrap items-center gap-1.5">
                  <span className="text-xs text-slate-500 w-36">{t(`cmdb.group.${g}`)}</span>
                  {present.map(c => (
                    <button key={c} onClick={() => setCls(cls === c ? '' : c)}
                      className={cn('text-xs border rounded-full px-2.5 py-0.5', cls === c ? 'bg-indigo-600 text-white border-indigo-600' : 'bg-white border-slate-200 text-slate-700 hover:bg-slate-50')}>
                      {t(`cmdb.class.${c}`)} <b className="tabular-nums">{d.counts[c]}</b>
                    </button>
                  ))}
                </div>
              )
            })}
          </div>
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder={t('soc.filter.search') as string} className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm w-56" />
          <div className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-100 text-sm">
            {items.map(x => (
              <div key={x.id} className="flex items-center gap-3 px-4 py-1.5">
                <Link to={`/inventory/${x.id}`} className="flex-1 min-w-0 truncate text-indigo-600 hover:underline">{x.name}</Link>
                <span className="text-xs text-slate-400 w-32 font-mono">{x.ip ?? ''}</span>
                <CiClassSelect id={x.id} ci={x} classes={d.classes} />
                <span className="text-xs text-slate-500 w-24 text-right">{x.relations ? t('cmdb.relCount', { n: x.relations }) : ''}</span>
              </div>
            ))}
          </div>
        </>
      )}
      {q.isLoading && <p className="text-sm text-slate-500">{t('common.loading')}</p>}
    </div>
  )
}
