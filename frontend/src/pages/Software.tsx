import { useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { vulnApi } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Package, Search } from 'lucide-react'
import { useTranslation } from 'react-i18next'

export function Software() {
  const { t } = useTranslation()
  const [query, setQuery] = useState('')
  const [params, setParams] = useSearchParams()
  const host = params.get('host') ?? 'all'

  const { data, isLoading } = useQuery({
    queryKey: ['software-packages'],
    queryFn: () => vulnApi.packages(),
  })

  // the asset filter lists every device that has a software list
  const hosts = useMemo(() => {
    const m = new Map<number, string>()
    for (const r of data ?? []) if (!m.has(r.host_id)) m.set(r.host_id, r.hostname ? `${r.hostname} (${r.ip})` : r.ip)
    return [...m.entries()].sort((a, b) => a[1].localeCompare(b[1]))
  }, [data])
  const needle = query.trim().toLowerCase()
  const rows = useMemo(
    () => (data ?? []).filter(r => (host === 'all' || String(r.host_id) === host) && (!needle || r.name.toLowerCase().includes(needle))),
    [data, host, needle],
  )
  const setHost = (v: string) => setParams(v === 'all' ? {} : { host: v }, { replace: true })

  return (
    <div className="p-6 space-y-4 max-w-5xl">
      <div className="flex items-center gap-2">
        <Package size={20} className="text-indigo-600" />
        <h1 className="text-lg font-semibold text-slate-900">{t('nav.software')}</h1>
      </div>
      <p className="text-sm text-slate-500">{t('software.subtitle')}</p>

      <div className="flex flex-wrap gap-2">
        <div className="relative w-full max-w-sm">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder={t('software.searchPlaceholder') as string}
            className="w-full border border-slate-300 rounded-lg pl-8 pr-3 py-1.5 text-sm"
          />
        </div>
        <select value={host} onChange={e => setHost(e.target.value)} className="border border-slate-300 rounded-lg px-2 py-1.5 text-sm bg-white max-w-xs" aria-label={t('software.assetFilter') as string}>
          <option value="all">{t('software.allAssets')}</option>
          {hosts.map(([id, label]) => <option key={id} value={id}>{label}</option>)}
        </select>
      </div>

      <Card>
        <CardHeader>
          <h2 className="text-sm font-semibold text-slate-700">
            {t('software.hostsTitle')} {!isLoading && `(${rows.length})`}
          </h2>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-sm text-slate-500">{t('common.loading')}</p>
          ) : rows.length === 0 ? (
            <p className="text-sm text-slate-500">{t('software.empty')}</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-slate-500 border-b">
                    <th className="py-1 pr-3">{t('software.colHost')}</th>
                    <th className="pr-3">{t('software.colName')}</th>
                    <th className="pr-3">{t('software.colVersion')}</th>
                    <th>{t('software.colLastSeen')}</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r, i) => (
                    <tr key={`${r.host_id}:${r.name}:${i}`} className="border-b border-slate-100">
                      <td className="py-2">
                        <span className="font-mono text-xs">{r.ip}</span>
                        {r.hostname && <span className="text-xs text-slate-500 ml-1.5">{r.hostname}</span>}
                      </td>
                      <td>{r.name}</td>
                      <td className="text-slate-500 font-mono text-xs">{r.version}</td>
                      <td className="text-xs text-slate-500">{r.last_seen ? new Date(r.last_seen).toLocaleString() : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
