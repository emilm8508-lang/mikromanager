import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { vulnApi } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Package, Search } from 'lucide-react'
import { useTranslation } from 'react-i18next'

export function Software() {
  const { t } = useTranslation()
  const [query, setQuery] = useState('')
  const [debouncedQuery, setDebouncedQuery] = useState('')

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedQuery(query.trim()), 300)
    return () => clearTimeout(timer)
  }, [query])

  const { data, isLoading } = useQuery({
    queryKey: ['software-packages', debouncedQuery],
    queryFn: () => vulnApi.packages(debouncedQuery ? { q: debouncedQuery } : undefined),
  })

  const rows = data ?? []

  return (
    <div className="p-6 space-y-4 max-w-5xl">
      <div className="flex items-center gap-2">
        <Package size={20} className="text-indigo-600" />
        <h1 className="text-lg font-semibold text-slate-900">{t('nav.software')}</h1>
      </div>
      <p className="text-sm text-slate-500">{t('software.subtitle')}</p>

      <div className="relative max-w-sm">
        <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
        <input
          type="text"
          value={query}
          onChange={e => setQuery(e.target.value)}
          placeholder={t('software.searchPlaceholder') as string}
          className="w-full border border-slate-300 rounded-lg pl-8 pr-3 py-1.5 text-sm"
        />
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
