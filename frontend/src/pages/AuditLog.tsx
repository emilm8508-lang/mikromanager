import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { auditApi } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { Input } from '../components/ui/Input'
import { ClipboardList, ChevronLeft, ChevronRight } from 'lucide-react'
import { useAuth } from './Login'

const PAGE_SIZE = 50

function methodBadgeVariant(method: string): 'red' | 'yellow' | 'blue' | 'gray' {
  switch (method) {
    case 'DELETE': return 'red'
    case 'POST': return 'blue'
    case 'PUT':
    case 'PATCH': return 'yellow'
    default: return 'gray'
  }
}

function formatDate(iso: string): string {
  try { return new Date(iso).toLocaleString() } catch { return iso }
}

export function AuditLog() {
  const { t } = useTranslation()
  const { role } = useAuth()
  const [usernameFilter, setUsernameFilter] = useState('')
  const [offset, setOffset] = useState(0)

  const { data, isLoading } = useQuery({
    queryKey: ['audit-log', usernameFilter, offset],
    queryFn: () => auditApi.list({ limit: PAGE_SIZE, offset, username: usernameFilter || undefined }),
    enabled: role === 'admin',
  })

  if (role !== 'admin') {
    return (
      <div className="p-6">
        <Card><CardContent className="text-sm text-slate-500 py-8 text-center">
          {t('audit.adminOnly')}
        </CardContent></Card>
      </div>
    )
  }

  const rows = data ?? []

  return (
    <div className="p-6 space-y-5">
      <div>
        <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2">
          <ClipboardList size={20} className="text-indigo-600" />
          {t('audit.title')}
        </h1>
        <p className="text-sm text-slate-500 mt-0.5">{t('audit.subtitle')}</p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-3">
            <div className="w-56">
              <Input
                placeholder={t('audit.filterUsername') as string}
                value={usernameFilter}
                onChange={e => { setUsernameFilter(e.target.value); setOffset(0) }}
              />
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setOffset(o => Math.max(0, o - PAGE_SIZE))}
                disabled={offset === 0}
                className="p-1.5 rounded border border-slate-200 text-slate-500 hover:text-indigo-600 disabled:opacity-40"
              >
                <ChevronLeft size={14} />
              </button>
              <button
                onClick={() => setOffset(o => o + PAGE_SIZE)}
                disabled={rows.length < PAGE_SIZE}
                className="p-1.5 rounded border border-slate-200 text-slate-500 hover:text-indigo-600 disabled:opacity-40"
              >
                <ChevronRight size={14} />
              </button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <p className="text-sm text-slate-500 py-8 text-center">{t('common.loading')}</p>
          ) : rows.length === 0 ? (
            <p className="text-sm text-slate-500 py-8 text-center">{t('audit.empty')}</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-200 text-left text-xs text-slate-500">
                    <th className="px-4 py-2 font-medium">{t('audit.colTime')}</th>
                    <th className="px-4 py-2 font-medium">{t('audit.colUser')}</th>
                    <th className="px-4 py-2 font-medium">{t('audit.colSource')}</th>
                    <th className="px-4 py-2 font-medium">{t('audit.colAction')}</th>
                    <th className="px-4 py-2 font-medium">{t('audit.colResult')}</th>
                    <th className="px-4 py-2 font-medium">{t('audit.colIp')}</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map(r => (
                    <tr key={r.id} className="border-b border-slate-100 last:border-0">
                      <td className="px-4 py-2 whitespace-nowrap text-slate-600">{formatDate(r.ts)}</td>
                      <td className="px-4 py-2">
                        <span className="font-medium text-slate-800">{r.username}</span>
                        <span className="ml-1.5 text-[11px] text-slate-400">({r.role})</span>
                      </td>
                      <td className="px-4 py-2">
                        <Badge variant={r.source === 'local' ? 'yellow' : 'gray'} className="text-[10px]">
                          {r.source === 'local' ? t('auth.sourceLocal') : t('auth.sourceOvh')}
                        </Badge>
                      </td>
                      <td className="px-4 py-2">
                        <Badge variant={methodBadgeVariant(r.method)} className="text-[10px] mr-1.5">{r.method}</Badge>
                        <span className="font-mono text-[11px] text-slate-600">{r.path}</span>
                      </td>
                      <td className="px-4 py-2">
                        <span className={r.status_code < 400 ? 'text-green-700' : 'text-red-600'}>{r.status_code}</span>
                      </td>
                      <td className="px-4 py-2 text-slate-500">{r.ip ?? '—'}</td>
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
