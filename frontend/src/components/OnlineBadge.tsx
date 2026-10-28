import { useTranslation } from 'react-i18next'
import { Badge } from './ui/Badge'

// Online / offline of a device; a device that can only be read over SNMP (SwOS Lite, older switches) says so, which is normal and not a fault; an online device none of whose management ports answers from the agent (it answers ping or SNMP) says so.
export function OnlineBadge({ online, mgmtOk, snmpOnly }: { online: boolean; mgmtOk?: boolean | null; snmpOnly?: boolean }) {
  const { t } = useTranslation()
  return (
    <span className="inline-flex items-center gap-1.5">
      <Badge variant={online ? 'green' : 'red'}>{online ? t('common.online') : t('common.offline')}</Badge>
      {online && mgmtOk === false && <span className="text-[10px] text-amber-700 border border-amber-300 bg-amber-50 rounded px-1.5 py-0.5" title={t('common.mgmtBlockedHint') as string}>{t('common.mgmtBlocked')}</span>}
      {snmpOnly && <span className="text-[10px] text-slate-600 border border-slate-300 bg-slate-50 rounded px-1.5 py-0.5" title={t('common.snmpOnlyHint') as string}>{t('common.snmpOnly')}</span>}
    </span>
  )
}
