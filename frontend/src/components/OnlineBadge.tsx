import { useTranslation } from 'react-i18next'
import { Badge } from './ui/Badge'

// Online / offline of a device; an online device none of whose management ports answers from the agent (it answers ping or SNMP) says so.
export function OnlineBadge({ online, mgmtOk }: { online: boolean; mgmtOk?: boolean | null }) {
  const { t } = useTranslation()
  return (
    <span className="inline-flex items-center gap-1.5">
      <Badge variant={online ? 'green' : 'red'}>{online ? t('common.online') : t('common.offline')}</Badge>
      {online && mgmtOk === false && <span className="text-[10px] text-amber-700 border border-amber-300 bg-amber-50 rounded px-1.5 py-0.5" title={t('common.mgmtBlockedHint') as string}>{t('common.mgmtBlocked')}</span>}
    </span>
  )
}
