import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Modal } from './ui/Modal'
import { Button } from './ui/Button'

interface Props {
  open: boolean
  onClose: () => void
  platform: 'linux' | 'windows'
  targetLabel: string
  onRun: (args: { script: string; useSudo: boolean; reason: string }) => Promise<void>
}

export function RunScriptModal({ open, onClose, platform, targetLabel, onRun }: Props) {
  const { t } = useTranslation()
  const [script, setScript] = useState('')
  const [useSudo, setUseSudo] = useState(false)
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const reset = () => { setScript(''); setUseSudo(false); setReason(''); setError(null) }
  const close = () => { if (busy) return; reset(); onClose() }

  const submit = async () => {
    if (!script.trim()) { setError(t('runScript.scriptRequired') as string); return }
    if (!reason.trim()) { setError(t('runScript.reasonRequired') as string); return }
    setBusy(true)
    setError(null)
    try {
      await onRun({ script: script.trim(), useSudo, reason: reason.trim() })
      reset()
      onClose()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal open={open} onClose={close} title={t('runScript.title', { target: targetLabel }) as string} className="max-w-2xl">
      <div className="space-y-3">
        <p className="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded p-2">
          {t('runScript.warning')}
        </p>
        <div>
          <label className="text-xs font-medium text-slate-600 block mb-1">
            {t(platform === 'linux' ? 'runScript.scriptLabelLinux' : 'runScript.scriptLabelWindows')}
          </label>
          <textarea
            value={script}
            onChange={e => setScript(e.target.value)}
            rows={10}
            spellCheck={false}
            className="w-full border border-slate-300 rounded-lg px-2 py-1.5 text-xs font-mono"
            placeholder={platform === 'linux' ? '#!/bin/bash\necho hello' : '# PowerShell\nWrite-Host hello'}
          />
        </div>
        {platform === 'linux' && (
          <label className="flex items-center gap-2 text-sm text-slate-700">
            <input type="checkbox" checked={useSudo} onChange={e => setUseSudo(e.target.checked)} />
            {t('runScript.useSudo')}
          </label>
        )}
        <div>
          <label className="text-xs font-medium text-slate-600 block mb-1">{t('runScript.reasonLabel')}</label>
          <input
            type="text"
            value={reason}
            onChange={e => setReason(e.target.value)}
            className="w-full border border-slate-300 rounded-lg px-2 py-1.5 text-sm"
          />
        </div>
        {error && <p className="text-sm text-red-600">{error}</p>}
        <div className="flex justify-end gap-2 pt-1">
          <button type="button" onClick={close} disabled={busy} className="text-sm text-slate-500 hover:underline">
            {t('common.cancel')}
          </button>
          <Button variant="danger" onClick={submit} disabled={busy}>
            {busy ? t('common.loading') : t('runScript.run')}
          </Button>
        </div>
      </div>
    </Modal>
  )
}
