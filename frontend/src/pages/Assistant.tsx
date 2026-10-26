import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Sparkles, Send, Settings2, RotateCcw, Wrench } from 'lucide-react'
import { aiApi, AiScope } from '../lib/api'
import { cn } from '../lib/utils'

function errText(e: unknown): string {
  const x = e as { response?: { data?: { detail?: string } }; message?: string }
  return x?.response?.data?.detail ?? x?.message ?? String(e)
}

const SCOPES: AiScope[] = ['alerts', 'assets', 'vulnerabilities', 'availability', 'configs', 'syslog']

function SettingsPanel({ open, setOpen }: { open: boolean; setOpen: (v: boolean) => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const st = useQuery({ queryKey: ['ai-status'], queryFn: aiApi.status })
  const s = st.data?.settings
  const [key, setKey] = useState('')
  const [model, setModel] = useState('claude-opus-5-5')
  const [effort, setEffort] = useState('medium')
  const [scopes, setScopes] = useState<Record<string, boolean>>({})
  const [limit, setLimit] = useState(100)
  const [consent, setConsent] = useState(false)
  const [enabled, setEnabled] = useState(false)
  const [dirty, setDirty] = useState(false)
  useEffect(() => {
    if (s && !dirty) { setModel(s.model); setEffort(s.effort); setScopes(s.scopes); setLimit(s.daily_limit); setConsent(!!s.consent_at); setEnabled(s.enabled) }
  }, [s, dirty])
  const save = useMutation({
    mutationFn: (extra: { api_key?: string }) => aiApi.save({ model, effort, scopes, daily_limit: limit, consent, enabled, ...extra }),
    onSuccess: () => { setKey(''); setDirty(false); void qc.invalidateQueries({ queryKey: ['ai-status'] }) },
  })
  const mark = <T,>(f: (v: T) => void) => (v: T) => { f(v); setDirty(true) }
  if (!s) return null
  return (
    <div className="bg-white border border-slate-200 rounded-xl text-sm">
      <button className="w-full flex items-center gap-2 px-4 py-3 text-left" onClick={() => setOpen(!open)}>
        <Settings2 size={15} className="text-slate-500" />
        <span className="font-semibold text-slate-900">{t('ai.settings.title')}</span>
        <span className={cn('text-xs border rounded-full px-2 py-0.5', s.ready ? 'bg-green-50 text-green-700 border-green-200' : 'bg-amber-50 text-amber-800 border-amber-200')}>
          {s.ready ? t('ai.ready') : t(`ai.notReady.${s.not_ready ?? 'off'}`)}
        </span>
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-3 border-t border-slate-100 pt-3">
          <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 text-xs text-amber-900 space-y-1">
            <div className="font-medium">{t('ai.privacy.title')}</div>
            <p>{t('ai.privacy.body')}</p>
          </div>
          <div className="flex gap-2 flex-wrap items-center">
            <input type="password" autoComplete="off" value={key} onChange={e => mark(setKey)(e.target.value)} placeholder={(s.has_key ? t('ai.settings.keySet') : t('ai.settings.keyPlaceholder')) as string}
              className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm w-80 font-mono" />
            <button disabled={!key.trim() || save.isPending} onClick={() => save.mutate({ api_key: key.trim() })} className="px-3 py-1.5 text-sm rounded-lg bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50">{t('ai.settings.saveKey')}</button>
            {s.has_key && <button disabled={save.isPending} onClick={() => { if (confirm(t('ai.settings.removeKeyConfirm') as string)) save.mutate({ api_key: '' }) }} className="px-3 py-1.5 text-sm rounded-lg border border-slate-300 bg-white hover:bg-slate-50">{t('ai.settings.removeKey')}</button>}
            <span className="text-[11px] text-slate-400">{t('ai.settings.keyNote')}</span>
          </div>
          <div className="flex gap-4 flex-wrap">
            <label className="text-xs text-slate-500">{t('ai.settings.model')}
              <select value={model} onChange={e => mark(setModel)(e.target.value)} className="block mt-0.5 border border-slate-300 rounded-lg px-2 py-1 text-sm bg-white text-slate-900">
                {s.models.map(m => <option key={m} value={m}>{t(`ai.models.${m}`, { defaultValue: m })}</option>)}
              </select></label>
            <label className="text-xs text-slate-500">{t('ai.settings.effort')}
              <select value={effort} onChange={e => mark(setEffort)(e.target.value)} className="block mt-0.5 border border-slate-300 rounded-lg px-2 py-1 text-sm bg-white text-slate-900">
                {s.efforts.map(m => <option key={m} value={m}>{t(`ai.efforts.${m}`)}</option>)}
              </select></label>
            <label className="text-xs text-slate-500">{t('ai.settings.dailyLimit')}
              <input type="number" min={1} value={limit} onChange={e => mark(setLimit)(Number(e.target.value))} className="block mt-0.5 border border-slate-300 rounded-lg px-2 py-1 text-sm w-24 text-slate-900" /></label>
          </div>
          <div>
            <div className="text-xs font-medium text-slate-700 mb-1">{t('ai.settings.scopes')}</div>
            <div className="grid sm:grid-cols-2 gap-x-6 gap-y-1">
              {SCOPES.map(sc => (
                <label key={sc} className="flex items-start gap-2 text-xs text-slate-700">
                  <input type="checkbox" className="mt-0.5" checked={!!scopes[sc]} onChange={e => mark(setScopes)({ ...scopes, [sc]: e.target.checked })} />
                  <span><b>{t(`ai.scope.${sc}.name`)}</b> — {t(`ai.scope.${sc}.what`)}</span>
                </label>
              ))}
            </div>
          </div>
          <label className="flex items-start gap-2 text-xs text-slate-800">
            <input type="checkbox" className="mt-0.5" checked={consent} onChange={e => mark(setConsent)(e.target.checked)} />
            <span>{t('ai.settings.consent')}{s.consent_at ? <span className="text-slate-400"> ({s.consent_by}, {new Date(s.consent_at).toLocaleString()})</span> : null}</span>
          </label>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={enabled} onChange={e => mark(setEnabled)(e.target.checked)} /> {t('ai.settings.enabled')}</label>
          <div className="flex items-center gap-3">
            <button disabled={!dirty || save.isPending} onClick={() => save.mutate({})} className="px-3 py-1.5 text-sm rounded-lg bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50">{t('ai.settings.save')}</button>
            {save.isError && <span className="text-xs text-red-700">{errText(save.error)}</span>}
          </div>
        </div>
      )}
    </div>
  )
}

interface Msg { role: 'user' | 'assistant' | 'error'; text: string; tools?: Array<{ name: string }>; usage?: { in: number; out: number } }

function History() {
  const { t } = useTranslation()
  const st = useQuery({ queryKey: ['ai-status'], queryFn: aiApi.status })
  const d = st.data
  const [open, setOpen] = useState(false)
  if (!d) return null
  return (
    <div className="text-xs text-slate-500">
      <button onClick={() => setOpen(!open)} className="underline decoration-dotted hover:text-indigo-600">
        {t('ai.history.title')} · {t('ai.history.today', { n: d.today })} · {t('ai.history.tokens', { in: Math.round(d.tokens_30d.in / 1000), out: Math.round(d.tokens_30d.out / 1000) })}
      </button>
      {open && (
        <div className="mt-2 bg-white border border-slate-200 rounded-xl divide-y divide-slate-100">
          {d.queries.length === 0 && <div className="px-3 py-2">{t('ai.history.none')}</div>}
          {d.queries.map((q, i) => (
            <div key={i} className="px-3 py-1.5 flex gap-3">
              <span className="w-36 shrink-0 text-slate-400">{new Date(q.at).toLocaleString()}</span>
              <span className="w-20 shrink-0 truncate">{q.user}</span>
              <span className="flex-1 min-w-0 text-slate-700 truncate" title={q.question}>{q.question}</span>
              <span className="w-48 shrink-0 truncate text-slate-400" title={q.tools.join(', ')}>{q.tools.join(', ')}</span>
              <span className={cn('w-24 shrink-0 text-right tabular-nums', q.error && 'text-red-600')}>{q.error ? t('ai.history.error') : `${q.in}/${q.out}`}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// Questions about the network in plain words, answered by Claude from the agent's own data through read-only tools (see services/ai_assistant.py).
export function Assistant() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const st = useQuery({ queryKey: ['ai-status'], queryFn: aiApi.status })
  const ready = st.data?.settings.ready
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [msgs, setMsgs] = useState<Msg[]>([])
  const [sid, setSid] = useState<string | null>(null)
  const [text, setText] = useState('')
  const endRef = useRef<HTMLDivElement>(null)
  useEffect(() => { if (st.data && !ready) setSettingsOpen(true) }, [st.data, ready])
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [msgs])
  const ask = useMutation({
    mutationFn: (q: string) => aiApi.chat(q, sid),
    onSuccess: r => { setSid(r.session_id); setMsgs(m => [...m, { role: 'assistant', text: r.answer, tools: r.tools, usage: r.usage }]); void qc.invalidateQueries({ queryKey: ['ai-status'] }) },
    onError: e => setMsgs(m => [...m, { role: 'error', text: errText(e) }]),
  })
  const send = (q: string) => { const v = q.trim(); if (!v || ask.isPending) return; setMsgs(m => [...m, { role: 'user', text: v }]); setText(''); ask.mutate(v) }
  const reset = () => { if (sid) void aiApi.endSession(sid); setSid(null); setMsgs([]) }
  const suggestions = ['whatsWrong', 'riskiest', 'eol', 'changes', 'services']
  return (
    <div className="p-6 space-y-4 max-w-[1000px]">
      <div className="flex items-start gap-3">
        <div className="flex-1">
          <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><Sparkles size={20} className="text-indigo-600" /> {t('ai.title')}</h1>
          <p className="text-sm text-slate-500 mt-0.5">{t('ai.subtitle')}</p>
        </div>
        {msgs.length > 0 && <button onClick={reset} className="flex items-center gap-1.5 text-sm border border-slate-300 rounded-lg px-3 py-1.5 bg-white hover:bg-slate-50"><RotateCcw size={14} /> {t('ai.newChat')}</button>}
      </div>
      <SettingsPanel open={settingsOpen} setOpen={setSettingsOpen} />
      {ready && (
        <div className="space-y-3">
          {msgs.length === 0 && (
            <div className="flex flex-wrap gap-2">
              {suggestions.map(k => <button key={k} onClick={() => send(t(`ai.suggest.${k}`) as string)} className="text-xs border border-slate-300 rounded-full px-3 py-1 bg-white hover:bg-indigo-50 hover:border-indigo-300">{t(`ai.suggest.${k}`)}</button>)}
            </div>
          )}
          <div className="space-y-3">
            {msgs.map((m, i) => (
              <div key={i} className={cn('rounded-xl px-4 py-3 text-sm whitespace-pre-wrap break-words', m.role === 'user' ? 'bg-indigo-50 text-slate-900 ml-12' : m.role === 'error' ? 'bg-red-50 text-red-800 border border-red-200' : 'bg-white border border-slate-200 text-slate-800 mr-12')}>
                {m.text}
                {m.tools && m.tools.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1.5 items-center text-[11px] text-slate-400"><Wrench size={11} />{m.tools.map((x, j) => <span key={j} className="border border-slate-200 rounded px-1.5">{t(`ai.tool.${x.name}`, { defaultValue: x.name })}</span>)}
                    {m.usage && <span className="ml-auto">{m.usage.in}/{m.usage.out} tok</span>}</div>
                )}
              </div>
            ))}
            {ask.isPending && <div className="text-sm text-slate-500 animate-pulse">{t('ai.thinking')}</div>}
            <div ref={endRef} />
          </div>
          <div className="flex gap-2 items-end">
            <textarea value={text} onChange={e => setText(e.target.value)} rows={2} placeholder={t('ai.placeholder') as string}
              onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(text) } }}
              className="flex-1 border border-slate-300 rounded-xl px-3 py-2 text-sm resize-none" />
            <button disabled={!text.trim() || ask.isPending} onClick={() => send(text)} className="px-4 py-2.5 rounded-xl bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50"><Send size={16} /></button>
          </div>
        </div>
      )}
      <History />
    </div>
  )
}
