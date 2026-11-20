import { useEffect, useRef, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ArrowLeft, Camera, ScanLine, Search, X } from 'lucide-react'
import { assetsApi, labelsApi } from '../lib/api'
import { Attachments } from '../components/Attachments'
import { STAGES, StagePill } from '../components/AssetItam'
import { cn } from '../lib/utils'

function errText(e: unknown): string {
  const x = e as { response?: { data?: { detail?: string } }; message?: string }
  return x?.response?.data?.detail ?? x?.message ?? String(e)
}

type Detector = { detect: (src: CanvasImageSource) => Promise<Array<{ rawValue: string }>> }
const detectorCtor = (): (new (o: { formats: string[] }) => Detector) | null =>
  (window as unknown as { BarcodeDetector?: new (o: { formats: string[] }) => Detector }).BarcodeDetector ?? null

// The camera with the browser's own code reader (Chrome / Edge on Android, Safari 17+); without it the code is typed in.
function Scanner({ onCode, onClose }: { onCode: (c: string) => void; onClose: () => void }) {
  const { t } = useTranslation()
  const video = useRef<HTMLVideoElement>(null)
  const [err, setErr] = useState<string | null>(null)
  useEffect(() => {
    const Ctor = detectorCtor()
    if (!Ctor) { setErr(t('mob.noScanner') as string); return }
    let stream: MediaStream | null = null
    let stop = false
    const det = new Ctor({ formats: ['qr_code', 'code_128', 'code_39', 'ean_13', 'data_matrix'] })
    navigator.mediaDevices?.getUserMedia({ video: { facingMode: 'environment' } }).then(s => {
      stream = s
      if (video.current) { video.current.srcObject = s; void video.current.play() }
      const tick = async () => {
        if (stop || !video.current) return
        try {
          const r = await det.detect(video.current)
          if (r.length && r[0].rawValue) { stop = true; onCode(r[0].rawValue); return }
        } catch { /* a frame that could not be read */ }
        setTimeout(tick, 250)
      }
      void tick()
    }).catch(() => setErr(t('mob.noCamera') as string))
    return () => { stop = true; stream?.getTracks().forEach(tr => tr.stop()) }
  }, [onCode, t])
  return (
    <div className="fixed inset-0 bg-black z-50 flex flex-col">
      <div className="flex items-center justify-between p-3 text-white"><span className="text-sm">{t('mob.pointAtCode')}</span><button onClick={onClose}><X size={22} /></button></div>
      {err ? <p className="text-white text-sm p-4">{err}</p> : <video ref={video} playsInline muted className="flex-1 object-cover" />}
    </div>
  )
}

function useFindByCode() {
  const nav = useNavigate()
  return useMutation({ mutationFn: (code: string) => labelsApi.find(code), onSuccess: r => nav(`/m/a/${r.id}`) })
}

// The phone page: find an asset by scanning its label (or a barcode with its asset tag / serial) or by typing.
export function MobileHome() {
  const { t } = useTranslation()
  const [q, setQ] = useState('')
  const [scan, setScan] = useState(false)
  const [code, setCode] = useState('')
  const find = useFindByCode()
  const res = useQuery({ queryKey: ['mob-search', q], queryFn: () => labelsApi.search(q), enabled: q.trim().length >= 2 })
  return (
    <div className="min-h-screen bg-slate-50 p-4 space-y-4 max-w-lg mx-auto">
      <div className="flex items-center justify-between"><h1 className="text-lg font-bold text-slate-900">{t('mob.title')}</h1><Link to="/inventory/list" className="text-xs text-indigo-600">{t('mob.fullApp')}</Link></div>
      <button onClick={() => setScan(true)} className="w-full flex items-center justify-center gap-2 bg-indigo-600 text-white rounded-xl py-4 text-base font-medium"><ScanLine size={22} /> {t('mob.scan')}</button>
      <form className="flex gap-2" onSubmit={e => { e.preventDefault(); if (code.trim()) find.mutate(code.trim()) }}>
        <input value={code} onChange={e => setCode(e.target.value)} placeholder={t('mob.codePlaceholder') as string} className="flex-1 border border-slate-300 rounded-lg px-3 py-2.5 text-base" />
        <button className="px-4 rounded-lg border border-slate-300 bg-white text-sm">{t('mob.open')}</button>
      </form>
      {find.isError && <p className="text-sm text-red-700">{t('mob.notFound')}</p>}
      <div className="relative">
        <Search size={16} className="absolute left-3 top-3 text-slate-400" />
        <input value={q} onChange={e => setQ(e.target.value)} placeholder={t('mob.searchPlaceholder') as string} className="w-full border border-slate-300 rounded-lg pl-9 pr-3 py-2.5 text-base" />
      </div>
      <div className="space-y-1.5">
        {(res.data?.results ?? []).map(a => (
          <Link key={a.id} to={`/m/a/${a.id}`} className="block bg-white border border-slate-200 rounded-xl px-3 py-2.5">
            <div className="font-medium text-slate-900">{a.name}</div>
            <div className="text-xs text-slate-500">{[a.asset_tag, a.ip, a.model].filter(Boolean).join(' · ')}</div>
          </Link>
        ))}
      </div>
      {scan && <Scanner onClose={() => setScan(false)} onCode={c => { setScan(false); find.mutate(c) }} />}
    </div>
  )
}

// One asset on the phone: what it is and where, with a quick change of the place, owner, stage and note, and a photo.
export function MobileAsset() {
  const { t } = useTranslation()
  const { id } = useParams()
  const aid = Number(id)
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['asset', aid], queryFn: () => assetsApi.get(aid), enabled: Number.isFinite(aid) })
  const a = q.data
  const [f, setF] = useState<{ location: string; place: string; owner: string; stage: string; notes: string } | null>(null)
  useEffect(() => {
    if (a) setF({ location: a.location_override ?? '', place: a.place ?? '', owner: a.owner ?? '', stage: a.itam?.stage_set ? a.itam.lifecycle_stage : '', notes: a.notes ?? '' })
  }, [a])
  const save = useMutation({
    mutationFn: () => assetsApi.update(aid, { location_override: f!.location, place: f!.place, owner: f!.owner, notes: f!.notes, ...(f!.stage ? { itam: { lifecycle_stage: f!.stage } } : {}) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['asset', aid] }),
  })
  const photo = useRef<HTMLInputElement>(null)
  if (q.isError) return <div className="p-4 text-sm text-red-700">{errText(q.error)} <Link to="/m" className="text-indigo-600">{t('mob.back')}</Link></div>
  if (!a || !f) return <div className="p-4 text-sm text-slate-500">{t('common.loading')}</div>
  const inp = 'mt-0.5 block w-full border border-slate-300 rounded-lg px-3 py-2.5 text-base bg-white'
  return (
    <div className="min-h-screen bg-slate-50 p-4 space-y-4 max-w-lg mx-auto">
      <Link to="/m" className="inline-flex items-center gap-1 text-sm text-indigo-600"><ArrowLeft size={16} /> {t('mob.back')}</Link>
      <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-1">
        <div className="text-lg font-bold text-slate-900">{a.name}</div>
        <div className="text-sm text-slate-600">{[a.manufacturer, a.model].filter(Boolean).join(' ')}</div>
        <div className="text-xs text-slate-500 font-mono">{[a.itam?.asset_tag, a.serial, a.ip].filter(Boolean).join(' · ')}</div>
        <div className="flex items-center gap-2 pt-1">{a.itam && <StagePill stage={a.itam.lifecycle_stage} />}{a.location && <span className="text-xs text-slate-500">{a.location}</span>}</div>
        {a.itam?.warranty_until && <div className="text-xs text-slate-500">{t('itam.f.warranty_until')}: {a.itam.warranty_until}</div>}
      </div>
      <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-3">
        <label className="block text-xs text-slate-500">{t('assets.location')}<input value={f.location} onChange={e => setF({ ...f, location: e.target.value })} className={inp} /></label>
        <label className="block text-xs text-slate-500">{t('assets.place')}<input value={f.place} onChange={e => setF({ ...f, place: e.target.value })} className={inp} /></label>
        <label className="block text-xs text-slate-500">{t('assets.owner')}<input value={f.owner} onChange={e => setF({ ...f, owner: e.target.value })} className={inp} /></label>
        <div>
          <div className="text-xs text-slate-500 mb-1">{t('itam.stageLabel')}</div>
          <div className="flex flex-wrap gap-1.5">
            {STAGES.filter(s => s !== 'disposed').map(s => (
              <button key={s} onClick={() => setF({ ...f, stage: s })} className={cn('text-sm border rounded-full px-3 py-1.5', (f.stage || a.itam?.lifecycle_stage) === s ? 'bg-indigo-600 text-white border-indigo-600' : 'bg-white border-slate-300')}>{t(`itam.stage.${s}`)}</button>
            ))}
          </div>
        </div>
        <label className="block text-xs text-slate-500">{t('assets.notes')}<textarea value={f.notes} rows={3} maxLength={2000} onChange={e => setF({ ...f, notes: e.target.value })} className={inp} /></label>
        <button disabled={save.isPending} onClick={() => save.mutate()} className="w-full bg-indigo-600 text-white rounded-xl py-3 text-base font-medium disabled:opacity-50">{t('common.save')}</button>
        {save.isSuccess && <p className="text-sm text-green-700 text-center">{t('itam.saved')}</p>}
        {save.isError && <p className="text-sm text-red-700">{errText(save.error)}</p>}
      </div>
      <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-2">
        <input ref={photo} type="file" accept="image/*" capture="environment" className="hidden"
          onChange={e => { const file = e.target.files?.[0]; if (file) void labelsApi.uploadPhoto(aid, file).then(() => qc.invalidateQueries({ queryKey: ['attachments', 'asset', aid] })); e.target.value = '' }} />
        <button onClick={() => photo.current?.click()} className="w-full flex items-center justify-center gap-2 border border-slate-300 rounded-xl py-3 text-base"><Camera size={20} /> {t('mob.photo')}</button>
        <Attachments kind="asset" id={aid} compact />
      </div>
      <Link to={`/inventory/${aid}`} className="block text-center text-sm text-indigo-600">{t('mob.openFull')}</Link>
    </div>
  )
}
