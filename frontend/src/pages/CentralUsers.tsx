import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  centralAuthApi, centralUsersApi, centralApi, centralSession, centralConfig,
  type CentralUser, type AuthRole,
} from '../lib/api'
import { Button } from '../components/ui/Button'
import { Input } from '../components/ui/Input'
import { Badge } from '../components/ui/Badge'
import { LogIn, Trash2, KeyRound, ShieldCheck } from 'lucide-react'

function formatDate(iso: string | null): string {
  if (!iso) return '—'
  try { return new Date(iso).toLocaleString() } catch { return iso }
}

// ── Users panel — per-user OVH account login, then admin-only CRUD ──────────
// A DIFFERENT login than the legacy shared viewer password configured on the
// "Widok" tab: this is the new, recommended per-user account system, used
// here for account management and — once you switch the "Widok" tab over
// too — for viewing/acting on the dashboard itself.

export function UsersPanel() {
  const { t } = useTranslation()
  const [session, setSessionState] = useState(centralSession.load())

  if (!session) {
    return <UsersLoginForm onLoggedIn={s => setSessionState(s)} />
  }
  if (session.role !== 'admin' || (session.allowedTenants !== null && session.allowedTenants !== undefined)) {
    // Only a GLOBAL admin manages accounts — a tenant-scoped admin manages
    // their own tenant's devices/rules, not the server's user directory.
    return (
      <div className="bg-white rounded-lg border border-slate-200 p-4 text-sm text-slate-600">
        <p>{t('centralUsers.notGlobalAdmin')}</p>
        <button
          onClick={() => { centralSession.clear(); setSessionState(null) }}
          className="mt-2 text-xs text-indigo-600 hover:text-indigo-500"
        >
          {t('centralUsers.switchAccount')}
        </button>
      </div>
    )
  }
  return <UsersManagePanel session={session} onLogout={() => { centralSession.clear(); setSessionState(null) }} />
}

function UsersLoginForm({ onLoggedIn }: { onLoggedIn: (s: NonNullable<ReturnType<typeof centralSession.load>>) => void }) {
  const { t } = useTranslation()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    if (!centralConfig.load()) { setError(t('centralUsers.notConfigured') as string); return }
    setBusy(true)
    try {
      const r = await centralAuthApi.login(username.trim(), password, totpCode || undefined)
      const session = {
        token: r.token, username: r.username, role: r.role,
        allowedTenants: r.allowed_tenants, expiresAt: r.expires_at,
      }
      centralSession.save(session)
      onLoggedIn(session)
    } catch (e) {
      setError((e as Error).message || (t('centralUsers.loginFailed') as string))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="bg-white rounded-lg border border-slate-200 p-4 space-y-3 max-w-sm">
      <div className="flex items-center gap-2">
        <LogIn size={15} className="text-indigo-600" />
        <h3 className="font-semibold text-slate-900 text-sm">{t('centralUsers.loginTitle')}</h3>
      </div>
      <p className="text-xs text-slate-500">{t('centralUsers.loginSubtitle')}</p>
      <form onSubmit={submit} className="space-y-3">
        <Input label={t('auth.username') as string} value={username}
          onChange={e => setUsername(e.target.value)} required autoFocus />
        <Input label={t('auth.password') as string} type="password" value={password}
          onChange={e => setPassword(e.target.value)} required />
        <Input label={`${t('auth.totpCode')} (${t('common.optional')})`} value={totpCode}
          onChange={e => setTotpCode(e.target.value)} inputMode="numeric" maxLength={6}
          autoComplete="one-time-code" />
        {error && <p className="text-xs text-red-600">{error}</p>}
        <Button type="submit" variant="primary" disabled={busy}>{t('auth.loginButton')}</Button>
      </form>
    </div>
  )
}

function UsersManagePanel({ session, onLogout }: { session: NonNullable<ReturnType<typeof centralSession.load>>; onLogout: () => void }) {
  const { t } = useTranslation()
  const [users, setUsers] = useState<CentralUser[]>([])
  const [tenants, setTenants] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [showForm, setShowForm] = useState(false)
  const [totpResult, setTotpResult] = useState<{ id: number; secret: string; otpauth_uri: string } | null>(null)

  // Add-user form state
  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newRole, setNewRole] = useState<AuthRole>('viewer')
  const [newGlobal, setNewGlobal] = useState(true)
  const [newTenants, setNewTenants] = useState<string[]>([])
  const [submitting, setSubmitting] = useState(false)

  const reload = async () => {
    setLoading(true)
    try {
      const [u, t] = await Promise.all([centralUsersApi.list(), centralApi.tenants()])
      setUsers(u.users ?? [])
      setTenants((t.tenants ?? []).map(x => x.id))
      setErr(null)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { reload() }, [])

  const submit = async () => {
    setSubmitting(true)
    try {
      await centralUsersApi.add({
        username: newUsername.trim(), password: newPassword, role: newRole,
        allowed_tenants: newGlobal ? null : newTenants,
      })
      setShowForm(false)
      setNewUsername(''); setNewPassword(''); setNewRole('viewer'); setNewGlobal(true); setNewTenants([])
      await reload()
    } catch (e) {
      alert((e as Error).message)
    } finally {
      setSubmitting(false)
    }
  }

  const toggleActive = async (u: CentralUser) => {
    try { await centralUsersApi.update({ id: u.id, is_active: !u.is_active }); await reload() }
    catch (e) { alert((e as Error).message) }
  }

  const changeRole = async (u: CentralUser, role: AuthRole) => {
    try { await centralUsersApi.update({ id: u.id, role }); await reload() }
    catch (e) { alert((e as Error).message) }
  }

  const del = async (u: CentralUser) => {
    if (!confirm(t('centralUsers.confirmDelete', { username: u.username }) as string)) return
    try { await centralUsersApi.delete(u.id); await reload() }
    catch (e) { alert((e as Error).message) }
  }

  const resetPassword = async (u: CentralUser) => {
    const pw = prompt(t('centralUsers.newPasswordPrompt') as string)
    if (!pw) return
    try { await centralUsersApi.update({ id: u.id, password: pw }); alert(t('centralUsers.passwordResetOk') as string) }
    catch (e) { alert((e as Error).message) }
  }

  const resetTotp = async (u: CentralUser) => {
    if (!confirm(t('centralUsers.confirmTotpReset', { username: u.username }) as string)) return
    try {
      const r = await centralUsersApi.totpReset(u.id)
      setTotpResult({ id: u.id, secret: r.secret, otpauth_uri: r.otpauth_uri })
      await reload()
    } catch (e) { alert((e as Error).message) }
  }

  return (
    <div className="bg-white rounded-lg border border-slate-200 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="font-semibold text-slate-900">{t('centralUsers.title')}</h3>
          <p className="text-xs text-slate-500 mt-0.5">{t('centralUsers.loggedInAs', { username: session.username })}</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => setShowForm(v => !v)}
            className="px-3 py-1.5 text-sm bg-indigo-600 text-white rounded hover:bg-indigo-700">
            {showForm ? t('common.cancel') : `+ ${t('centralUsers.addUser')}`}
          </button>
          <button onClick={onLogout} className="px-3 py-1.5 text-sm text-slate-500 hover:text-red-600">
            {t('auth.logout')}
          </button>
        </div>
      </div>

      {showForm && (
        <div className="border border-slate-200 rounded p-3 space-y-2 bg-slate-50">
          <div className="grid grid-cols-2 gap-2">
            <Input label={t('auth.username') as string} value={newUsername} onChange={e => setNewUsername(e.target.value)} />
            <Input label={t('auth.password') as string} type="password" value={newPassword} onChange={e => setNewPassword(e.target.value)} />
          </div>
          <label className="text-sm block">
            <span className="text-slate-600">{t('centralUsers.role')}</span>
            <select value={newRole} onChange={e => setNewRole(e.target.value as AuthRole)}
              className="w-full mt-1 border border-slate-300 rounded px-2 py-1">
              <option value="viewer">{t('auth.roleViewer')}</option>
              <option value="admin">{t('auth.roleAdmin')}</option>
            </select>
          </label>
          <label className="text-sm flex items-center gap-2">
            <input type="checkbox" checked={newGlobal} onChange={e => setNewGlobal(e.target.checked)} />
            <span className="text-slate-600">{t('centralUsers.allTenants')}</span>
          </label>
          {!newGlobal && (
            <div className="flex flex-wrap gap-2">
              {tenants.map(tn => (
                <label key={tn} className="text-xs flex items-center gap-1 border border-slate-300 rounded px-2 py-1">
                  <input type="checkbox" checked={newTenants.includes(tn)}
                    onChange={e => setNewTenants(prev => e.target.checked ? [...prev, tn] : prev.filter(x => x !== tn))} />
                  {tn}
                </label>
              ))}
            </div>
          )}
          <div className="flex justify-end">
            <Button onClick={submit} variant="primary" disabled={submitting || !newUsername || !newPassword}>
              {t('common.save')}
            </Button>
          </div>
        </div>
      )}

      {err && <p className="text-sm text-red-600">{err}</p>}
      {loading ? (
        <p className="text-sm text-slate-500">{t('common.loading')}</p>
      ) : (
        <div className="divide-y divide-slate-100">
          {users.map(u => (
            <div key={u.id} className="py-2.5 flex items-center gap-3">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-sm font-medium text-slate-800">{u.username}</span>
                  <select value={u.role} onChange={e => changeRole(u, e.target.value as AuthRole)}
                    className="text-xs border border-slate-300 rounded px-1 py-0.5">
                    <option value="viewer">{t('auth.roleViewer')}</option>
                    <option value="admin">{t('auth.roleAdmin')}</option>
                  </select>
                  {!u.is_active && <Badge variant="gray" className="text-[10px]">{t('centralUsers.inactive')}</Badge>}
                  {u.totp_enabled ? (
                    <Badge variant="green" className="text-[10px] inline-flex items-center gap-1"><ShieldCheck size={9} /> {t('centralUsers.totpOn')}</Badge>
                  ) : (
                    <Badge variant="yellow" className="text-[10px]">{t('centralUsers.totpOff')}</Badge>
                  )}
                </div>
                <p className="text-[11px] text-slate-500 mt-0.5">
                  {t('centralUsers.lastLogin')}: {formatDate(u.last_login_at)}
                </p>
                {totpResult?.id === u.id && (
                  <div className="mt-1 text-[11px] bg-amber-50 border border-amber-200 rounded p-2">
                    <p className="text-amber-800">{t('centralUsers.totpResetHint')}</p>
                    <p className="font-mono break-all mt-1">{totpResult.secret}</p>
                  </div>
                )}
              </div>
              <div className="flex items-center gap-1 shrink-0">
                <button onClick={() => resetPassword(u)} title={t('centralUsers.resetPassword') as string}
                  className="text-slate-500 hover:text-indigo-600 p-1"><KeyRound size={14} /></button>
                <button onClick={() => resetTotp(u)} title={t('centralUsers.resetTotp') as string}
                  className="text-slate-500 hover:text-indigo-600 p-1"><ShieldCheck size={14} /></button>
                <button onClick={() => toggleActive(u)} className="text-xs text-slate-500 hover:text-indigo-600 px-1">
                  {u.is_active ? t('centralUsers.deactivate') : t('centralUsers.activate')}
                </button>
                <button onClick={() => del(u)} title={t('common.delete') as string}
                  className="text-slate-500 hover:text-red-600 p-1"><Trash2 size={14} /></button>
              </div>
            </div>
          ))}
          {users.length === 0 && <p className="text-sm text-slate-500 py-2">{t('centralUsers.empty')}</p>}
        </div>
      )}
    </div>
  )
}
