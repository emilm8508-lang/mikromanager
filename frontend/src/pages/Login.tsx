import { createContext, useContext, useEffect, useState, FormEvent, ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { AxiosError } from 'axios'
import { authApi, MfaSetupInfo } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Input } from '../components/ui/Input'
import { Button } from '../components/ui/Button'
import { ShieldCheck, Lock, AlertTriangle, Network } from 'lucide-react'

// ── Auth context — lets Sidebar show the username + a logout button ─────────

interface AuthContextValue {
  username: string
  logout: () => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside AuthGate')
  return ctx
}

function errorMessage(err: unknown, fallback: string): string {
  const e = err as AxiosError<{ detail?: string }>
  return e?.response?.data?.detail || fallback
}

type Step = 'loading' | 'connection-error' | 'setup-account' | 'resume-mfa' | 'setup-mfa' | 'login'

export function AuthGate({ children }: { children: ReactNode }) {
  const { t } = useTranslation()
  const [step, setStep] = useState<Step>('loading')
  const [username, setUsername] = useState('')

  // Carried between steps of the setup flow
  const [pendingUsername, setPendingUsername] = useState('')
  const [mfaInfo, setMfaInfo] = useState<MfaSetupInfo | null>(null)

  async function refreshFromStatus() {
    setStep('loading')
    try {
      const status = await authApi.status()
      if (!status.configured) {
        setStep(status.mfa_setup_pending ? 'resume-mfa' : 'setup-account')
        return
      }
      try {
        const me = await authApi.me()
        setUsername(me.username)
        setAuthed(true)
      } catch {
        setStep('login')
      }
    } catch {
      setStep('connection-error')
    }
  }

  const [authed, setAuthed] = useState(false)

  useEffect(() => { refreshFromStatus() }, [])

  function logout() {
    authApi.logout().finally(() => {
      setAuthed(false)
      refreshFromStatus()
    })
  }

  if (authed) {
    return <AuthContext.Provider value={{ username, logout }}>{children}</AuthContext.Provider>
  }

  return (
    <div className="h-screen w-full flex items-center justify-center bg-slate-50 px-4">
      <div className="w-full max-w-sm space-y-4">
        <div className="flex items-center justify-center gap-2.5 mb-2">
          <div className="w-9 h-9 bg-indigo-600 rounded-lg flex items-center justify-center">
            <Network size={18} className="text-white" />
          </div>
          <div>
            <p className="text-base font-bold text-slate-900 leading-none">{t('auth.title')}</p>
            <p className="text-[11px] text-slate-500 mt-0.5">{t('auth.subtitle')}</p>
          </div>
        </div>

        {step === 'loading' && (
          <Card><CardContent className="text-center text-sm text-slate-500 py-8">{t('auth.loading')}</CardContent></Card>
        )}

        {step === 'connection-error' && (
          <Card>
            <CardContent className="flex items-start gap-2 text-sm text-red-700 py-6">
              <AlertTriangle size={16} className="mt-0.5 shrink-0" />
              <span>{t('auth.errorConnection')}</span>
            </CardContent>
          </Card>
        )}

        {step === 'setup-account' && (
          <SetupAccountForm
            onDone={(uname, info) => { setPendingUsername(uname); setMfaInfo(info); setStep('setup-mfa') }}
          />
        )}

        {step === 'resume-mfa' && (
          <ResumeMfaForm
            onDone={(uname, info) => { setPendingUsername(uname); setMfaInfo(info); setStep('setup-mfa') }}
          />
        )}

        {step === 'setup-mfa' && mfaInfo && (
          <MfaConfirmForm
            info={mfaInfo}
            onConfirmed={() => { setUsername(pendingUsername); setAuthed(true) }}
          />
        )}

        {step === 'login' && (
          <LoginForm onLoggedIn={(uname) => { setUsername(uname); setAuthed(true) }} />
        )}
      </div>
    </div>
  )
}

// ── Step 1: create the account ───────────────────────────────────────────────

function SetupAccountForm({ onDone }: { onDone: (username: string, info: MfaSetupInfo) => void }) {
  const { t } = useTranslation()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [totpSecret, setTotpSecret] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError('')
    if (password.length < 8) { setError(t('auth.passwordTooShort') as string); return }
    if (password !== confirm) { setError(t('auth.passwordMismatch') as string); return }
    setBusy(true)
    try {
      const info = await authApi.setup(username, password, showAdvanced ? totpSecret : undefined)
      onDone(username, info)
    } catch (err) {
      setError(errorMessage(err, t('auth.genericError') as string))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Lock size={15} className="text-indigo-600" />
          <h2 className="text-sm font-semibold text-slate-700">{t('auth.setupTitle')}</h2>
        </div>
        <p className="text-xs text-slate-500 mt-1">{t('auth.setupSubtitle')}</p>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="space-y-3">
          <Input label={t('auth.username') as string} value={username}
            onChange={e => setUsername(e.target.value)} required autoFocus />
          <Input label={t('auth.password') as string} type="password" value={password}
            onChange={e => setPassword(e.target.value)} required minLength={8} />
          <Input label={t('auth.confirmPassword') as string} type="password" value={confirm}
            onChange={e => setConfirm(e.target.value)} required />

          <button
            type="button"
            onClick={() => setShowAdvanced(a => !a)}
            className="text-xs text-indigo-600 hover:text-indigo-500"
          >
            {showAdvanced ? t('auth.hideAdvanced') : t('auth.reuseSecretToggle')}
          </button>
          {showAdvanced && (
            <div className="space-y-1">
              <Input label={t('auth.reuseSecretLabel') as string} value={totpSecret}
                onChange={e => setTotpSecret(e.target.value)}
                placeholder="RC63HTOZD75QBACER6JWVUPFFANYUXFJ" />
              <p className="text-[11px] text-slate-500">{t('auth.reuseSecretHint')}</p>
            </div>
          )}

          {error && <p className="text-xs text-red-600">{error}</p>}
          <Button type="submit" variant="primary" className="w-full justify-center" disabled={busy}>
            {t('auth.continueButton')}
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}

// ── Alt step 1: resume an interrupted setup (account exists, MFA not confirmed) ──

function ResumeMfaForm({ onDone }: { onDone: (username: string, info: MfaSetupInfo) => void }) {
  const { t } = useTranslation()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError('')
    setBusy(true)
    try {
      const info = await authApi.setupResume(username, password)
      onDone(username, info)
    } catch (err) {
      setError(errorMessage(err, t('auth.genericError') as string))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <ShieldCheck size={15} className="text-amber-600" />
          <h2 className="text-sm font-semibold text-slate-700">{t('auth.resumeTitle')}</h2>
        </div>
        <p className="text-xs text-slate-500 mt-1">{t('auth.resumeSubtitle')}</p>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="space-y-3">
          <Input label={t('auth.username') as string} value={username}
            onChange={e => setUsername(e.target.value)} required autoFocus />
          <Input label={t('auth.password') as string} type="password" value={password}
            onChange={e => setPassword(e.target.value)} required />
          {error && <p className="text-xs text-red-600">{error}</p>}
          <Button type="submit" variant="primary" className="w-full justify-center" disabled={busy}>
            {t('auth.continueButton')}
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}

// ── Step 2: scan QR + confirm TOTP code ──────────────────────────────────────

function MfaConfirmForm({ info, onConfirmed }: { info: MfaSetupInfo; onConfirmed: () => void }) {
  const { t } = useTranslation()
  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError('')
    setBusy(true)
    try {
      await authApi.mfaConfirm(code)
      onConfirmed()
    } catch (err) {
      setError(errorMessage(err, t('auth.genericError') as string))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <ShieldCheck size={15} className="text-indigo-600" />
          <h2 className="text-sm font-semibold text-slate-700">{t('auth.mfaTitle')}</h2>
        </div>
        <p className="text-xs text-slate-500 mt-1">{t('auth.mfaSubtitle')}</p>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex justify-center bg-white border border-slate-200 rounded-lg p-3">
          <img src={info.qr_svg_data_uri} alt="TOTP QR code" className="w-40 h-40" />
        </div>
        <div>
          <p className="text-xs text-slate-500">{t('auth.mfaSecretLabel')}</p>
          <p className="font-mono text-xs text-slate-700 break-all bg-slate-100 rounded px-2 py-1 mt-1">
            {info.secret}
          </p>
        </div>
        <form onSubmit={submit} className="space-y-3">
          <Input label={t('auth.mfaCodeLabel') as string} value={code}
            onChange={e => setCode(e.target.value)}
            placeholder={t('auth.mfaCodePlaceholder') as string}
            inputMode="numeric" maxLength={6} required autoFocus
            autoComplete="one-time-code" autoCorrect="off" autoCapitalize="off" spellCheck={false}
            data-lpignore="true" data-1p-ignore="true" data-bwignore="true" data-form-type="other" />
          {error && <p className="text-xs text-red-600">{error}</p>}
          <Button type="submit" variant="primary" className="w-full justify-center" disabled={busy}>
            {t('auth.confirmButton')}
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}

// ── Normal login ──────────────────────────────────────────────────────────────

function LoginForm({ onLoggedIn }: { onLoggedIn: (username: string) => void }) {
  const { t } = useTranslation()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError('')
    setBusy(true)
    try {
      await authApi.login(username, password, totpCode)
      onLoggedIn(username)
    } catch (err) {
      const e2 = err as AxiosError<{ detail?: string }>
      if (e2?.response?.status === 429) {
        setError(e2.response.data?.detail || (t('auth.genericError') as string))
      } else {
        setError(t('auth.invalidCredentials') as string)
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Lock size={15} className="text-indigo-600" />
          <h2 className="text-sm font-semibold text-slate-700">{t('auth.loginTitle')}</h2>
        </div>
        <p className="text-xs text-slate-500 mt-1">{t('auth.loginSubtitle')}</p>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="space-y-3">
          <Input label={t('auth.username') as string} value={username}
            onChange={e => setUsername(e.target.value)} required autoFocus />
          <Input label={t('auth.password') as string} type="password" value={password}
            onChange={e => setPassword(e.target.value)} required />
          <Input label={t('auth.totpCode') as string} value={totpCode}
            onChange={e => setTotpCode(e.target.value)}
            placeholder={t('auth.mfaCodePlaceholder') as string}
            inputMode="numeric" maxLength={6} required
            autoComplete="one-time-code" autoCorrect="off" autoCapitalize="off" spellCheck={false}
            data-lpignore="true" data-1p-ignore="true" data-bwignore="true" data-form-type="other" />
          {error && <p className="text-xs text-red-600">{error}</p>}
          <Button type="submit" variant="primary" className="w-full justify-center" disabled={busy}>
            {t('auth.loginButton')}
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}
