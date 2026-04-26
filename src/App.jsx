import { useEffect, useMemo, useRef, useState } from 'react'
import { loadStripe } from '@stripe/stripe-js'

const SYSTEM_PROMPT = `You are an advanced fraud detection analyst specializing in device fingerprinting, behavioral biometrics, and anonymization detection.
Analyze the payload and return strict JSON:
{"cases":[{"session_id":"string","fraud_likelihood_score":0,"verdict":"low|medium|high|critical","signal_breakdown":{"device_fingerprint":[],"network_location":[],"behavioral_biometrics":[]},"red_flags":[],"recommended_action":"allow|step-up auth|manual review|block"}]}`

const EXAMPLE_DATA = [{ session_id: 'example_1', transaction: { amount: 249.99, currency: 'USD', payment_method: 'card' } }]
const TEST_CARDS = [
  '4242 4242 4242 4242 — Clean/legitimate',
  '4000 0000 0000 0002 — Always declined',
  '4000 0000 0000 9995 — Insufficient funds',
  '4000 0000 0000 0069 — Expired card',
  '4000 0025 0000 3155 — Triggers 3D Secure',
  '4000 0000 0000 0259 — Disputed/chargeback',
  '4000 0000 0000 1976 — Prepaid card',
  '4000 0000 0000 4954 — Always blocked by Stripe radar',
  '4000 0082 6000 0000 — High risk country card',
]
const ACTION_STYLE = {
  ALLOW: 'bg-emerald-600/20 text-emerald-200 border-emerald-500/50',
  'STEP-UP AUTH': 'bg-amber-600/20 text-amber-200 border-amber-500/50',
  'MANUAL REVIEW': 'bg-orange-600/20 text-orange-200 border-orange-500/50',
  BLOCK: 'bg-red-600/20 text-red-200 border-red-500/50',
  REPORT: 'bg-rose-700/30 text-rose-100 border-rose-500/60',
}

const clamp = (n) => Math.max(0, Math.min(100, Math.round(n)))
const riskColor = (s) => (s <= 20 ? 'text-emerald-400' : s <= 40 ? 'text-yellow-300' : s <= 60 ? 'text-orange-400' : s <= 80 ? 'text-red-400' : 'text-rose-500')
const toCases = (raw) => (Array.isArray(raw) ? raw : raw?.cases || [raw])

const STEP_STATUS_STYLE = {
  pending: 'border-slate-700 bg-slate-900 text-slate-300',
  in_progress: 'border-cyan-500/60 bg-cyan-500/10 text-cyan-200',
  passed: 'border-emerald-500/60 bg-emerald-500/10 text-emerald-200',
  failed: 'border-red-500/60 bg-red-500/10 text-red-200',
}

function parseModelJSON(text) {
  try {
    return JSON.parse(text)
  } catch {
    const s = text.indexOf('{')
    const e = text.lastIndexOf('}')
    if (s !== -1 && e !== -1) return JSON.parse(text.slice(s, e + 1))
    throw new Error('Model response was not valid JSON.')
  }
}

function applyOperationalEscalation(modelCases, inputCases) {
  const inputBySessionId = new Map((inputCases || []).filter((i) => i?.session_id).map((i) => [i.session_id, i]))
  return (modelCases || []).map((c) => {
    const src = inputBySessionId.get(c.session_id)
    if (!src) return c
    const shouldEscalate =
      src?.network?.vpn_proxy_tor === 'confirmed' &&
      Number(src?.network?.ip_reputation || 0) >= 80 &&
      Number(src?.behavior?.mouse_entropy_score || 1) <= 0.3 &&
      (src?.behavior?.copy_paste_fields || []).some((f) => ['cvv', 'card_number'].includes(String(f).toLowerCase()))
    if (!shouldEscalate) return c
    const ruleFlag = 'Auto-escalation: VPN/Tor + high IP risk + low entropy + sensitive-field paste.'
    return {
      ...c,
      fraud_likelihood_score: Math.max(Number(c.fraud_likelihood_score || 0), 90),
      verdict: 'critical',
      recommended_action: 'block',
      red_flags: [ruleFlag, ...(c.red_flags || [])],
    }
  })
}

function App() {
  const stripePk = import.meta.env.VITE_STRIPE_PUBLISHABLE_KEY ?? ''
  const [tab, setTab] = useState('json')
  const [jsonInput, setJsonInput] = useState('')
  const [results, setResults] = useState([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [hasServerKey, setHasServerKey] = useState(false)

  const [paymentLoading, setPaymentLoading] = useState(false)
  const [paymentError, setPaymentError] = useState('')
  const [paymentResult, setPaymentResult] = useState(null)
  const [history, setHistory] = useState([])
  const [selectedCardHint, setSelectedCardHint] = useState('')
  const [stripeInfo, setStripeInfo] = useState({ ready: false, complete: false, brand: '', error: '' })
  const [form, setForm] = useState({ amount: '129.99', cardholder: '', street: '', city: '', state: '', zip: '', billingCountry: 'US', ipCountry: 'US', sessionCountry: 'US' })

  const [approvalInput, setApprovalInput] = useState('')
  const [approvalCase, setApprovalCase] = useState(null)
  const [approvalError, setApprovalError] = useState('')
  const [approvalLoading, setApprovalLoading] = useState(false)
  const [otpPhone, setOtpPhone] = useState('')
  const [otpCode, setOtpCode] = useState('')
  const [otpSid, setOtpSid] = useState('')
  const [mercuryResult, setMercuryResult] = useState(null)
  const [steps, setSteps] = useState([
    { key: 'fraud', name: 'Fraud Pre-Screen', status: 'pending', signals: [], completedAt: '' },
    { key: 'identity', name: 'Stripe Identity', status: 'pending', signals: [], completedAt: '' },
    { key: 'bank', name: 'Plaid Bank Confirmation', status: 'pending', signals: [], completedAt: '' },
    { key: 'sms', name: 'Twilio SMS Verify', status: 'pending', signals: [], completedAt: '' },
  ])

  const stripeRef = useRef(null)
  const cardRef = useRef(null)
  const expRef = useRef(null)
  const cvcRef = useRef(null)
  const cardElRef = useRef(null)
  const expElRef = useRef(null)
  const cvcElRef = useRef(null)
  const velocityRef = useRef(new Map())

  const sorted = useMemo(() => [...results].sort((a, b) => (b.fraud_likelihood_score ?? 0) - (a.fraud_likelihood_score ?? 0)), [results])
  const progress = useMemo(() => Math.round((steps.filter((s) => s.status === 'passed' || s.status === 'failed').length / steps.length) * 100), [steps])

  const refreshKeyStatus = async () => {
    try {
      const res = await fetch('/api/status')
      const data = await res.json()
      setHasServerKey(Boolean(data.hasKey))
    } catch {
      setHasServerKey(false)
    }
  }

  useEffect(() => {
    refreshKeyStatus()
  }, [])

  useEffect(() => {
    let dead = false
    const init = async () => {
      if (!stripePk) {
        setStripeInfo((p) => ({ ...p, error: 'Missing VITE_STRIPE_PUBLISHABLE_KEY in .env.local' }))
        return
      }
      const stripe = await loadStripe(stripePk)
      if (!stripe || dead) return
      stripeRef.current = stripe
      const elements = stripe.elements()
      const baseStyle = { color: '#e2e8f0', fontSize: '14px', '::placeholder': { color: '#64748b' } }
      const card = elements.create('cardNumber', { style: { base: baseStyle } })
      const exp = elements.create('cardExpiry', { style: { base: baseStyle } })
      const cvc = elements.create('cardCvc', { style: { base: baseStyle } })
      if (cardRef.current) card.mount(cardRef.current)
      if (expRef.current) exp.mount(expRef.current)
      if (cvcRef.current) cvc.mount(cvcRef.current)
      card.on('change', (e) => setStripeInfo((p) => ({ ...p, complete: e.complete, brand: e.brand || '', error: e.error?.message || '' })))
      exp.on('change', (e) => setStripeInfo((p) => ({ ...p, error: e.error?.message || '' })))
      cvc.on('change', (e) => setStripeInfo((p) => ({ ...p, error: e.error?.message || '' })))
      cardElRef.current = card
      expElRef.current = exp
      cvcElRef.current = cvc
      setStripeInfo((p) => ({ ...p, ready: true, error: '' }))
    }
    init()
    return () => {
      dead = true
      if (cardElRef.current) cardElRef.current.destroy()
      if (expElRef.current) expElRef.current.destroy()
      if (cvcElRef.current) cvcElRef.current.destroy()
    }
  }, [stripePk])

  const analyzeCases = async (cases) => {
    if (!hasServerKey) throw new Error('Missing API key in .env.local')
    const response = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1500,
        system: SYSTEM_PROMPT,
        messages: [{ role: 'user', content: `Analyze:\n${JSON.stringify(cases, null, 2)}` }],
      }),
    })
    if (!response.ok) throw new Error(await response.text())
    const body = await response.json()
    return parseModelJSON(body?.content?.[0]?.text || '{}')
  }

  const updateStep = (key, next) => {
    setSteps((prev) =>
      prev.map((s) =>
        s.key === key
          ? { ...s, ...next, completedAt: next.status === 'passed' || next.status === 'failed' ? new Date().toLocaleTimeString() : s.completedAt }
          : s,
      ),
    )
  }

  const resetApprovalSteps = () => {
    setSteps((prev) => prev.map((s) => ({ ...s, status: 'pending', signals: [], completedAt: '' })))
    setMercuryResult(null)
    setOtpSid('')
  }

  const analyzeJson = async () => {
    try {
      const parsed = JSON.parse(jsonInput)
      const cases = toCases(parsed)
      if (cases.length > 10) throw new Error('Supports up to 10 cases')
      setLoading(true)
      setError('')
      const output = await analyzeCases(cases)
      setResults(applyOperationalEscalation(output?.cases || [], cases))
    } catch (err) {
      setError(err.message || 'Invalid JSON')
    } finally {
      setLoading(false)
    }
  }

  const computeStripeSignals = (token) => {
    const card = token.card || {}
    const last4 = card.last4 || ''
    const funding = card.funding || (last4 === '1976' ? 'prepaid' : 'credit')
    const cardCountry = card.country || (last4 === '0000' ? 'NG' : 'US')
    const fingerprint = card.fingerprint || token.id
    const attempts = (velocityRef.current.get(fingerprint) || 0) + 1
    velocityRef.current.set(fingerprint, attempts)
    const declined = ['0002', '9995', '0069', '4954'].includes(last4)
    const threeDS = last4 === '3155'
    const chargeback = last4 === '0259'
    const radar = last4 === '4954'
    const highRisk = ['NG', 'RU', 'BY', 'IR', 'KP'].includes(cardCountry)
    const flags = []
    let score = 8
    if (funding === 'prepaid') { score += 25; flags.push('Prepaid card detected (+25)') }
    if (cardCountry !== form.ipCountry.toUpperCase()) { score += 20; flags.push('Card country vs IP mismatch (+20)') }
    if (cardCountry !== form.billingCountry.toUpperCase()) { score += 20; flags.push('Card country vs billing mismatch (+20)') }
    if (radar) { score += 30; flags.push('Stripe elevated risk flag (+30)') }
    if (threeDS) { score += 15; flags.push('3D Secure triggered (+15)') }
    if (attempts >= 3) { score += 35; flags.push('Velocity 3+ attempts (+35)') }
    if (chargeback) { score += 40; flags.push('Chargeback history (+40)') }
    if (funding === 'corporate') { score += 10; flags.push('Corporate card on consumer site (+10)') }
    if (highRisk) { score += 25; flags.push('High-risk country origin (+25)') }
    if (declined && attempts > 1) { score += 20; flags.push('Card declined then retried (+20)') }
    if (cardCountry !== form.sessionCountry.toUpperCase()) flags.push('BIN country vs session country mismatch')
    return {
      stripeRiskScore: clamp(score),
      stripeSignals: {
        card_type: card.brand || 'unknown',
        card_country: cardCountry,
        card_funding: funding,
        three_d_secure_triggered: threeDS,
        authorization_response_code: declined ? 'declined' : 'authorized',
        stripe_network_new_card: attempts === 1,
        decline_reason: last4 === '0002' ? 'card_declined' : last4 === '9995' ? 'insufficient_funds' : last4 === '0069' ? 'expired_card' : last4 === '4954' ? 'blocked_by_radar' : null,
        chargeback_history: chargeback,
        velocity_attempts: attempts,
      },
      stripeFlags: flags,
    }
  }

  const runPaymentTest = async () => {
    try {
      setPaymentLoading(true)
      setPaymentError('')
      setPaymentResult(null)
      if (!stripeInfo.ready || !stripeRef.current || !cardElRef.current) throw new Error('Stripe not initialized')
      if (!stripeInfo.complete) throw new Error('Complete card number, expiry, and CVV first')
      const tokenResult = await stripeRef.current.createToken(cardElRef.current, {
        name: form.cardholder,
        address_line1: form.street,
        address_city: form.city,
        address_state: form.state,
        address_zip: form.zip,
        address_country: form.billingCountry,
      })
      if (tokenResult.error) throw new Error(tokenResult.error.message || 'Tokenization failed')
      const stripeComputed = computeStripeSignals(tokenResult.token)
      const aiOutput = await analyzeCases([{
        session_id: `payment_${Date.now()}`,
        network: { ip_geo: form.ipCountry },
        transaction: {
          amount: Number(form.amount),
          currency: 'USD',
          payment_method: 'card',
          stripe_token_id: tokenResult.token.id,
          stripe_risk_score: stripeComputed.stripeRiskScore,
          stripe_signals: stripeComputed.stripeSignals,
        },
      }])
      const aiResult = aiOutput?.cases?.[0] || {}
      const aiScore = clamp(aiResult.fraud_likelihood_score || stripeComputed.stripeRiskScore)
      const combined = clamp((stripeComputed.stripeRiskScore * 0.4) + (aiScore * 0.6))
      const verdict = combined <= 20 ? 'ALLOW' : combined <= 40 ? 'LOW RISK' : combined <= 60 ? 'SUSPICIOUS' : combined <= 80 ? 'HIGH RISK' : 'CRITICAL'
      const action = combined > 90 && stripeComputed.stripeSignals.chargeback_history ? 'REPORT' : combined > 80 ? 'BLOCK' : combined > 60 ? 'MANUAL REVIEW' : combined > 40 ? 'STEP-UP AUTH' : 'ALLOW'
      const caughtBy = stripeComputed.stripeRiskScore > 60 && aiScore > 60 ? 'Both' : stripeComputed.stripeRiskScore > aiScore ? 'Stripe' : 'AI'
      const topFlags = [...stripeComputed.stripeFlags, ...(aiResult.red_flags || [])].slice(0, 5)
      const out = { stripeRiskScore: stripeComputed.stripeRiskScore, aiFraudScore: aiScore, combinedFinalScore: combined, verdict, action, caughtBy, topFlags, stripeSignals: stripeComputed.stripeSignals, aiSignals: aiResult, token: { id: tokenResult.token.id, brand: tokenResult.token.card?.brand, last4: tokenResult.token.card?.last4 } }
      setPaymentResult(out)
      setHistory((prev) => [out, ...prev].slice(0, 20))
    } catch (err) {
      setPaymentError(err.message || 'Payment test failed')
    } finally {
      setPaymentLoading(false)
    }
  }

  const exportCase = () => {
    if (!paymentResult) return
    const blob = new Blob([JSON.stringify(paymentResult, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `fraud-case-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const runApprovalPrescreen = async () => {
    try {
      setApprovalError('')
      setApprovalLoading(true)
      resetApprovalSteps()
      const parsed = JSON.parse(approvalInput)
      const one = toCases(parsed)[0]
      if (!one) throw new Error('Provide one transaction JSON object')
      setApprovalCase(one)
      updateStep('fraud', { status: 'in_progress' })
      const out = await analyzeCases([one])
      const result = applyOperationalEscalation(out?.cases || [], [one])[0]
      const score = Number(result?.fraud_likelihood_score || 0)
      const signals = [`AI score: ${score}`]
      if (score >= 61) {
        signals.push('Auto-block threshold reached (61+)')
        updateStep('fraud', { status: 'failed', signals })
        updateStep('identity', { status: 'failed', signals: ['Skipped due to auto-block'] })
        updateStep('bank', { status: 'failed', signals: ['Skipped due to auto-block'] })
        updateStep('sms', { status: 'failed', signals: ['Skipped due to auto-block'] })
      } else {
        updateStep('fraud', { status: 'passed', signals: [...signals, score <= 20 ? 'Low-risk pre-screen passed' : 'Step-up required (21-60)'] })
      }
      setApprovalCase((prev) => ({ ...prev, fraudResult: result }))
    } catch (err) {
      setApprovalError(err.message || 'Pre-screen failed')
    } finally {
      setApprovalLoading(false)
    }
  }

  const runIdentityCheck = async () => {
    if (!approvalCase?.fraudResult) return
    updateStep('identity', { status: 'in_progress' })
    await new Promise((r) => setTimeout(r, 700))
    const billingName = String(approvalCase?.transaction?.billing_name || '').trim().toLowerCase()
    const txName = String(approvalCase?.claimed_name || approvalCase?.user_name || approvalCase?.transaction?.customer_name || '').trim().toLowerCase()
    const mismatch = billingName && txName && billingName !== txName
    const expiredDoc = String(approvalCase?.identity?.id_status || '').toLowerCase() === 'expired'
    const failed = mismatch || expiredDoc
    updateStep('identity', {
      status: failed ? 'failed' : 'passed',
      signals: failed ? ['ID verification failed', mismatch ? 'Name mismatch with billing details' : 'ID expired'] : ['Document uploaded', 'Selfie matches ID', 'ID not expired'],
    })
  }

  const runBankCheck = async () => {
    if (!approvalCase?.fraudResult) return
    updateStep('bank', { status: 'in_progress' })
    await new Promise((r) => setTimeout(r, 700))
    const amount = Number(approvalCase?.transaction?.amount || 0)
    const simulatedBalance = Number(approvalCase?.bank?.simulated_balance || 5000)
    const mismatch = String(approvalCase?.bank?.account_holder_match || '').toLowerCase() === 'false'
    const inactive = String(approvalCase?.bank?.status || '').toLowerCase() === 'inactive'
    let status = 'confirmed'
    if (inactive) status = 'failed'
    else if (mismatch) status = 'mismatch'
    else if (simulatedBalance < amount) status = 'insufficient_funds'
    const failed = status !== 'confirmed'
    updateStep('bank', {
      status: failed ? 'failed' : 'passed',
      signals: failed ? [`Bank verification: ${status}`] : ['Plaid Link connected', 'Account active', 'Sufficient balance'],
    })
  }

  const sendOtp = async () => {
    try {
      updateStep('sms', { status: 'in_progress', signals: ['Sending OTP...'] })
      const response = await fetch('http://localhost:3001/api/send-otp', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ phone: otpPhone }),
      })
      const data = await response.json()
      if (!response.ok) throw new Error(data.error || 'OTP send failed')
      setOtpSid(data.verificationSid || '')
      updateStep('sms', { status: 'in_progress', signals: ['OTP sent', 'Waiting for code verification'] })
    } catch (err) {
      updateStep('sms', { status: 'failed', signals: [err.message || 'OTP send failed'] })
      setApprovalError(err.message || 'OTP send failed')
    }
  }

  const verifyOtp = async () => {
    try {
      const response = await fetch('http://localhost:3001/api/verify-otp', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ phone: otpPhone, code: otpCode, sid: otpSid }),
      })
      const data = await response.json()
      if (!response.ok) throw new Error(data.error || 'OTP verify failed')
      const passed = data.status === 'verified'
      updateStep('sms', { status: passed ? 'passed' : 'failed', signals: [passed ? 'OTP verified' : `OTP status: ${data.status || 'failed'}`] })
    } catch (err) {
      updateStep('sms', { status: 'failed', signals: [err.message || 'OTP verify failed'] })
      setApprovalError(err.message || 'OTP verify failed')
    }
  }

  const approvalDecision = useMemo(() => {
    const identity = steps.find((s) => s.key === 'identity')
    const bank = steps.find((s) => s.key === 'bank')
    const sms = steps.find((s) => s.key === 'sms')
    const fraudScore = Number(approvalCase?.fraudResult?.fraud_likelihood_score || 0)
    const fraudSignal = clamp(100 - fraudScore)
    const idSignal = identity?.status === 'passed' ? 100 : identity?.status === 'failed' ? 20 : 50
    const bankSignal = bank?.status === 'passed' ? 100 : bank?.status === 'failed' ? 20 : 50
    const smsSignal = sms?.status === 'passed' ? 100 : sms?.status === 'failed' ? 20 : 50
    const confidence = clamp(fraudSignal * 0.4 + idSignal * 0.25 + bankSignal * 0.2 + smsSignal * 0.15)
    const failedCount = steps.filter((s) => s.status === 'failed').length
    let verdict = 'PENDING'
    if (fraudScore >= 61) verdict = 'BLOCKED'
    else if (identity?.status === 'failed' || bank?.status === 'failed') verdict = 'REJECTED'
    else if (failedCount >= 2) verdict = 'MANUAL REVIEW'
    else if (failedCount === 1) verdict = 'CONDITIONAL APPROVE'
    else if (steps.every((s) => s.status === 'passed')) verdict = 'APPROVED'
    const action =
      verdict === 'APPROVED' ? 'ALLOW' :
      verdict === 'CONDITIONAL APPROVE' ? 'STEP-UP AUTH' :
      verdict === 'MANUAL REVIEW' ? 'MANUAL REVIEW' :
      verdict === 'REJECTED' || verdict === 'BLOCKED' ? 'BLOCK' : 'MANUAL REVIEW'
    return { verdict, confidence, action, passed: steps.filter((s) => s.status === 'passed').map((s) => s.name), failed: steps.filter((s) => s.status === 'failed').map((s) => s.name) }
  }, [steps, approvalCase])

  const approveToMercury = async () => {
    try {
      const response = await fetch('http://localhost:3001/api/approve-payment', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ transaction: approvalCase?.transaction || {}, decision: approvalDecision }),
      })
      const data = await response.json()
      if (!response.ok) throw new Error(data.error || 'Mercury approval failed')
      setMercuryResult(data)
      setHistory((prev) => [{ combinedFinalScore: approvalDecision.confidence, verdict: approvalDecision.verdict, action: approvalDecision.action, token: { id: data.confirmationNumber || `approval_${Date.now()}` } }, ...prev].slice(0, 20))
    } catch (err) {
      setApprovalError(err.message || 'Mercury approval failed')
    }
  }

  return (
    <main className="min-h-screen bg-slate-950 p-6 text-slate-100 md:p-10">
      <div className="mx-auto max-w-7xl space-y-6">
        <header className="rounded-2xl border border-slate-800 bg-panel p-6 shadow-2xl shadow-black/30">
          <h1 className="text-3xl font-semibold tracking-tight">Fraud Detection Command Center</h1>
          <p className="mt-2 text-sm text-slate-400">Dark-theme fraud operations dashboard with payment and approval tooling.</p>
          <div className="mt-4 flex flex-wrap gap-2">
            {[
              ['json', 'Tab 1: JSON Batch Analyzer'],
              ['payment', 'Tab 2: Payment Signal Tester'],
              ['history', 'Tab 3: Case History'],
              ['approval', 'Tab 4: Approval Engine'],
            ].map(([id, label]) => (
              <button key={id} onClick={() => setTab(id)} className={`rounded-lg px-3 py-1.5 text-sm ${tab === id ? 'bg-cyan-600 text-white' : 'bg-slate-800 text-slate-300 hover:bg-slate-700'}`}>{label}</button>
            ))}
          </div>
        </header>

        {tab === 'json' && (
          <>
            <section className="grid gap-4 rounded-2xl border border-slate-800 bg-panel p-6 lg:grid-cols-3">
              <div className="lg:col-span-2">
                <label className="mb-2 block text-sm font-medium text-slate-300">JSON Input</label>
                <textarea value={jsonInput} onChange={(e) => setJsonInput(e.target.value)} className="h-56 w-full rounded-xl border border-slate-700 bg-slate-900 p-3 font-mono text-xs text-slate-200" placeholder="Paste transaction object or array..." />
                <div className="mt-3 flex gap-2">
                  <button onClick={() => setJsonInput(JSON.stringify(EXAMPLE_DATA, null, 2))} className="rounded-lg border border-slate-600 bg-slate-800 px-3 py-1.5 text-xs">Load Example Data</button>
                  <button onClick={() => { setJsonInput(''); setResults([]); setError('') }} className="rounded-lg border border-slate-600 bg-slate-800 px-3 py-1.5 text-xs">Clear</button>
                </div>
                <div className="mt-4 rounded-xl border border-slate-700 bg-slate-900/80 p-3 text-xs text-slate-300">Root can be object, array, or `{`"cases": [...]`}` with `session_id`, `device`, `network`, `behavior`, `transaction`.</div>
              </div>
              <div className="space-y-4">
                <div className="rounded-xl border border-slate-700 bg-slate-900 p-3"><p className="text-xs text-slate-400">Status</p><p className="text-sm">{loading ? 'Analyzing...' : results.length ? 'Complete' : hasServerKey ? 'Ready' : 'Missing API key in .env.local'}</p></div>
                <div className="rounded-xl border border-slate-700 bg-slate-900 p-3 text-xs text-slate-300">Using `.env.local`: `ANTHROPIC_API_KEY` or `VITE_ANTHROPIC_API_KEY`<button onClick={refreshKeyStatus} className="mt-2 block rounded border border-slate-600 bg-slate-800 px-2 py-1">Re-check key status</button></div>
                <button onClick={analyzeJson} disabled={loading} className="w-full rounded-xl bg-cyan-600 px-4 py-2 font-medium text-white">{loading ? 'Analyzing...' : 'Analyze Transactions'}</button>
                <p className="text-xs text-slate-400">Supports single transactions or batch arrays up to 10 cases</p>
              </div>
            </section>
            {error && <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200">{error}</div>}
            {results.length > 1 && (
              <section className="rounded-2xl border border-slate-800 bg-panel p-6">
                <h2 className="text-xl font-semibold">Comparison View</h2>
                <div className="mt-4 grid gap-3 md:grid-cols-2 lg:grid-cols-4">
                  {sorted.map((item) => (
                    <div key={item.session_id} className="rounded-xl border border-slate-700 bg-slate-900 p-4"><p className="truncate text-xs text-slate-400">{item.session_id}</p><p className={`mt-2 text-3xl font-bold ${riskColor(item.fraud_likelihood_score ?? 0)}`}>{item.fraud_likelihood_score ?? 0}</p><p className="mt-1 text-xs text-slate-400">{item.verdict}</p></div>
                  ))}
                </div>
              </section>
            )}
            {results.length > 0 && (
              <section className="grid gap-4 lg:grid-cols-2">
                {results.map((result) => (
                  <article key={result.session_id} className="rounded-2xl border border-slate-800 bg-panel p-6">
                    <div className="flex items-start justify-between gap-3"><div><h3 className="text-lg font-semibold">{result.session_id || 'Session'}</h3><p className="mt-1 text-sm text-slate-400">AI risk decision</p></div><span className="rounded-full border border-slate-600 bg-slate-800 px-3 py-1 text-xs font-semibold uppercase text-slate-200">{result.verdict || 'unknown'}</span></div>
                    <div className="mt-4 rounded-xl border border-slate-700 bg-slate-900 p-4"><p className="text-xs uppercase tracking-wide text-slate-400">Risk Score</p><p className={`mt-1 text-6xl font-bold ${riskColor(result.fraud_likelihood_score ?? 0)}`}>{result.fraud_likelihood_score ?? 0}</p></div>
                    <div className="mt-5 space-y-4">
                      <div><h4 className="text-sm font-semibold text-slate-300">Signal Breakdown</h4><ul className="mt-2 space-y-2 text-sm text-slate-200"><li><span className="mr-2">🖥️</span>{(result.signal_breakdown?.device_fingerprint ?? []).join(' • ') || 'No device signals'}</li><li><span className="mr-2">🌐</span>{(result.signal_breakdown?.network_location ?? []).join(' • ') || 'No network signals'}</li><li><span className="mr-2">🧠</span>{(result.signal_breakdown?.behavioral_biometrics ?? []).join(' • ') || 'No behavior signals'}</li></ul></div>
                      <div><h4 className="text-sm font-semibold text-slate-300">Red Flags</h4><ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-red-200">{(result.red_flags ?? []).map((flag) => <li key={flag}>{flag}</li>)}{!result.red_flags?.length && <li className="text-slate-400">No red flags listed.</li>}</ul></div>
                      <button className="w-full rounded-xl bg-rose-700 px-4 py-2 text-sm font-semibold uppercase tracking-wide text-white hover:bg-rose-600">Recommended: {result.recommended_action ?? 'manual review'}</button>
                    </div>
                  </article>
                ))}
              </section>
            )}
          </>
        )}

        {tab === 'payment' && (
          <>
            <section className="grid gap-4 lg:grid-cols-2">
              <div className="space-y-4 rounded-2xl border border-slate-800 bg-panel p-6">
                <h2 className="text-xl font-semibold">Payment Signal Tester</h2>
                <p className="text-sm text-slate-400">Raw card number never enters application state. Stripe Elements tokenizes first.</p>
                <div className="grid gap-3 md:grid-cols-2">
                  <input className="rounded-xl border border-slate-700 bg-slate-900 p-2 text-sm" placeholder="Amount USD" value={form.amount} onChange={(e) => setForm((p) => ({ ...p, amount: e.target.value }))} />
                  <input className="rounded-xl border border-slate-700 bg-slate-900 p-2 text-sm" placeholder="Cardholder name" value={form.cardholder} onChange={(e) => setForm((p) => ({ ...p, cardholder: e.target.value }))} />
                </div>

                <div className="rounded-xl border border-slate-700 bg-slate-900 p-3 transition-all duration-200">
                  <p className="mb-2 text-xs text-slate-400">Card number</p>
                  <div ref={cardRef} className="rounded-lg border border-slate-600 bg-slate-950 p-3" />
                </div>

                <div className="grid gap-3 md:grid-cols-2">
                  <div className="rounded-xl border border-slate-700 bg-slate-900 p-3">
                    <p className="mb-2 text-xs text-slate-400">Expiry (MM/YY)</p>
                    <div ref={expRef} className="rounded-lg border border-slate-600 bg-slate-950 p-3" />
                  </div>
                  <div className="rounded-xl border border-slate-700 bg-slate-900 p-3">
                    <p className="mb-2 text-xs text-slate-400">CVV</p>
                    <div ref={cvcRef} className="rounded-lg border border-slate-600 bg-slate-950 p-3" />
                  </div>
                </div>

                <div className="grid gap-3 md:grid-cols-2">
                  <input className="rounded-xl border border-slate-700 bg-slate-900 p-2 text-sm" placeholder="Street" value={form.street} onChange={(e) => setForm((p) => ({ ...p, street: e.target.value }))} />
                  <input className="rounded-xl border border-slate-700 bg-slate-900 p-2 text-sm" placeholder="City" value={form.city} onChange={(e) => setForm((p) => ({ ...p, city: e.target.value }))} />
                  <input className="rounded-xl border border-slate-700 bg-slate-900 p-2 text-sm" placeholder="State" value={form.state} onChange={(e) => setForm((p) => ({ ...p, state: e.target.value }))} />
                  <input className="rounded-xl border border-slate-700 bg-slate-900 p-2 text-sm" placeholder="ZIP" value={form.zip} onChange={(e) => setForm((p) => ({ ...p, zip: e.target.value }))} />
                  <input className="rounded-xl border border-slate-700 bg-slate-900 p-2 text-sm" placeholder="Billing country (ISO2)" value={form.billingCountry} onChange={(e) => setForm((p) => ({ ...p, billingCountry: e.target.value.toUpperCase() }))} />
                  <input className="rounded-xl border border-slate-700 bg-slate-900 p-2 text-sm" placeholder="IP country (ISO2)" value={form.ipCountry} onChange={(e) => setForm((p) => ({ ...p, ipCountry: e.target.value.toUpperCase() }))} />
                </div>
                <input className="rounded-xl border border-slate-700 bg-slate-900 p-2 text-sm" placeholder="Session country (ISO2)" value={form.sessionCountry} onChange={(e) => setForm((p) => ({ ...p, sessionCountry: e.target.value.toUpperCase() }))} />

                <div className="rounded-xl border border-slate-700 bg-slate-900 p-3">
                  <p className="mb-2 text-xs text-slate-400">Stripe test card shortcuts</p>
                  <div className="grid gap-2 md:grid-cols-2">
                    {TEST_CARDS.map((card) => (
                      <button key={card} onClick={() => setSelectedCardHint(card)} className="rounded-lg border border-slate-600 bg-slate-800 px-2 py-1.5 text-left text-xs hover:bg-slate-700">
                        {card}
                      </button>
                    ))}
                  </div>
                  <p className="mt-2 text-xs text-cyan-300">{selectedCardHint || 'Select a test card, then type it into Stripe card field.'}</p>
                </div>

                <button onClick={runPaymentTest} disabled={paymentLoading || !stripeInfo.ready} className="w-full rounded-xl bg-cyan-600 px-4 py-2 font-semibold text-white">
                  {paymentLoading ? 'Testing Transaction...' : 'Test Transaction'}
                </button>
                {paymentError && <p className="text-sm text-red-300">{paymentError}</p>}
              </div>

              <div className="space-y-4 rounded-2xl border border-slate-800 bg-panel p-6">
                <h3 className="text-lg font-semibold">Live Signal Analysis</h3>
                <div className="rounded-xl border border-slate-700 bg-slate-900 p-4">
                  <p className="text-sm">Stripe ready: {stripeInfo.ready ? 'Yes' : 'No'}</p>
                  <p className="text-sm">Card complete: {stripeInfo.complete ? 'Yes' : 'No'}</p>
                  <p className="text-sm">Brand detected: {stripeInfo.brand || 'Unknown'}</p>
                  <p className="text-sm text-amber-300">{stripeInfo.error || 'No entry errors detected.'}</p>
                </div>
                <div className="rounded-xl border border-slate-700 bg-slate-900 p-4 text-sm">
                  <p className="text-emerald-300">Green = clean signal</p>
                  <p className="text-amber-300">Amber = warning signal</p>
                  <p className="text-red-300">Red = critical signal</p>
                </div>
              </div>
            </section>
            {paymentResult && (
              <section className="space-y-4 rounded-2xl border border-slate-800 bg-panel p-6">
                <h3 className="text-xl font-semibold">Combined Final Verdict Card</h3>
                <div className="grid gap-4 md:grid-cols-3"><div className="rounded-xl border border-slate-700 bg-slate-900 p-4"><p className="text-xs text-slate-400">Stripe Risk Score</p><p className={`text-5xl font-bold ${riskColor(paymentResult.stripeRiskScore)}`}>{paymentResult.stripeRiskScore}</p></div><div className="rounded-xl border border-slate-700 bg-slate-900 p-4"><p className="text-xs text-slate-400">AI Fraud Score</p><p className={`text-5xl font-bold ${riskColor(paymentResult.aiFraudScore)}`}>{paymentResult.aiFraudScore}</p></div><div className={`rounded-xl border border-slate-700 bg-slate-900 p-4 ${paymentResult.combinedFinalScore > 80 ? 'animate-pulse' : ''}`}><p className="text-xs text-slate-400">Combined Final Score</p><p className={`text-5xl font-bold ${riskColor(paymentResult.combinedFinalScore)}`}>{paymentResult.combinedFinalScore}</p></div></div>
                <div className="grid gap-4 lg:grid-cols-2"><div className={`rounded-xl border p-4 ${ACTION_STYLE[paymentResult.action] || 'border-slate-600'}`}><p className="text-sm">Verdict badge: <span className="font-semibold">{paymentResult.verdict}</span></p><p className="text-sm">Caught by: <span className="font-semibold">{paymentResult.caughtBy}</span></p><p className="text-sm">Recommended action: <span className="font-semibold">{paymentResult.action}</span></p><button onClick={exportCase} className="mt-3 rounded-lg border border-slate-500 bg-slate-800 px-3 py-1.5 text-xs">Export case (JSON report)</button></div><div className="rounded-xl border border-slate-700 bg-slate-900 p-4"><p className="text-sm font-semibold">Top 5 red flags</p><ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-red-200">{paymentResult.topFlags.map((flag) => <li key={flag}>{flag}</li>)}</ul></div></div>
                <div className="grid gap-4 lg:grid-cols-2"><div className="rounded-xl border border-slate-700 bg-slate-900 p-4"><p className="text-sm font-semibold">Stripe signals</p><pre className="mt-2 overflow-x-auto text-xs">{JSON.stringify(paymentResult.stripeSignals, null, 2)}</pre></div><div className="rounded-xl border border-slate-700 bg-slate-900 p-4"><p className="text-sm font-semibold">AI signals</p><pre className="mt-2 overflow-x-auto text-xs">{JSON.stringify(paymentResult.aiSignals, null, 2)}</pre></div></div>
              </section>
            )}
          </>
        )}

        {tab === 'history' && (
          <section className="rounded-2xl border border-slate-800 bg-panel p-6">
            <h2 className="text-xl font-semibold">Case History (future)</h2>
            <p className="mt-1 text-sm text-slate-400">Placeholder tab for persistent history. Showing in-memory recent tests for now.</p>
            <div className="mt-4 space-y-2">
              {history.length === 0 ? <p className="text-sm text-slate-500">No payment test cases yet.</p> : history.map((h, i) => <div key={`${h.token?.id || 'case'}-${i}`} className="rounded-xl border border-slate-700 bg-slate-900 p-3 text-sm">Combined {h.combinedFinalScore} | {h.verdict} | {h.action}</div>)}
            </div>
          </section>
        )}

        {tab === 'approval' && (
          <section className="space-y-4 rounded-2xl border border-slate-800 bg-panel p-6">
            <div className="grid gap-4 lg:grid-cols-2">
              <div className="rounded-xl border border-slate-700 bg-slate-900 p-4">
                <h2 className="text-lg font-semibold">Approval Engine Input</h2>
                <textarea value={approvalInput} onChange={(e) => setApprovalInput(e.target.value)} className="mt-3 h-48 w-full rounded-lg border border-slate-700 bg-slate-950 p-3 font-mono text-xs" placeholder="Paste one transaction JSON..." />
                <div className="mt-3 flex gap-2">
                  <button onClick={() => setApprovalInput(JSON.stringify(EXAMPLE_DATA[0], null, 2))} className="rounded-lg border border-slate-600 bg-slate-800 px-3 py-1.5 text-xs">Load Example</button>
                  <button onClick={runApprovalPrescreen} disabled={approvalLoading} className="rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-semibold text-white">{approvalLoading ? 'Running...' : 'Run Pre-Screen'}</button>
                </div>
                {approvalError && <p className="mt-2 text-xs text-red-300">{approvalError}</p>}
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-900 p-4">
                <h3 className="text-lg font-semibold">Top Summary</h3>
                <p className="mt-2 text-sm">Overall approval status: <span className={`font-semibold ${riskColor(100 - approvalDecision.confidence)}`}>{approvalDecision.verdict}</span></p>
                <p className="text-sm">Confidence score: {approvalDecision.confidence}</p>
                <div className="mt-3 h-2 w-full overflow-hidden rounded bg-slate-800">
                  <div className="h-full bg-cyan-500 transition-all duration-500" style={{ width: `${progress}%` }} />
                </div>
                <p className="mt-2 text-xs text-slate-400">Progress tracker: {progress}% complete</p>
              </div>
            </div>

            <div className="grid gap-4 lg:grid-cols-2">
              <div className="space-y-3">
                {steps.map((step, idx) => (
                  <div key={step.key} className={`rounded-xl border p-4 transition-all duration-300 ${STEP_STATUS_STYLE[step.status] || STEP_STATUS_STYLE.pending}`}>
                    <p className="text-sm font-semibold">Step {idx + 1} — {step.name}</p>
                    <p className="text-xs uppercase">{step.status.replace('_', ' ')}</p>
                    <ul className="mt-2 list-disc pl-5 text-xs">{(step.signals || []).map((signal) => <li key={signal}>{signal}</li>)}</ul>
                    {step.completedAt && <p className="mt-2 text-xs text-slate-400">Completed: {step.completedAt}</p>}
                  </div>
                ))}
              </div>
              <div className="space-y-3 rounded-xl border border-slate-700 bg-slate-900 p-4">
                <h3 className="text-lg font-semibold">Verification Controls</h3>
                <button onClick={runIdentityCheck} className="w-full rounded-lg border border-slate-600 bg-slate-800 px-3 py-2 text-sm">Run Stripe Identity Check</button>
                <button onClick={runBankCheck} className="w-full rounded-lg border border-slate-600 bg-slate-800 px-3 py-2 text-sm">Run Plaid Bank Confirmation</button>
                <div className="rounded-lg border border-slate-700 bg-slate-950 p-3">
                  <p className="mb-2 text-xs text-slate-400">Twilio Verify (via backend)</p>
                  <input value={otpPhone} onChange={(e) => setOtpPhone(e.target.value)} placeholder="+15551234567" className="mb-2 w-full rounded border border-slate-700 bg-slate-900 p-2 text-xs" />
                  <div className="flex gap-2"><button onClick={sendOtp} className="rounded border border-slate-600 bg-slate-800 px-2 py-1 text-xs">Send OTP</button><input value={otpCode} onChange={(e) => setOtpCode(e.target.value)} placeholder="123456" className="flex-1 rounded border border-slate-700 bg-slate-900 p-2 text-xs" /><button onClick={verifyOtp} className="rounded border border-slate-600 bg-slate-800 px-2 py-1 text-xs">Verify</button></div>
                </div>
              </div>
            </div>

            <div className="rounded-xl border border-slate-700 bg-slate-900 p-4">
              <h3 className="text-lg font-semibold">Final Verdict Card</h3>
              <p className={`mt-1 inline-block rounded-full border px-3 py-1 text-xs font-semibold ${ACTION_STYLE[approvalDecision.action] || 'border-slate-700'}`}>{approvalDecision.verdict}</p>
              <p className="mt-2 text-sm">Passed: {approvalDecision.passed.join(', ') || 'None'}</p>
              <p className="text-sm">Failed: {approvalDecision.failed.join(', ') || 'None'}</p>
              <p className="mt-2 text-sm text-slate-300">Risk narrative: weighted decision uses Fraud 40%, Identity 25%, Bank 20%, SMS 15%. Auto-block at fraud 61+.</p>
              <div className="mt-3 flex flex-wrap gap-2">
                <button onClick={approveToMercury} disabled={approvalDecision.verdict !== 'APPROVED'} className="rounded-lg bg-emerald-600 px-3 py-2 text-xs font-semibold text-white disabled:opacity-50">Approve and Process</button>
                <button className="rounded-lg border border-slate-600 bg-slate-800 px-3 py-2 text-xs">Request More Info</button>
                <button className="rounded-lg bg-red-700 px-3 py-2 text-xs font-semibold text-white">Reject Transaction</button>
                <button className="rounded-lg bg-orange-700 px-3 py-2 text-xs font-semibold text-white">Escalate to Human Review</button>
              </div>
              {mercuryResult && <p className="mt-3 text-sm text-emerald-300">Mercury confirmation: {mercuryResult.confirmationNumber || mercuryResult.status}</p>}
            </div>
          </section>
        )}
      </div>
    </main>
  )
}

export default App
