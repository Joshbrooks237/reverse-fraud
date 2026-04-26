/* global process */
import { Router } from 'express'
import twilio from 'twilio'

const router = Router()
const ttlMs = 5 * 60 * 1000
const mockOtpStore = new Map()

function twilioClient() {
  const sid = process.env.TWILIO_ACCOUNT_SID || process.env.VITE_TWILIO_ACCOUNT_SID
  const token = process.env.TWILIO_AUTH_TOKEN || process.env.VITE_TWILIO_AUTH_TOKEN
  if (!sid || !token) return null
  return twilio(sid, token)
}

router.post('/send-otp', async (req, res) => {
  const { phone } = req.body || {}
  if (!phone) {
    res.status(400).json({ error: 'phone is required' })
    return
  }

  const verifySid = process.env.TWILIO_VERIFY_SERVICE_SID || process.env.VITE_TWILIO_VERIFY_SERVICE_SID
  const client = twilioClient()
  if (client && verifySid) {
    try {
      const verification = await client.verify.v2.services(verifySid).verifications.create({
        to: phone,
        channel: 'sms',
      })
      res.json({ status: verification.status || 'pending', verificationSid: verification.sid })
      return
    } catch (error) {
      res.status(500).json({ error: `Twilio send failed: ${error.message}` })
      return
    }
  }

  const sid = `mock_${Date.now()}`
  mockOtpStore.set(phone, { code: '123456', expiresAt: Date.now() + ttlMs, sid })
  res.json({ status: 'pending', verificationSid: sid, mode: 'mock', hint: 'Use code 123456' })
})

router.post('/verify-otp', async (req, res) => {
  const { phone, code } = req.body || {}
  if (!phone || !code) {
    res.status(400).json({ error: 'phone and code are required' })
    return
  }

  const verifySid = process.env.TWILIO_VERIFY_SERVICE_SID || process.env.VITE_TWILIO_VERIFY_SERVICE_SID
  const client = twilioClient()
  if (client && verifySid) {
    try {
      const check = await client.verify.v2.services(verifySid).verificationChecks.create({ to: phone, code })
      res.json({ status: check.status === 'approved' ? 'verified' : check.status })
      return
    } catch (error) {
      res.status(500).json({ error: `Twilio verify failed: ${error.message}` })
      return
    }
  }

  const rec = mockOtpStore.get(phone)
  if (!rec) {
    res.status(400).json({ status: 'failed', error: 'No OTP request found for phone' })
    return
  }
  if (Date.now() > rec.expiresAt) {
    mockOtpStore.delete(phone)
    res.json({ status: 'expired' })
    return
  }
  if (String(code).trim() !== rec.code) {
    res.json({ status: 'failed' })
    return
  }
  mockOtpStore.delete(phone)
  res.json({ status: 'verified', mode: 'mock' })
})

export default router
