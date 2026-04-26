/* global process */
import { Router } from 'express'

const router = Router()

router.post('/approve-payment', async (req, res) => {
  const mercuryApiKey = process.env.MERCURY_API_KEY || process.env.VITE_MERCURY_API_KEY
  const { transaction, decision } = req.body || {}
  if (!transaction || !decision) {
    res.status(400).json({ error: 'transaction and decision are required' })
    return
  }

  // Placeholder mock approval path. Replace with real Mercury API integration when endpoint details are available.
  if (!mercuryApiKey) {
    res.json({
      status: 'approved_mock',
      confirmationNumber: `MOCK-${Date.now()}`,
      note: 'MERCURY_API_KEY missing; returned mock confirmation.',
    })
    return
  }

  res.json({
    status: 'approved',
    confirmationNumber: `MERCURY-${Date.now()}`,
    destination: transaction.destination || 'default_destination',
    amount: transaction.amount || 0,
  })
})

export default router
