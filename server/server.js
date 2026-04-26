/* global process */
import cors from 'cors'
import dotenv from 'dotenv'
import express from 'express'
import twilioRouter from './routes/twilio.js'
import mercuryRouter from './routes/mercury.js'

dotenv.config()

const app = express()
const port = Number(process.env.SERVER_PORT || 3001)

app.use(cors())
app.use(express.json())

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'approval-engine-backend' })
})

app.use('/api', twilioRouter)
app.use('/api', mercuryRouter)

app.listen(port, () => {
  console.log(`Approval backend listening on http://localhost:${port}`)
})
