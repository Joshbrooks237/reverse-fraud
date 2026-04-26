/* global process */
import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const apiKey = env.ANTHROPIC_API_KEY || env.VITE_ANTHROPIC_API_KEY

  return {
    plugins: [
      react(),
      {
        name: 'anthropic-proxy',
        configureServer(server) {
        server.middlewares.use('/api/status', (req, res) => {
          const hasKey = Boolean(apiKey)
          res.setHeader('Content-Type', 'application/json')
          res.end(JSON.stringify({ hasKey }))
        })

        server.middlewares.use('/api/analyze', async (req, res) => {
          if (req.method !== 'POST') {
            res.statusCode = 405
            res.setHeader('Content-Type', 'application/json')
            res.end(JSON.stringify({ error: 'Method not allowed' }))
            return
          }

          if (!apiKey) {
            res.statusCode = 500
            res.setHeader('Content-Type', 'application/json')
            res.end(JSON.stringify({ error: 'Missing ANTHROPIC_API_KEY or VITE_ANTHROPIC_API_KEY in .env.local' }))
            return
          }

          try {
            let rawBody = ''
            await new Promise((resolve, reject) => {
              req.on('data', (chunk) => {
                rawBody += chunk.toString()
              })
              req.on('end', resolve)
              req.on('error', reject)
            })

            const payload = JSON.parse(rawBody || '{}')
            const response = await fetch('https://api.anthropic.com/v1/messages', {
              method: 'POST',
              headers: {
                'content-type': 'application/json',
                'x-api-key': apiKey.trim(),
                'anthropic-version': '2023-06-01',
              },
              body: JSON.stringify(payload),
            })

            const text = await response.text()
            res.statusCode = response.status
            res.setHeader('Content-Type', 'application/json')
            res.end(text)
          } catch (error) {
            res.statusCode = 500
            res.setHeader('Content-Type', 'application/json')
            res.end(JSON.stringify({ error: `Proxy request failed: ${error.message}` }))
          }
        })
        },
      },
    ],
  }
})
