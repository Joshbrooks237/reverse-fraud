# reverse-fraud

> "The future's not set. There's no fate but what we make for ourselves."
> - John Connor, T2

This project is a dark-mode fraud operations console built to identify, verify, and decide.

## Origin Story (T2)

The logs burn in the dark.  
One transaction at a time.  
Most look clean. Some are ghosts.

By the time old systems saw the threat, money was already gone and trust was already broken.

So we changed the timeline.

`reverse-fraud` is built on one rule: **no blind approvals**.  
Every payment enters the machine and faces layered judgment:

- device and behavior analysis
- network and anonymization checks
- payment-risk signals
- identity, bank, and OTP verification before release

This is not passive monitoring.  
This is interception.

If the signal is real, it gets through.  
If the signal lies, it gets terminated.

## Mission

In a world where bad actors automate faster than trust can react, this dashboard gives defenders leverage:

- JSON-based fraud scoring with AI-assisted analysis
- Payment signal testing with Stripe tokenization-first handling
- Multi-step Approval Engine with pre-screen, identity, bank, and OTP layers
- Action-focused verdicting: allow, step-up, manual review, block, or report

## Stack

- React + Vite + Tailwind
- Stripe.js (Elements/tokenization)
- Express proxy backend for Twilio/Mercury actions

## Run

Frontend:

```bash
npm install
npm run dev
```

Backend:

```bash
npm run server
```

## Environment

See `.env.example` and provide keys in `.env.local`.

## Ethos

Trust is earned in layers. Every signal counts. Every decision leaves a trail.
