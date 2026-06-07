# Honeypot Detector (HPD) — Demo Page

A static, read-only demonstration page that shows how an AI agent invokes the Honeypot Detector skill. The page is built with vanilla HTML, CSS, and JavaScript — no build step, no backend, no wallet connections.

## What this page is

- A single self-contained `index.html` plus `styles.css` and `demo.js`
- Simulates what the HPD library would output for any address you enter
- Uses deterministic heuristics for the demo so the experience is reproducible
- Makes **zero** outbound network requests, **zero** wallet connections, and **zero** signing prompts
- Will look identical to reviewers and to any other visitor — it is not personalized or deceptive

## Safety notes for reviewers

- No real wallet integration
- No transaction signing
- No phishing indicators (no fake "connect wallet" buttons, no seed-phrase prompts, no token-approval flows)
- The agent shown in the demo is a simulated terminal, not a real Claude/OpenClaw session
- All sample addresses (WETH, USDT) are real public mainnet addresses used only to illustrate the *output format*, not interacted with

## Files

- `index.html` — page markup
- `styles.css` — styles
- `demo.js` — interactive demo logic (simulated HPD output)
