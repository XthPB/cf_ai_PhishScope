# cf_ai_signalboard

PhishScope is an original AI-powered phishing investigation workstation built on Cloudflare. It captures suspicious pages with Browser Rendering, scores them with Workers AI, and stores each investigation in a Durable Object so the analyst can keep asking follow-up questions inside the same case.

## Why this fits the assignment

- `LLM`: Cloudflare Workers AI with `@cf/meta/llama-3.3-70b-instruct-fp8-fast`
- `Workflow / coordination`: a Durable Object coordinates each investigation case
- `User input`: URL submission, analyst chat, and optional browser voice input
- `Memory / state`: each case persists rendered evidence, verdicts, notes, and chat history

## Product concept

PhishScope is designed like a phishing triage desk rather than a generic chatbot.

The analyst:

1. submits a suspicious URL and an optional note
2. captures visual and structural evidence from the page
3. receives a structured phishing assessment
4. continues the investigation with follow-up chat in the same case

Each case preserves:

- requested URL
- final URL after render
- screenshot evidence
- visible text excerpt
- extracted forms
- extracted links
- suspicious and benign signals
- verdict, confidence, risk score, and recommended action
- analyst note and follow-up conversation

## Stack

- Cloudflare Worker for API routing and front-end serving
- Cloudflare Browser Rendering for visual page capture and DOM extraction
- Cloudflare Workers AI for phishing verdicts and analyst guidance
- Cloudflare Durable Objects for per-case persistence and coordination
- Static asset front-end for the phishing investigation console
- Vitest for local route and state-flow tests

## Project structure

- `src/index.ts`: Worker routes, Browser Rendering capture, Workers AI analysis, Durable Object case logic
- `src/shared.ts`: investigation schema, normalization, and deterministic mock fixtures
- `public/index.html`: application shell
- `public/app.js`: front-end case lifecycle, rendering, and voice input
- `public/styles.css`: custom security-console UI
- `PROMPTS.md`: AI prompts used while building the project

## Run locally in deterministic mock mode

Install dependencies:

```bash
npm install
```

Create a `.dev.vars` file:

```bash
cat <<'EOF' > .dev.vars
MOCK_AI=true
MOCK_BROWSER=true
EOF
```

Start the app:

```bash
npm run dev
```

Open [http://localhost:8787](http://localhost:8787).

Mock mode still demonstrates:

- case creation
- persisted investigation memory
- verdict rendering
- evidence panels
- analyst follow-up chat
- voice note / voice question UI in supported browsers

## Run with live Cloudflare services

Check authentication:

```bash
npx wrangler whoami
```

If needed:

```bash
npx wrangler login
```

Use remote dev for the live path:

```bash
npm run dev:remote
```

This is the recommended way to test live Workers AI and Browser Rendering together.

In live mode, verify:

- `/api/health` reports `workers-ai` and `browser-rendering`
- the screenshot panel shows a real page capture
- the extracted forms and links reflect the rendered page
- the verdict changes based on the captured evidence
- the same case persists when reloading the case URL

## Test and validate

Run the full local check:

```bash
npm run check
```

## Deploy

Deploy the Worker and static assets:

```bash
npm run deploy
```

The Worker serves the UI and API from one deployment.

## Submission notes

- The repository name starts with `cf_ai_`, which satisfies the naming requirement.
- `README.md` is included with local and live run instructions.
- `PROMPTS.md` is included with the AI prompts used during development.

## Originality note

The product concept, UI, case model, capture flow, and investigation workflow in this repo are original work created for this assignment. The only starter material was the initial official Cloudflare Worker scaffold before the project was fully rewritten into PhishScope.
