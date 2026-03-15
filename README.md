# cf_ai_signalboard

Signalboard is an original AI-powered Cloudflare application built for the assignment requirements. It helps a user turn a rough product, campaign, or workflow idea into a sharper plan with persistent session memory, live board updates, and chat or voice input.

## Why it fits the assignment

- `LLM`: Cloudflare Workers AI using `@cf/meta/llama-3.3-70b-instruct-fp8-fast`
- `Workflow / coordination`: a Durable Object coordinates each session and stores durable state
- `User input`: browser chat UI plus optional browser voice dictation
- `Memory / state`: each session keeps its conversation history and a persistent strategy board

## What the app does

- Starts a new strategy session and persists it behind a shareable session id
- Accepts chat prompts or voice-captured text
- Uses Workers AI to generate a response plus structured board updates
- Maintains a memory board with:
  - project name
  - objective
  - audience
  - tone
  - constraints
  - risks
  - next actions
- Falls back to deterministic mock mode locally if live AI is unavailable

## Stack

- Cloudflare Worker for routing and API endpoints
- Durable Object for per-session coordination and state
- Workers AI for Llama 3.3 inference
- Static assets for the front-end
- Vitest with Cloudflare Workers pool for route tests

## Project structure

- `src/index.ts`: Worker routes and Durable Object session coordinator
- `src/shared.ts`: shared session types, normalization, and mock-mode helpers
- `public/index.html`: app shell
- `public/app.js`: front-end session and chat logic
- `public/styles.css`: custom interface styling
- `PROMPTS.md`: AI prompts used while building the project

## Run locally

### 1. Install dependencies

```bash
npm install
```

### 2. Start the app in local mock mode

Create a `.dev.vars` file in the project root:

```bash
echo "MOCK_AI=true" > .dev.vars
```

Then run:

```bash
npm run dev
```

Open [http://localhost:8787](http://localhost:8787).

This mode exercises the UI, routing, Durable Object state, and session memory without requiring a live Workers AI connection.

## Run with live Workers AI

Authenticate first:

```bash
npx wrangler whoami
```

If needed:

```bash
npx wrangler login
```

Then start remote dev:

```bash
npm run dev:remote
```

Open the preview URL from Wrangler. In this mode, the app calls Workers AI using Llama 3.3.

## Test and type-check

```bash
npm run check
```

## Deploy

```bash
npm run deploy
```

The Worker serves both the front-end and the API, so deployment is a single Cloudflare publish step.

## Submission note

The assignment requires the repository name to start with `cf_ai_`. Push this project to a repository named `cf_ai_signalboard` before submitting.

## Originality note

The app logic, UI, state model, and documentation in this project are original work created for this assignment. Only the initial Cloudflare Worker scaffold came from the official `create-cloudflare` starter.
