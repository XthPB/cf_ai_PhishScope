# cf_ai_phishscope

Live application: [https://cf-ai-phishscope.pranav20032021p.workers.dev](https://cf-ai-phishscope.pranav20032021p.workers.dev)

PhishScope is a Cloudflare-native phishing investigation workstation. It captures suspicious pages with Browser Rendering, produces structured verdicts and analyst guidance, attaches optional RadarOps context, drafts mitigation actions, and preserves each case as a stateful investigation rather than a one-off scan.

## Platform highlights

- browser-rendered evidence capture instead of text-only URL analysis
- persistent case memory with follow-up investigation thread
- score decomposition so risk is explainable, not opaque
- optional RadarOps enrichment for broader Internet context
- mitigation drafting with scoped WAF, rate-limit, and rollback guidance

## Product concept

PhishScope is designed like a compact edge threat operations console rather than a generic chatbot.

The analyst:

1. submits a suspicious URL and an optional note
2. captures visual and structural evidence from the page
3. receives a structured phishing assessment and score decomposition
4. reviews RadarOps context and a mitigation draft
5. continues the investigation with follow-up chat in the same case

Each case preserves:

- requested URL
- final URL after render
- screenshot evidence
- visible text excerpt
- extracted forms
- extracted links
- suspicious and benign signals
- score drivers showing what pushed the risk model up or down
- optional RadarOps findings and recommended checks
- mitigation plan with WAF, rate-limit, monitoring, and rollback guidance
- verdict, confidence, risk score, and recommended action
- analyst note and follow-up conversation

## Stack

- Cloudflare Worker for API routing and front-end serving
- Cloudflare Browser Rendering for visual page capture and DOM extraction
- Cloudflare Workers AI for phishing verdicts and analyst guidance
- optional Radar URL Scanner enrichment for broader Internet context
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

Start the app:

```bash
npm run dev
```

Open [http://localhost:8787](http://localhost:8787).

This local path uses the tracked [`wrangler.local.jsonc`](./wrangler.local.jsonc) config, so it works without Cloudflare authentication.

Mock mode still demonstrates:

- case creation
- persisted investigation memory
- verdict rendering
- score decomposition
- evidence panels
- RadarOps heuristic context
- mitigation drafting
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

Before the first live preview or deploy on a new Cloudflare account, open the Workers dashboard once to create the required `workers.dev` subdomain:

```text
https://dash.cloudflare.com/<your-account-id>/workers/onboarding
```

Then use remote dev for the live path:

```bash
npm run dev:remote
```

This is the recommended way to test live Workers AI and Browser Rendering together.

To enable live RadarOps enrichment as well:

1. add your Cloudflare account id as `RADAR_ACCOUNT_ID` in [`wrangler.jsonc`](./wrangler.jsonc) or via the dashboard
2. store the Radar token as a Wrangler secret:

```bash
npx wrangler secret put RADAR_API_TOKEN
```

In live mode, verify:

- `/api/health` reports `workers-ai` and `browser-rendering`
- the screenshot panel shows a real page capture
- the extracted forms and links reflect the rendered page
- the verdict changes based on the captured evidence
- the Intel tab shows `Radar URL Scanner` when RadarOps credentials are configured
- the Mitigation tab drafts containment guidance based on the latest verdict and evidence
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

## Repository notes

- The repository name starts with `cf_ai_`, which satisfies the naming requirement.
- `README.md` is included with local and live run instructions.
- `PROMPTS.md` is included with the AI prompts used during development.

## Development note

The product concept, UI, case model, capture flow, and investigation workflow in this repo are original work created for this assignment. The only starter material was the initial official Cloudflare Worker scaffold before the project was fully rewritten into PhishScope.
