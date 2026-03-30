---
name: claude-cowork-handoff
description: Use when continuing work on cf_ai_phishscope with another agent. This is the single handoff skill for the PhishScope codebase, covering project architecture, current implementation status, repo knowledge, environment variables, bindings, commands, optional infrastructure, safe credential setup, current deployment, useful Cloudflare documentation links, and the practical steps needed to develop, test, deploy, and extend the project.
---

# Claude Co-Work Handoff

Use this skill when continuing implementation, debugging, deployment, UI polish, or architectural changes in `cf_ai_phishscope`.

This file is intentionally a single-source handoff. It is meant to be shared with another coding agent so they can pick up work quickly without re-deriving the repo structure.

## Scope and safety

- This repo is a real Cloudflare Worker application, not a toy scaffold.
- Do not commit secrets or paste live tokens into source control.
- This file documents **credential names and setup steps**, not secret values.
- Current deployment is public at:
  - [https://cf-ai-phishscope.pranav20032021p.workers.dev](https://cf-ai-phishscope.pranav20032021p.workers.dev)
- Current repo is:
  - [https://github.com/XthPB/cf_ai_PhishScope.git](https://github.com/XthPB/cf_ai_PhishScope.git)
- Local repo root:
  - `/Users/xthpb/Documents/Cloudflare/cf_ai_phishscope`

## What the project is

PhishScope is a Cloudflare-native phishing investigation workstation / compact edge threat operations console.

Current implemented product shape:

- suspicious URL intake
- rendered evidence capture with Browser Rendering
- structured phishing verdict and follow-up reasoning
- durable per-case state and conversation memory
- indexed case catalog and dashboard
- score decomposition so the risk score is explainable
- RadarOps surface for broader Internet context
- Mitigation Studio surface for scoped containment guidance
- scheduled rescans
- guardrails for unsupported questions like traffic attribution, WHOIS, passive DNS, registrant correlation

Important: the current app **does not yet** use the Cloudflare Agents SDK or remote MCP servers in code. Those were discussed as a future direction, but the current implementation is still a Workers + Durable Objects app with optional Radar REST enrichment.

## Current architecture

### Core runtime

- Cloudflare Worker entrypoint serves:
  - API routes
  - static front-end assets
- Durable Object:
  - `InvestigationCase`
  - owns one case’s state, transcript, rescans, and follow-up flow
- Optional platform services:
  - D1 for case index persistence
  - Analytics Engine for event telemetry
  - Rate Limiting bindings for intake and follow-up hardening
  - Turnstile for human verification on intake
  - Radar URL Scanner enrichment

### Main files

- `/Users/xthpb/Documents/Cloudflare/cf_ai_phishscope/src/index.ts`
  - Worker routes
  - case proxying
  - Durable Object implementation
  - Browser Rendering capture
  - Workers AI prompting
  - unsupported-evidence guardrails
  - RadarOps enrichment
  - score decomposition
  - mitigation plan generation

- `/Users/xthpb/Documents/Cloudflare/cf_ai_phishscope/src/shared.ts`
  - all shared types
  - normalization
  - default state creation
  - prompt snapshots
  - mock investigation fixtures

- `/Users/xthpb/Documents/Cloudflare/cf_ai_phishscope/src/platform.ts`
  - optional D1 schema
  - case indexing
  - dashboard aggregation
  - related-case lookup
  - Analytics Engine helpers

- `/Users/xthpb/Documents/Cloudflare/cf_ai_phishscope/public/index.html`
  - app shell
  - case queue
  - overview / evidence / network / intel / mitigation / history tabs

- `/Users/xthpb/Documents/Cloudflare/cf_ai_phishscope/public/app.js`
  - client state
  - fetch lifecycle
  - workspace rendering
  - queue filters
  - voice input

- `/Users/xthpb/Documents/Cloudflare/cf_ai_phishscope/public/styles.css`
  - console UI styling
  - button system
  - Intel / Mitigation / score driver presentation

- `/Users/xthpb/Documents/Cloudflare/cf_ai_phishscope/test/index.spec.ts`
  - route tests
  - case lifecycle tests
  - guardrail tests
  - Radar enrichment test

## API and workflow map

### Worker routes

- `GET /api/health`
  - returns AI/browser mode
  - returns feature flags
  - returns Turnstile site key when configured

- `GET /api/dashboard`
  - returns aggregate dashboard stats

- `GET /api/cases`
  - indexed case list
  - supports `search`, `status`, `verdict`, `limit`

- `POST /api/cases`
  - creates a new investigation case

- `GET /api/cases/:caseId`
  - returns a case

- `POST /api/cases/:caseId/messages`
  - analyst follow-up

- `POST /api/cases/:caseId/rescan`
  - immediate fresh rescan

- `POST /api/cases/:caseId/schedule-rescan`
  - delayed automated rescan

### Durable Object internal routes

- `POST /initialize`
- `GET /state`
- `POST /rescan`
- `POST /schedule-rescan`
- `POST /messages`

### UI tabs

- `Overview`
  - executive summary
  - highlight
  - suspicious / benign signals
  - score drivers
  - provenance
  - Radar quick facts
  - Mitigation quick facts

- `Evidence`
  - screenshot
  - requested/final URL
  - page title
  - text excerpt

- `Network`
  - structural indicators
  - brand hints
  - link summary
  - forms and links extracted
  - operations workflow panel

- `Intel`
  - RadarOps narrative
  - source / status / category / confidence
  - anomaly signals
  - recommended checks
  - findings

- `Mitigation`
  - mitigation mode
  - owner / approval state
  - rationale
  - WAF expression
  - rate-limit guidance
  - Turnstile guidance
  - monitoring guidance
  - rollout and rollback steps

- `History`
  - timeline
  - related cases

## Current implementation behavior

### Evidence and AI

- Browser Rendering captures real rendered page state when live.
- Mock mode exists for local development and tests.
- Workers AI uses structured JSON response schemas.
- Screenshot payload is **not** inserted into the AI prompt.
  - This was fixed after a real context-window overflow issue.
- Prompt context is bounded using compact snapshots from `src/shared.ts`.

### Guardrails

The app intentionally refuses to invent unsupported data.

Handled as explicit evidence gaps:

- traffic sources
- referrers
- campaign origin
- visitor analytics
- WHOIS
- registrant history
- passive DNS / DNS history
- reputation feeds
- certificate transparency
- same-registrant / sibling-domain correlation

If asked, the assistant should say that data is not in the case evidence and recommend the correct external lookup.

### RadarOps

Current state:

- if `RADAR_ACCOUNT_ID` and `RADAR_API_TOKEN` exist:
  - submit URL to Radar URL Scanner
  - fetch result
  - attach findings, confidence, threat category, summary, checks
- otherwise:
  - fallback to heuristic RadarOps context derived from local evidence

### Mitigation Studio

Current state:

- mitigation mode is one of:
  - `monitor`
  - `review`
  - `block`
- derived from:
  - verdict
  - risk score
  - score drivers
  - Radar high-risk context
- output includes:
  - WAF expression
  - rate-limit recommendation
  - Turnstile recommendation
  - monitoring recommendation
  - rationale
  - rollout steps
  - rollback steps
  - suggested owner

### Case indexing

Current state:

- if `DB` is not configured:
  - in-memory index fallback
- if `DB` is configured:
  - creates and uses `cases_index`
  - supports searchable queue and dashboard aggregation

## Files worth reading first

If another agent has limited time, start with these in this order:

1. `/Users/xthpb/Documents/Cloudflare/cf_ai_phishscope/README.md`
2. `/Users/xthpb/Documents/Cloudflare/cf_ai_phishscope/src/index.ts`
3. `/Users/xthpb/Documents/Cloudflare/cf_ai_phishscope/src/shared.ts`
4. `/Users/xthpb/Documents/Cloudflare/cf_ai_phishscope/public/app.js`
5. `/Users/xthpb/Documents/Cloudflare/cf_ai_phishscope/test/index.spec.ts`
6. `/Users/xthpb/Documents/Cloudflare/cf_ai_phishscope/wrangler.jsonc`

## Environment variables, bindings, and safe credential guidance

### Always-configured bindings

- `AI`
  - Workers AI binding
- `BROWSER`
  - Browser Rendering binding
- `ASSETS`
  - static assets binding
- `CASES`
  - Durable Object binding for `InvestigationCase`

### Vars currently in Wrangler config

From `wrangler.jsonc`:

- `MOCK_AI`
- `MOCK_BROWSER`
- `RADAR_ACCOUNT_ID`
- `TURNSTILE_SITE_KEY`

From `wrangler.local.jsonc`:

- `MOCK_AI=true`
- `MOCK_BROWSER=true`
- `RADAR_ACCOUNT_ID=""`
- `TURNSTILE_SITE_KEY=""`

### Secrets / sensitive config

Do not commit these.

- `RADAR_API_TOKEN`
  - Wrangler secret
  - set with:
    - `npx wrangler secret put RADAR_API_TOKEN`

- `TURNSTILE_SECRET_KEY`
  - should be stored as a secret, not in source control

### Optional commented bindings not yet always enabled

- `DB`
  - D1 database
- `ANALYTICS`
  - Workers Analytics Engine dataset
- `CREATE_LIMITER`
  - Rate Limiting binding for intake
- `FOLLOWUP_LIMITER`
  - Rate Limiting binding for follow-up / rescans

### Credential note

This repo should document **what credentials are required and how to wire them**, but should not store actual secret values in the skill.

## Packages used

From `package.json`:

### Runtime dependency

- `@cloudflare/puppeteer`

### Dev dependencies

- `wrangler`
- `typescript`
- `vitest`
- `@types/node`

## CLI tools used

Primary tools used in this repo:

- `npm`
- `npx wrangler`
- `tsc`
- `vitest`
- `git`
- `rg`

Most important commands:

```bash
npm install
npm run dev
npm run dev:mock
npm run dev:remote
npm run typecheck
npm test
npm run check
npm run deploy
npx wrangler whoami
npx wrangler login
npx wrangler deploy --dry-run
npx wrangler secret put RADAR_API_TOKEN
npx wrangler types
```

## Common workflows

### Local mock development

```bash
cd /Users/xthpb/Documents/Cloudflare/cf_ai_phishscope
npm install
npm run dev
```

Open:

- [http://localhost:8787](http://localhost:8787)

Use this when you want:

- deterministic local behavior
- no Cloudflare auth dependency
- fast UI iteration
- tests against mock AI/mock browser behavior

### Live Cloudflare development

```bash
cd /Users/xthpb/Documents/Cloudflare/cf_ai_phishscope
npx wrangler whoami
npm run dev:remote
```

Use this when you want:

- real Workers AI
- real Browser Rendering
- live validation of the production path

### Deploy

```bash
cd /Users/xthpb/Documents/Cloudflare/cf_ai_phishscope
npm run deploy
```

### Full verification

```bash
cd /Users/xthpb/Documents/Cloudflare/cf_ai_phishscope
npm run check
npx wrangler deploy --dry-run
```

## How to enable optional infrastructure

### RadarOps live mode

1. set `RADAR_ACCOUNT_ID`
2. add secret:

```bash
npx wrangler secret put RADAR_API_TOKEN
```

3. deploy or run remote dev
4. confirm `/api/health` shows `radarOps: true`
5. confirm Intel tab shows `Radar URL Scanner` instead of heuristic mode

### D1 case index

1. create a D1 database in Cloudflare
2. uncomment the `d1_databases` section in `wrangler.jsonc`
3. set:
   - `binding: DB`
   - `database_name`
   - `database_id`
4. deploy

Behavior:

- `src/platform.ts` auto-creates the `cases_index` schema on first use

### Analytics Engine

1. create a dataset
2. uncomment `analytics_engine_datasets` in `wrangler.jsonc`
3. bind as `ANALYTICS`
4. deploy

### Rate limiting

1. provision namespaces in Cloudflare
2. uncomment `ratelimits` in `wrangler.jsonc`
3. supply namespace ids for:
   - `CREATE_LIMITER`
   - `FOLLOWUP_LIMITER`
4. deploy

### Turnstile

1. create a Turnstile widget
2. set `TURNSTILE_SITE_KEY`
3. store `TURNSTILE_SECRET_KEY` as a secret
4. deploy

## Testing knowledge

Current test file:

- `/Users/xthpb/Documents/Cloudflare/cf_ai_phishscope/test/index.spec.ts`

Current coverage themes:

- app shell
- health flags
- case creation
- analytics emission
- indexed list and dashboard
- RadarOps enrichment
- follow-up chat
- rescans
- scheduled rescans
- unsupported telemetry guardrails
- WHOIS/registrant guardrails
- rate limiting
- Turnstile verification
- bounded prompt snapshots

Useful commands:

```bash
npm test
npm run typecheck
npm run check
```

## Current recent commit history

Most recent commits at the time this handoff was written:

- `0c90f7c` Refine README positioning and live link
- `71e907a` Add RadarOps and mitigation console modules
- `3eda1fc` Polish console buttons and clarify queue filters
- `161c5a5` Tighten unsupported enrichment follow-up guardrails
- `4405805` Upgrade PhishScope analyst console and case platform
- `e792928` Guardrail unsupported telemetry follow-ups
- `d9e3edf` Fix live AI prompt sizing and refine analyst UI

These are useful for understanding the project evolution.

## Known next-step opportunities

Discussed but not yet implemented:

- Agents SDK orchestration
- remote MCP clients for Cloudflare services
- War Room real-time collaboration over WebSockets
- full RadarOps expansion beyond current URL Scanner usage
- campaign clustering with Vectorize
- downloadable review package
- false-positive memory loop

If another agent implements these, they should first preserve the current product coherence. Do not turn the app into a random feature dump.

## Codex-side skills available during development

These were the broader skills available in the original Codex environment. Claude will not automatically have them, but this list is useful as context for how work was approached:

- `cloudflare-deploy`
- `doc`
- `figma`
- `figma-implement-design`
- `jupyter-notebook`
- `notion-knowledge-capture`
- `notion-meeting-intelligence`
- `notion-research-documentation`
- `notion-spec-to-implementation`
- `openai-docs`
- `pdf`
- `render-deploy`
- `screenshot`
- `skill-creator`
- `skill-installer`

The one directly relevant to this handoff was `skill-creator`.

## Cloudflare documentation links

These are the most relevant official links for this repo and the near-term roadmap.

### Current project stack

- Agents landing page:
  - [https://agents.cloudflare.com](https://agents.cloudflare.com)
- Agents docs:
  - [https://developers.cloudflare.com/agents/](https://developers.cloudflare.com/agents/)
- Cloudflare MCP servers:
  - [https://developers.cloudflare.com/agents/model-context-protocol/mcp-servers-for-cloudflare/](https://developers.cloudflare.com/agents/model-context-protocol/mcp-servers-for-cloudflare/)
- Cloudflare MCP server repo:
  - [https://github.com/cloudflare/mcp-server-cloudflare](https://github.com/cloudflare/mcp-server-cloudflare)
- Wrangler configuration:
  - [https://developers.cloudflare.com/workers/wrangler/configuration/](https://developers.cloudflare.com/workers/wrangler/configuration/)
- Workers bindings:
  - [https://developers.cloudflare.com/workers/runtime-apis/bindings/](https://developers.cloudflare.com/workers/runtime-apis/bindings/)
- Workers secrets:
  - [https://developers.cloudflare.com/workers/configuration/secrets/](https://developers.cloudflare.com/workers/configuration/secrets/)
- workers.dev routing:
  - [https://developers.cloudflare.com/workers/configuration/routing/workers-dev/](https://developers.cloudflare.com/workers/configuration/routing/workers-dev/)
- Browser Rendering:
  - [https://developers.cloudflare.com/browser-rendering/](https://developers.cloudflare.com/browser-rendering/)
- Browser Rendering pricing:
  - [https://developers.cloudflare.com/browser-rendering/pricing/](https://developers.cloudflare.com/browser-rendering/pricing/)
- Browser Rendering limits:
  - [https://developers.cloudflare.com/browser-rendering/limits/](https://developers.cloudflare.com/browser-rendering/limits/)
- Workers AI overview:
  - [https://developers.cloudflare.com/workers-ai/](https://developers.cloudflare.com/workers-ai/)
- Llama 3.3 model page:
  - [https://developers.cloudflare.com/workers-ai/models/llama-3.3-70b-instruct-fp8-fast/](https://developers.cloudflare.com/workers-ai/models/llama-3.3-70b-instruct-fp8-fast/)
- Workers AI JSON mode:
  - [https://developers.cloudflare.com/workers-ai/features/json-mode/](https://developers.cloudflare.com/workers-ai/features/json-mode/)
- Durable Objects:
  - [https://developers.cloudflare.com/durable-objects/](https://developers.cloudflare.com/durable-objects/)
- Durable Object migrations:
  - [https://developers.cloudflare.com/durable-objects/reference/durable-objects-migrations/](https://developers.cloudflare.com/durable-objects/reference/durable-objects-migrations/)
- Radar overview:
  - [https://developers.cloudflare.com/radar/](https://developers.cloudflare.com/radar/)

### Optional infrastructure used or discussed

- D1:
  - [https://developers.cloudflare.com/d1/](https://developers.cloudflare.com/d1/)
- Analytics Engine:
  - [https://developers.cloudflare.com/analytics/analytics-engine/](https://developers.cloudflare.com/analytics/analytics-engine/)
- Rate limiting binding:
  - [https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/)
- Turnstile:
  - [https://developers.cloudflare.com/turnstile/](https://developers.cloudflare.com/turnstile/)
- Workflows:
  - [https://developers.cloudflare.com/workflows/](https://developers.cloudflare.com/workflows/)
- Vectorize:
  - [https://developers.cloudflare.com/vectorize/](https://developers.cloudflare.com/vectorize/)
- AI Gateway:
  - [https://developers.cloudflare.com/ai-gateway/](https://developers.cloudflare.com/ai-gateway/)

### MCP / future architecture references

- MCP overview:
  - [https://developers.cloudflare.com/agents/model-context-protocol/](https://developers.cloudflare.com/agents/model-context-protocol/)
- MCP client API:
  - [https://developers.cloudflare.com/agents/api-reference/mcp-client-api/](https://developers.cloudflare.com/agents/api-reference/mcp-client-api/)
- Radar MCP server:
  - [https://radar.mcp.cloudflare.com/mcp](https://radar.mcp.cloudflare.com/mcp)
- Browser Rendering MCP server:
  - [https://browser.mcp.cloudflare.com/mcp](https://browser.mcp.cloudflare.com/mcp)
- Observability MCP server:
  - [https://observability.mcp.cloudflare.com/mcp](https://observability.mcp.cloudflare.com/mcp)
- Cloudflare API MCP server:
  - [https://mcp.cloudflare.com/mcp](https://mcp.cloudflare.com/mcp)
- Agents SDK docs MCP server:
  - [https://agents.cloudflare.com/mcp](https://agents.cloudflare.com/mcp)

## Practical collaboration note

If Claude continues the project:

- keep the app coherent
- preserve the current security-console tone
- do not remove guardrails that prevent fabricated answers
- prefer Cloudflare-native primitives over adding random third-party services
- validate with tests and `wrangler deploy --dry-run` before claiming completion
