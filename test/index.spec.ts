import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import worker, { InvestigationCase } from '../src';
import { resetPlatformState } from '../src/platform';
import { buildEvidenceSnapshot, buildTranscript, createDefaultEvidence, createMessage } from '../src/shared';

beforeEach(() => {
	resetPlatformState();
});

afterEach(() => {
	vi.restoreAllMocks();
});

describe('PhishScope worker', () => {
	it('serves the PhishScope app shell', async () => {
		const response = await worker.fetch(new Request('http://example.com/'), createEnv(), createCtx());

		expect(response.headers.get('content-type')).toContain('text/html');
		expect(await response.text()).toContain('PhishScope');
	});

	it('reports health metadata and feature flags', async () => {
		const response = await worker.fetch(new Request('http://example.com/api/health'), createEnv({
			CREATE_LIMITER: {
				limit: vi.fn(async () => ({ success: true })),
			},
			FOLLOWUP_LIMITER: {
				limit: vi.fn(async () => ({ success: true })),
			},
			TURNSTILE_SECRET_KEY: 'secret',
			TURNSTILE_SITE_KEY: 'site-key',
		}), createCtx());
		const payload = (await response.json()) as Record<string, any>;

		expect(response.ok).toBe(true);
		expect(payload.status).toBe('ok');
		expect(payload.aiMode).toBe('mock');
		expect(payload.browserMode).toBe('mock');
		expect(payload.features.rateLimit).toBe(true);
		expect(payload.features.scheduledRescans).toBe(true);
		expect(payload.features.turnstile).toBe(true);
		expect(payload.model).toContain('llama-3.3');
	});

	it('creates a phishing investigation case with preserved evidence and emits analytics', async () => {
		const writeDataPoint = vi.fn();
		const env = createEnv({
			ANALYTICS: {
				writeDataPoint,
			},
		});
		const { response, payload } = await requestJson(env, 'http://example.com/api/cases', {
			body: JSON.stringify({
				analystNote: 'User reported an urgent Microsoft password reset lure.',
				url: 'https://secure-login-microsoft-example.test',
			}),
			headers: { 'content-type': 'application/json' },
			method: 'POST',
		});

		expect(response.ok).toBe(true);
		expect(payload.caseId).toMatch(/[a-f0-9-]{36}/);
		expect(payload.investigation.scanCount).toBe(1);
		expect(payload.investigation.assessment.verdict).toBeTruthy();
		expect(payload.investigation.evidence.screenshotDataUrl).toContain('data:image/');
		expect(payload.investigation.messages).toHaveLength(2);
		expect(payload.relatedCases).toEqual([]);
		expect(writeDataPoint).toHaveBeenCalledWith(
			expect.objectContaining({
				blobs: expect.arrayContaining(['case_opened']),
			}),
		);
	});

	it('indexes cases for dashboard and searchable case list views', async () => {
		const env = createEnv();

		await createCase(env, {
			analystNote: 'Urgent credential lure reported by the user.',
			url: 'https://secure-login-microsoft-example.test',
		});
		await createCase(env, {
			url: 'https://cloudflare.com/careers',
		});

		const dashboard = await requestJson(env, 'http://example.com/api/dashboard');
		expect(dashboard.response.ok).toBe(true);
		expect(dashboard.payload.dashboard.totalCases).toBe(2);
		expect(dashboard.payload.dashboard.averageRiskScore).toBeGreaterThan(0);
		expect(dashboard.payload.dashboard.needsReviewCases + dashboard.payload.dashboard.escalatedCases).toBeGreaterThan(0);

		const suspiciousCases = await requestJson(env, 'http://example.com/api/cases?verdict=suspicious');
		expect(suspiciousCases.response.ok).toBe(true);
		expect(suspiciousCases.payload.cases).toHaveLength(1);
		expect(suspiciousCases.payload.cases[0].hostname).toBe('secure-login-microsoft-example.test');

		const cloudflareCases = await requestJson(env, 'http://example.com/api/cases?search=cloudflare');
		expect(cloudflareCases.response.ok).toBe(true);
		expect(cloudflareCases.payload.cases.some((item: any) => item.hostname === 'cloudflare.com')).toBe(true);
	});

	it('supports follow-up chat and rescans within the same case', async () => {
		const env = createEnv();
		const created = await createCase(env, {
			analystNote: 'Potential Cloudflare impersonation lure.',
			url: 'https://verify-cloudflare-account.example.net',
		});

		const followUp = await requestJson(env, `http://example.com/api/cases/${created.payload.caseId}/messages`, {
			body: JSON.stringify({
				message: 'Should we block this indicator immediately?',
			}),
			headers: { 'content-type': 'application/json' },
			method: 'POST',
		});

		expect(followUp.response.ok).toBe(true);
		expect(followUp.payload.investigation.messages.at(-1).role).toBe('assistant');
		expect(followUp.payload.investigation.assessment.recommendedAction).toBeTruthy();
		expect(followUp.payload.investigation.timeline.some((event: any) => event.type === 'follow-up-answered')).toBe(true);

		const rescan = await requestJson(env, `http://example.com/api/cases/${created.payload.caseId}/rescan`, {
			body: JSON.stringify({
				analystNote: 'Re-scan after a second user report.',
			}),
			headers: { 'content-type': 'application/json' },
			method: 'POST',
		});

		expect(rescan.response.ok).toBe(true);
		expect(rescan.payload.investigation.scanCount).toBe(2);
		expect(rescan.payload.investigation.analystNote).toContain('second user report');
		expect(rescan.payload.investigation.timeline.some((event: any) => event.type === 'rescan-completed')).toBe(true);
	});

	it('schedules rescans and executes them through the durable object alarm path', async () => {
		const env = createEnv();
		const created = await createCase(env, {
			url: 'https://verify-cloudflare-account.example.net',
		});

		const scheduled = await requestJson(env, `http://example.com/api/cases/${created.payload.caseId}/schedule-rescan`, {
			body: JSON.stringify({
				delaySeconds: 45,
			}),
			headers: { 'content-type': 'application/json' },
			method: 'POST',
		});

		expect(scheduled.response.ok).toBe(true);
		expect(scheduled.payload.investigation.scheduledRescanAt).toBeTruthy();

		const durableState = getCaseState(env, created.payload.caseId);
		expect(await durableState.storage.getAlarm()).toBeTypeOf('number');

		await runAlarm(env, created.payload.caseId);

		const latest = await requestJson(env, `http://example.com/api/cases/${created.payload.caseId}`);
		expect(latest.response.ok).toBe(true);
		expect(latest.payload.investigation.scanCount).toBe(2);
		expect(latest.payload.investigation.scheduledRescanAt).toBe('');
		expect(latest.payload.investigation.timeline.some((event: any) => event.type === 'scheduled-rescan-completed')).toBe(true);
		expect(latest.payload.investigation.messages.at(-1).content).toContain('Scheduled rescan completed');
	});

	it('refuses to guess unsupported traffic-source telemetry in follow-up answers', async () => {
		const env = createEnv();
		const created = await createCase(env, {
			url: 'https://job-boards.greenhouse.io/cloudflare/jobs/7296929?gh_jid=7296929',
		});

		const followUp = await requestJson(env, `http://example.com/api/cases/${created.payload.caseId}/messages`, {
			body: JSON.stringify({
				message: 'Can you identify the major traffic sources on this page?',
			}),
			headers: { 'content-type': 'application/json' },
			method: 'POST',
		});
		const latestReply = followUp.payload.investigation.messages.at(-1).content as string;

		expect(followUp.response.ok).toBe(true);
		expect(latestReply).toContain('cannot be determined');
		expect(latestReply).toContain('referrers');
		expect(latestReply).not.toContain('Greenhouse');
		expect(followUp.payload.investigation.assessment.recommendedAction).toContain('analytics');
	});

	it('refuses to imply WHOIS or registrant-correlation data exists when it is not in evidence', async () => {
		const env = createEnv();
		const created = await createCase(env, {
			url: 'https://apple3.com',
		});

		const whois = await requestJson(env, `http://example.com/api/cases/${created.payload.caseId}/messages`, {
			body: JSON.stringify({
				message: 'What is the result of the WHOIS lookup for the apple3.com domain?',
			}),
			headers: { 'content-type': 'application/json' },
			method: 'POST',
		});
		const whoisReply = whois.payload.investigation.messages.at(-1).content as string;

		expect(whois.response.ok).toBe(true);
		expect(whoisReply).toContain('not present in the current case evidence');
		expect(whoisReply).toContain('WHOIS');
		expect(whois.payload.investigation.assessment.recommendedAction).toContain('WHOIS');

		const relatedDomains = await requestJson(env, `http://example.com/api/cases/${created.payload.caseId}/messages`, {
			body: JSON.stringify({
				message: 'Are there any other domains registered by the same registrant that may be related to phishing activities?',
			}),
			headers: { 'content-type': 'application/json' },
			method: 'POST',
		});
		const relatedDomainsReply = relatedDomains.payload.investigation.messages.at(-1).content as string;

		expect(relatedDomains.response.ok).toBe(true);
		expect(relatedDomainsReply).toContain('registrant-correlation');
		expect(relatedDomainsReply).toContain('passive-DNS');
		expect(relatedDomainsReply).not.toContain('may be related');
	});

	it('rejects create-case requests when the create limiter blocks the caller', async () => {
		const env = createEnv({
			CREATE_LIMITER: {
				limit: vi.fn(async () => ({ success: false })),
			},
		});

		const blocked = await requestJson(env, 'http://example.com/api/cases', {
			body: JSON.stringify({
				url: 'https://secure-login-microsoft-example.test',
			}),
			headers: { 'content-type': 'application/json' },
			method: 'POST',
		});

		expect(blocked.response.status).toBe(429);
		expect(blocked.payload.error).toContain('Rate limit exceeded');
	});

	it('rejects create-case requests when turnstile is configured but no token is provided', async () => {
		const env = createEnv({
			TURNSTILE_SECRET_KEY: 'secret',
			TURNSTILE_SITE_KEY: 'site-key',
		});

		const rejected = await requestJson(env, 'http://example.com/api/cases', {
			body: JSON.stringify({
				url: 'https://secure-login-microsoft-example.test',
			}),
			headers: { 'content-type': 'application/json' },
			method: 'POST',
		});

		expect(rejected.response.status).toBe(403);
		expect(rejected.payload.error).toContain('Human verification failed');
	});

	it('accepts create-case requests when turnstile verification succeeds', async () => {
		const siteverifyResponse = new Response(JSON.stringify({ success: true }), {
			headers: { 'content-type': 'application/json' },
		});
		vi.spyOn(globalThis, 'fetch').mockResolvedValue(siteverifyResponse);

		const env = createEnv({
			TURNSTILE_SECRET_KEY: 'secret',
			TURNSTILE_SITE_KEY: 'site-key',
		});

		const created = await requestJson(env, 'http://example.com/api/cases', {
			body: JSON.stringify({
				turnstileToken: 'token-123',
				url: 'https://secure-login-microsoft-example.test',
			}),
			headers: {
				'CF-Connecting-IP': '203.0.113.10',
				'content-type': 'application/json',
			},
			method: 'POST',
		});

		expect(created.response.ok).toBe(true);
		expect(created.payload.caseId).toBeTruthy();
		expect(globalThis.fetch).toHaveBeenCalledWith(
			'https://challenges.cloudflare.com/turnstile/v0/siteverify',
			expect.objectContaining({
				method: 'POST',
			}),
		);
	});

	it('builds compact AI snapshots without embedding the screenshot payload', () => {
		const evidence = {
			...createDefaultEvidence('https://example.com'),
			screenshotDataUrl: 'data:image/jpeg;base64,VERY-LONG-SCREENSHOT',
			textExcerpt: 'A'.repeat(5000),
		};

		const snapshot = buildEvidenceSnapshot(evidence);

		expect(snapshot).toContain('"screenshotCaptured": true');
		expect(snapshot).not.toContain('VERY-LONG-SCREENSHOT');
		expect(snapshot.length).toBeLessThan(4000);
	});

	it('truncates the transcript so follow-up prompts stay bounded', () => {
		const messages = [
			createMessage('user', 'B'.repeat(800), '2026-03-15T21:00:00.000Z'),
			createMessage('assistant', 'C'.repeat(800), '2026-03-15T21:00:01.000Z'),
		];

		const transcript = buildTranscript(messages);

		expect(transcript).toContain('USER:');
		expect(transcript).toContain('ASSISTANT:');
		expect(transcript.length).toBeLessThan(900);
	});
});

async function createCase(env: Env & { __casesById: Map<string, MockDurableObjectState> }, body: Record<string, unknown>) {
	return requestJson(env, 'http://example.com/api/cases', {
		body: JSON.stringify(body),
		headers: { 'content-type': 'application/json' },
		method: 'POST',
	});
}

async function requestJson(env: Env, url: string, init?: RequestInit) {
	const response = await worker.fetch(new Request(url, init), env, createCtx());
	const payload = await response.json().catch(() => ({}));
	return { payload, response };
}

function runAlarm(env: Env & { __casesById: Map<string, MockDurableObjectState> }, caseId: string) {
	const state = getCaseState(env, caseId);
	const instance = new InvestigationCase(state as unknown as DurableObjectState, env);
	return instance.alarm();
}

function getCaseState(env: Env & { __casesById: Map<string, MockDurableObjectState> }, caseId: string) {
	const state = env.__casesById.get(caseId);
	if (!state) {
		throw new Error(`Case state ${caseId} was not found.`);
	}

	return state;
}

function createEnv(overrides: Record<string, unknown> = {}) {
	const casesById = new Map<string, MockDurableObjectState>();

	const env: Record<string, any> = {
		AI: {
			run: async () => {
				throw new Error('AI is mocked in unit tests.');
			},
		},
		ASSETS: {
			fetch: async () =>
				new Response('<!doctype html><html><body>PhishScope</body></html>', {
					headers: { 'content-type': 'text/html; charset=utf-8' },
				}),
		},
		BROWSER: {},
		MOCK_AI: 'true',
		MOCK_BROWSER: 'true',
		__casesById: casesById,
		...overrides,
	};

	env.CASES = {
		get(id: string) {
			if (!casesById.has(id)) {
				casesById.set(id, new MockDurableObjectState());
			}

			const state = casesById.get(id)!;
			const instance = new InvestigationCase(state as unknown as DurableObjectState, env as Env);
			return {
				fetch: (request: Request) => instance.fetch(request),
			};
		},
		idFromName(name: string) {
			return name;
		},
	};

	return env as Env & { __casesById: Map<string, MockDurableObjectState> };
}

function createCtx(): ExecutionContext {
	return {
		passThroughOnException() {},
		waitUntil() {
			return undefined;
		},
	};
}

class MockDurableObjectState {
	storage = new MockStorage();
}

class MockStorage {
	private alarmAt: number | null = null;
	private readonly values = new Map<string, unknown>();

	async get<T>(key: string): Promise<T | undefined> {
		return this.values.get(key) as T | undefined;
	}

	async put(key: string, value: unknown): Promise<void> {
		this.values.set(key, value);
	}

	async setAlarm(timestamp: number): Promise<void> {
		this.alarmAt = timestamp;
	}

	async getAlarm(): Promise<number | null> {
		return this.alarmAt;
	}
}
