import { describe, expect, it } from 'vitest';

import worker, { InvestigationCase } from '../src';
import { buildEvidenceSnapshot, buildTranscript, createDefaultEvidence, createMessage } from '../src/shared';

describe('PhishScope worker', () => {
	it('serves the PhishScope app shell', async () => {
		const response = await worker.fetch(new Request('http://example.com/'), createEnv(), createCtx());

		expect(response.headers.get('content-type')).toContain('text/html');
		expect(await response.text()).toContain('PhishScope');
	});

	it('reports health metadata and mock modes', async () => {
		const response = await worker.fetch(new Request('http://example.com/api/health'), createEnv(), createCtx());
		const payload = (await response.json()) as Record<string, string>;

		expect(response.ok).toBe(true);
		expect(payload.status).toBe('ok');
		expect(payload.aiMode).toBe('mock');
		expect(payload.browserMode).toBe('mock');
		expect(payload.model).toContain('llama-3.3');
	});

	it('creates a phishing investigation case with preserved evidence', async () => {
		const env = createEnv();
		const response = await worker.fetch(
			new Request('http://example.com/api/cases', {
				body: JSON.stringify({
					analystNote: 'User reported an urgent Microsoft password reset lure.',
					url: 'https://secure-login-microsoft-example.test',
				}),
				headers: { 'content-type': 'application/json' },
				method: 'POST',
			}),
			env,
			createCtx(),
		);
		const payload = (await response.json()) as any;

		expect(response.ok).toBe(true);
		expect(payload.caseId).toMatch(/[a-f0-9-]{36}/);
		expect(payload.investigation.scanCount).toBe(1);
		expect(payload.investigation.assessment.verdict).toBeTruthy();
		expect(payload.investigation.evidence.screenshotDataUrl).toContain('data:image/');
		expect(payload.investigation.messages).toHaveLength(2);
	});

	it('supports follow-up chat and rescans within the same case', async () => {
		const env = createEnv();
		const created = (await (
			await worker.fetch(
				new Request('http://example.com/api/cases', {
					body: JSON.stringify({
						analystNote: 'Potential Cloudflare impersonation lure.',
						url: 'https://verify-cloudflare-account.example.net',
					}),
					headers: { 'content-type': 'application/json' },
					method: 'POST',
				}),
				env,
				createCtx(),
			)
		).json()) as any;

		const followUp = await worker.fetch(
			new Request(`http://example.com/api/cases/${created.caseId}/messages`, {
				body: JSON.stringify({
					message: 'Should we block this indicator immediately?',
				}),
				headers: { 'content-type': 'application/json' },
				method: 'POST',
			}),
			env,
			createCtx(),
		);
		const followUpPayload = (await followUp.json()) as any;

		expect(followUp.ok).toBe(true);
		expect(followUpPayload.investigation.messages.at(-1).role).toBe('assistant');
		expect(followUpPayload.investigation.assessment.recommendedAction).toBeTruthy();

		const rescan = await worker.fetch(
			new Request(`http://example.com/api/cases/${created.caseId}/rescan`, {
				body: JSON.stringify({
					analystNote: 'Re-scan after a second user report.',
				}),
				headers: { 'content-type': 'application/json' },
				method: 'POST',
			}),
			env,
			createCtx(),
		);
		const rescanPayload = (await rescan.json()) as any;

		expect(rescan.ok).toBe(true);
		expect(rescanPayload.investigation.scanCount).toBe(2);
		expect(rescanPayload.investigation.analystNote).toContain('second user report');
	});

	it('refuses to guess unsupported traffic-source telemetry in follow-up answers', async () => {
		const env = createEnv();
		const created = (await (
			await worker.fetch(
				new Request('http://example.com/api/cases', {
					body: JSON.stringify({
						url: 'https://job-boards.greenhouse.io/cloudflare/jobs/7296929?gh_jid=7296929',
					}),
					headers: { 'content-type': 'application/json' },
					method: 'POST',
				}),
				env,
				createCtx(),
			)
		).json()) as any;

		const followUp = await worker.fetch(
			new Request(`http://example.com/api/cases/${created.caseId}/messages`, {
				body: JSON.stringify({
					message: 'Can you identify the major traffic sources on this page?',
				}),
				headers: { 'content-type': 'application/json' },
				method: 'POST',
			}),
			env,
			createCtx(),
		);
		const followUpPayload = (await followUp.json()) as any;
		const latestReply = followUpPayload.investigation.messages.at(-1).content as string;

		expect(followUp.ok).toBe(true);
		expect(latestReply).toContain('cannot be determined');
		expect(latestReply).toContain('referrers');
		expect(latestReply).not.toContain('Greenhouse');
		expect(followUpPayload.investigation.assessment.recommendedAction).toContain('analytics');
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

function createEnv() {
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

	return env as Env;
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
	private readonly values = new Map<string, unknown>();

	async get<T>(key: string): Promise<T | undefined> {
		return this.values.get(key) as T | undefined;
	}

	async put(key: string, value: unknown): Promise<void> {
		this.values.set(key, value);
	}
}
