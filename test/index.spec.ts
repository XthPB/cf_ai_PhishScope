import { describe, expect, it } from 'vitest';

import worker, { ConversationSession } from '../src';

describe('Signalboard worker', () => {
	it('serves the app shell through the assets binding', async () => {
		const response = await worker.fetch(request('http://example.com/'), createEnv(), createCtx());

		expect(response.headers.get('content-type')).toContain('text/html');
		expect(await response.text()).toContain('Signalboard');
	});

	it('reports health metadata', async () => {
		const response = await worker.fetch(request('http://example.com/api/health'), createEnv(), createCtx());
		const payload = (await response.json()) as Record<string, string>;

		expect(response.ok).toBe(true);
		expect(payload.status).toBe('ok');
		expect(payload.model).toContain('llama-3.3');
	});

	it('creates and reloads a session', async () => {
		const env = createEnv();
		const createdResponse = await worker.fetch(
			request('http://example.com/api/sessions', { method: 'POST' }),
			env,
			createCtx(),
		);
		const created = (await createdResponse.json()) as any;

		expect(createdResponse.ok).toBe(true);
		expect(created.sessionId).toMatch(/[a-f0-9-]{36}/);
		expect(created.session.messages).toEqual([]);

		const loadedResponse = await worker.fetch(
			request(`http://example.com/api/sessions/${created.sessionId}`),
			env,
			createCtx(),
		);
		const loaded = (await loadedResponse.json()) as any;

		expect(loadedResponse.ok).toBe(true);
		expect(loaded.session.sessionId).toBe(created.sessionId);
		expect(loaded.session.board.projectName).toBeTruthy();
	});

	it('stores a user turn and updates the board in mock mode', async () => {
		const env = createEnv();
		const created = (await (
			await worker.fetch(request('http://example.com/api/sessions', { method: 'POST' }), env, createCtx())
		).json()) as any;

		const response = await worker.fetch(
			request(`http://example.com/api/sessions/${created.sessionId}/messages`, {
				body: JSON.stringify({
					message:
						'Help me scope an AI onboarding assistant for a B2B SaaS product with a three-week deadline and a small team.',
				}),
				headers: { 'content-type': 'application/json' },
				method: 'POST',
			}),
			env,
			createCtx(),
		);
		const payload = (await response.json()) as any;

		expect(response.ok).toBe(true);
		expect(payload.mode).toBe('mock');
		expect(payload.session.messages).toHaveLength(2);
		expect(payload.session.messages[0].role).toBe('user');
		expect(payload.session.messages[1].role).toBe('assistant');
		expect(payload.session.board.nextActions.length).toBeGreaterThan(0);
		expect(payload.highlight).toBeTruthy();
	});
});

function createEnv() {
	const storageById = new Map<string, MockDurableObjectState>();

	const env: Record<string, any> = {
		AI: {
			run: async () => {
				throw new Error('AI binding is intentionally mocked for local tests.');
			},
		},
		ASSETS: {
			fetch: async () =>
				new Response('<!doctype html><html><head><title>Signalboard</title></head><body>Signalboard</body></html>', {
					headers: { 'content-type': 'text/html; charset=utf-8' },
				}),
		},
		MOCK_AI: 'true',
	};

	env.SESSIONS = {
		get(id: string) {
			if (!storageById.has(id)) {
				storageById.set(id, new MockDurableObjectState());
			}

			const state = storageById.get(id)!;
			const instance = new ConversationSession(state as unknown as DurableObjectState, env as Env);
			return {
				fetch: (req: Request) => instance.fetch(req),
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

function request(url: string, init?: RequestInit): Request {
	return new Request(url, init);
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
