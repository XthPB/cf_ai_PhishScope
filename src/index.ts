import {
	APP_NAME,
	MODEL_NAME,
	STORAGE_KEY,
	buildBoardSnapshot,
	createMessage,
	createMockTurn,
	createSessionState,
	normalizeTurn,
	parseAiResponse,
	sanitizeText,
	trimMessages,
	type SessionState,
	type StrategyTurn,
} from './shared';

interface AiBinding {
	run(model: string, input: Record<string, unknown>): Promise<unknown>;
}

type AppEnv = Env;

const TURN_RESPONSE_FORMAT = {
	type: 'json_schema',
	json_schema: {
		type: 'object',
		properties: {
			reply: { type: 'string' },
			highlight: { type: 'string' },
			followUps: {
				type: 'array',
				items: { type: 'string' },
			},
			board: {
				type: 'object',
				properties: {
					projectName: { type: 'string' },
					objective: { type: 'string' },
					audience: { type: 'string' },
					tone: { type: 'string' },
					constraints: { type: 'array', items: { type: 'string' } },
					risks: { type: 'array', items: { type: 'string' } },
					nextActions: { type: 'array', items: { type: 'string' } },
					confidence: { type: 'string', enum: ['low', 'medium', 'high'] },
				},
				required: ['projectName', 'objective', 'audience', 'tone', 'constraints', 'risks', 'nextActions', 'confidence'],
			},
		},
		required: ['reply', 'highlight', 'followUps', 'board'],
	},
} as const;

const SYSTEM_PROMPT = `You are Signalboard, a pragmatic launch strategist running on Cloudflare.

Help the user turn rough product, campaign, or workflow ideas into a clear plan.

Rules:
- Be concise, specific, and practical.
- State tradeoffs instead of hiding them.
- Update the board with durable memory from the conversation.
- Keep constraints, risks, and next actions concrete.
- If the user is vague, ask sharp follow-up questions in the reply and followUps fields.
- Never mention the JSON schema or internal formatting in the reply.`;

export default {
	async fetch(request, env): Promise<Response> {
		const url = new URL(request.url);

		if (request.method === 'GET' && url.pathname === '/api/health') {
			return jsonResponse({
				app: APP_NAME,
				model: MODEL_NAME,
				mode: shouldUseMockAi(env) ? 'mock' : 'workers-ai',
				status: 'ok',
				timestamp: new Date().toISOString(),
			});
		}

		if (request.method === 'POST' && url.pathname === '/api/sessions') {
			return createSession(env);
		}

		const sessionMatch = url.pathname.match(/^\/api\/sessions\/([^/]+)(?:\/(messages|reset))?$/);
		if (sessionMatch) {
			const [, sessionId, action] = sessionMatch;
			return handleSessionRoute(request, env, sessionId, action);
		}

		return env.ASSETS.fetch(request);
	},
} satisfies ExportedHandler<AppEnv>;

export class ConversationSession implements DurableObject {
	constructor(
		private readonly state: DurableObjectState,
		private readonly env: AppEnv,
	) {}

	async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url);

		if (request.method === 'POST' && url.pathname === '/initialize') {
			const body = await readJson<{ sessionId?: string }>(request);
			const session = await this.loadState(body?.sessionId);
			return jsonResponse({ session });
		}

		if (request.method === 'GET' && url.pathname === '/state') {
			const session = await this.loadState();
			return jsonResponse({ session });
		}

		if (request.method === 'POST' && url.pathname === '/messages') {
			return this.handleMessage(request);
		}

		if (request.method === 'POST' && url.pathname === '/reset') {
			const existing = await this.loadState();
			const session = createSessionState(existing.sessionId);
			await this.persistState(session);
			return jsonResponse({ session });
		}

		return errorResponse(404, 'Session route not found.');
	}

	private async handleMessage(request: Request): Promise<Response> {
		const payload = await readJson<{ message?: string }>(request);
		const content = sanitizeText(payload?.message, 1200);
		if (!content) {
			return errorResponse(400, 'Message is required.');
		}

		const session = await this.loadState();
		const userMessage = createMessage('user', content);
		session.messages = trimMessages([...session.messages, userMessage]);
		session.updatedAt = userMessage.timestamp;

		const turn = await createStrategyTurn(this.env, session, content);
		const assistantMessage = createMessage('assistant', turn.reply);
		session.messages = trimMessages([...session.messages, assistantMessage]);
		session.board = turn.board;
		session.updatedAt = assistantMessage.timestamp;

		await this.persistState(session);

		return jsonResponse({
			followUps: turn.followUps,
			highlight: turn.highlight,
			mode: shouldUseMockAi(this.env) ? 'mock' : 'workers-ai',
			model: MODEL_NAME,
			session,
		});
	}

	private async loadState(sessionId?: string): Promise<SessionState> {
		const existing = await this.state.storage.get<SessionState>(STORAGE_KEY);
		if (existing) {
			return existing;
		}

		const session = createSessionState(sessionId ?? crypto.randomUUID());
		await this.persistState(session);
		return session;
	}

	private async persistState(session: SessionState): Promise<void> {
		await this.state.storage.put(STORAGE_KEY, {
			...session,
			messages: trimMessages(session.messages),
		});
	}
}

async function createSession(env: AppEnv): Promise<Response> {
	const sessionId = crypto.randomUUID();
	const response = await sendToSession(
		env,
		sessionId,
		new Request('https://session/initialize', {
			body: JSON.stringify({ sessionId }),
			headers: { 'content-type': 'application/json' },
			method: 'POST',
		}),
	);
	const payload = (await response.json()) as { session: SessionState };

	return jsonResponse({
		...payload,
		mode: shouldUseMockAi(env) ? 'mock' : 'workers-ai',
		model: MODEL_NAME,
		sessionId,
	});
}

async function handleSessionRoute(
	request: Request,
	env: AppEnv,
	sessionId: string,
	action?: string,
): Promise<Response> {
	if (!sessionId) {
		return errorResponse(400, 'Session id is required.');
	}

	if (request.method === 'GET' && !action) {
		return sendToSession(env, sessionId, new Request('https://session/state'));
	}

	if (request.method === 'POST' && action === 'messages') {
		return sendJsonToSession(env, sessionId, '/messages', request);
	}

	if (request.method === 'POST' && action === 'reset') {
		return sendJsonToSession(env, sessionId, '/reset', request);
	}

	return errorResponse(405, 'Method not allowed for this session route.');
}

async function sendJsonToSession(env: AppEnv, sessionId: string, path: string, request: Request): Promise<Response> {
	const body = request.method === 'GET' ? undefined : await request.text();
	return sendToSession(
		env,
		sessionId,
		new Request(`https://session${path}`, {
			body,
			headers: { 'content-type': 'application/json' },
			method: request.method,
		}),
	);
}

async function sendToSession(env: AppEnv, sessionId: string, request: Request): Promise<Response> {
	const id = env.SESSIONS.idFromName(sessionId);
	const stub = env.SESSIONS.get(id);
	return stub.fetch(request);
}

async function createStrategyTurn(env: AppEnv, session: SessionState, latestMessage: string): Promise<StrategyTurn> {
	if (shouldUseMockAi(env)) {
		return createMockTurn(latestMessage, session.board);
	}

	try {
		const ai = env.AI as unknown as AiBinding;
		const modelResponse = await ai.run(MODEL_NAME, {
			messages: [
				{
					role: 'system',
					content: `${SYSTEM_PROMPT}\n\nCurrent board JSON:\n${buildBoardSnapshot(session.board)}`,
				},
				...session.messages.slice(-8).map((message) => ({
					content: message.content,
					role: message.role,
				})),
			],
			max_tokens: 700,
			response_format: TURN_RESPONSE_FORMAT,
			temperature: 0.6,
		});

		return normalizeTurn(parseAiResponse(modelResponse), session.board);
	} catch (error) {
		console.warn('Workers AI call failed, falling back to mock turn.', error);
		return createMockTurn(latestMessage, session.board);
	}
}

function shouldUseMockAi(env: AppEnv): boolean {
	const ai = env.AI as unknown as AiBinding | undefined;
	return String(env.MOCK_AI) === 'true' || !ai || typeof ai.run !== 'function';
}

async function readJson<T>(request: Request): Promise<T | null> {
	if (request.method === 'GET') {
		return null;
	}

	try {
		return (await request.json<T>()) ?? null;
	} catch {
		return null;
	}
}

function errorResponse(status: number, error: string): Response {
	return jsonResponse({ error }, { status });
}

function jsonResponse(data: unknown, init: ResponseInit = {}): Response {
	const headers = new Headers(init.headers);
	headers.set('content-type', 'application/json; charset=utf-8');
	headers.set('cache-control', 'no-store');

	return new Response(JSON.stringify(data), {
		...init,
		headers,
	});
}
