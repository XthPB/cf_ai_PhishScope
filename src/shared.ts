export const APP_NAME = 'Signalboard';
export const MODEL_NAME = '@cf/meta/llama-3.3-70b-instruct-fp8-fast';
export const STORAGE_KEY = 'signalboard-session';
export const MAX_SESSION_MESSAGES = 18;

export type ChatRole = 'user' | 'assistant';
export type Confidence = 'low' | 'medium' | 'high';

export interface SessionMessage {
	id: string;
	role: ChatRole;
	content: string;
	timestamp: string;
}

export interface StrategyBoard {
	projectName: string;
	objective: string;
	audience: string;
	tone: string;
	constraints: string[];
	risks: string[];
	nextActions: string[];
	confidence: Confidence;
}

export interface SessionState {
	sessionId: string;
	createdAt: string;
	updatedAt: string;
	messages: SessionMessage[];
	board: StrategyBoard;
}

export interface StrategyTurn {
	reply: string;
	highlight: string;
	followUps: string[];
	board: StrategyBoard;
}

export function createDefaultBoard(): StrategyBoard {
	return {
		projectName: 'Untitled initiative',
		objective: 'Define the result you want this assistant to help you produce.',
		audience: 'No audience captured yet.',
		tone: 'Direct and practical',
		constraints: ['Add timing, budget, compliance, or technical constraints.'],
		risks: ['No explicit risks captured yet.'],
		nextActions: ['Describe the outcome you want in one sentence.'],
		confidence: 'low',
	};
}

export function createSessionState(sessionId: string): SessionState {
	const now = new Date().toISOString();
	return {
		sessionId,
		createdAt: now,
		updatedAt: now,
		messages: [],
		board: createDefaultBoard(),
	};
}

export function createMessage(role: ChatRole, content: string, timestamp = new Date().toISOString()): SessionMessage {
	return {
		id: crypto.randomUUID(),
		role,
		content: sanitizeText(content, 2400),
		timestamp,
	};
}

export function trimMessages(messages: SessionMessage[]): SessionMessage[] {
	return messages.slice(-MAX_SESSION_MESSAGES);
}

export function sanitizeText(value: unknown, maxLength: number): string {
	if (typeof value !== 'string') {
		return '';
	}

	return value.replace(/\s+/g, ' ').trim().slice(0, maxLength);
}

export function sanitizeList(value: unknown, fallback: string[]): string[] {
	if (!Array.isArray(value)) {
		return fallback;
	}

	const normalized = value
		.map((item) => sanitizeText(item, 160))
		.filter(Boolean)
		.slice(0, 5);

	return normalized.length > 0 ? dedupe(normalized) : fallback;
}

export function normalizeBoard(input: unknown, previous = createDefaultBoard()): StrategyBoard {
	const candidate = isRecord(input) ? input : {};

	return {
		projectName: sanitizeText(candidate.projectName, 80) || previous.projectName,
		objective: sanitizeText(candidate.objective, 220) || previous.objective,
		audience: sanitizeText(candidate.audience, 180) || previous.audience,
		tone: sanitizeText(candidate.tone, 120) || previous.tone,
		constraints: sanitizeList(candidate.constraints, previous.constraints),
		risks: sanitizeList(candidate.risks, previous.risks),
		nextActions: sanitizeList(candidate.nextActions, previous.nextActions),
		confidence: normalizeConfidence(candidate.confidence, previous.confidence),
	};
}

export function normalizeTurn(input: unknown, previousBoard: StrategyBoard): StrategyTurn {
	const candidate = isRecord(input) ? input : {};
	const reply =
		sanitizeText(candidate.reply, 2400) ||
		'The board is ready. Add more context so I can sharpen the plan and next steps.';
	const highlight =
		sanitizeText(candidate.highlight, 180) ||
		'Clarify the single most important outcome before making implementation choices.';
	const followUps = sanitizeList(candidate.followUps, [
		'Who is the primary user or buyer?',
		'What deadline or milestone matters most?',
		'What constraint could block progress fastest?',
	]).slice(0, 3);

	return {
		reply,
		highlight,
		followUps,
		board: normalizeBoard(candidate.board, previousBoard),
	};
}

export function parseAiResponse(response: unknown): unknown {
	if (isRecord(response) && 'response' in response) {
		return parseAiResponse(response.response);
	}

	if (typeof response === 'string') {
		const cleaned = response.replace(/^```json\s*/i, '').replace(/```$/i, '').trim();
		try {
			return JSON.parse(cleaned);
		} catch {
			return {};
		}
	}

	return response;
}

export function buildBoardSnapshot(board: StrategyBoard): string {
	return JSON.stringify(board, null, 2);
}

export function buildTranscript(messages: SessionMessage[]): string {
	return messages
		.slice(-10)
		.map((message) => `${message.role.toUpperCase()}: ${message.content}`)
		.join('\n');
}

export function createMockTurn(message: string, previousBoard: StrategyBoard): StrategyTurn {
	const cleaned = sanitizeText(message, 300);
	const board = normalizeBoard(
		{
			projectName:
				previousBoard.projectName === 'Untitled initiative'
					? inferProjectName(cleaned) || previousBoard.projectName
					: previousBoard.projectName,
			objective:
				previousBoard.objective === createDefaultBoard().objective
					? `Shape a focused plan for: ${cleaned || 'the current initiative'}.`
					: previousBoard.objective,
			audience: previousBoard.audience,
			tone: previousBoard.tone,
			constraints:
				previousBoard.constraints[0] === createDefaultBoard().constraints[0]
					? ['Mock mode is enabled locally.', 'Add real constraints to improve the plan.']
					: previousBoard.constraints,
			risks: ['Mock mode cannot reason over a real model response.', 'Assumptions may be too generic.'],
			nextActions: [
				'Switch to remote dev or deploy to use Workers AI.',
				'Specify the primary user and success metric.',
				'Add one hard constraint to sharpen tradeoffs.',
			],
			confidence: 'low',
		},
		previousBoard,
	);

	return {
		reply: `Mock mode is active, so this response is deterministic. Based on "${cleaned || 'your latest note'}", I would tighten the objective, name the audience, and lock one constraint before expanding the plan.`,
		highlight: 'Remote Workers AI mode is needed for live reasoning.',
		followUps: [
			'Who should use this first?',
			'What should be true after one successful session?',
			'What deadline or dependency matters most?',
		],
		board,
	};
}

function inferProjectName(input: string): string {
	if (!input) {
		return '';
	}

	const words = input
		.split(' ')
		.filter(Boolean)
		.slice(0, 4)
		.map((word) => word.replace(/[^a-z0-9-]/gi, ''));

	return words.join(' ').trim();
}

function normalizeConfidence(value: unknown, fallback: Confidence): Confidence {
	if (value === 'low' || value === 'medium' || value === 'high') {
		return value;
	}

	return fallback;
}

function dedupe(items: string[]): string[] {
	return [...new Set(items)];
}

function isRecord(value: unknown): value is Record<string, any> {
	return typeof value === 'object' && value !== null;
}
