import {
	APP_NAME,
	MODEL_NAME,
	STORAGE_KEY,
	buildAssessmentSnapshot,
	buildEvidenceSnapshot,
	buildTranscript,
	createCaseEvent,
	createDefaultAssessment,
	createDefaultEvidence,
	createInvestigationState,
	createMessage,
	createMockInvestigation,
	deriveCaseStatus,
	getHostname,
	normalizeAssessment,
	normalizeEvidence,
	normalizeFollowUpTurn,
	normalizeUrl,
	parseAiResponse,
	sanitizeText,
	trimEvents,
	trimMessages,
	type CaseListItem,
	type CaseStatus,
	type FollowUpTurn,
	type InvestigationAssessment,
	type InvestigationState,
	type RenderEvidence,
} from './shared';
import { findRelatedCases, getDashboardSummary, listIndexedCases, trackMetric, upsertIndexedCase } from './platform';

interface AiBinding {
	run(model: string, input: Record<string, unknown>): Promise<unknown>;
}

interface TurnstileVerificationResponse {
	action?: string;
	'error-codes'?: string[];
	hostname?: string;
	success?: boolean;
}

type AppEnv = Env & {
	ANALYTICS?: AnalyticsEngineDataset;
	CREATE_LIMITER?: RateLimit;
	DB?: D1Database;
	FOLLOWUP_LIMITER?: RateLimit;
	TURNSTILE_SECRET_KEY?: string;
	TURNSTILE_SITE_KEY?: string;
};

const ANALYSIS_RESPONSE_FORMAT = {
	type: 'json_schema',
	json_schema: {
		type: 'object',
		properties: {
			verdict: { type: 'string', enum: ['malicious', 'suspicious', 'benign', 'inconclusive'] },
			riskScore: { type: 'number' },
			confidence: { type: 'string', enum: ['low', 'medium', 'high'] },
			executiveSummary: { type: 'string' },
			highlight: { type: 'string' },
			impersonatedBrand: { type: 'string' },
			recommendedAction: { type: 'string' },
			suspiciousSignals: {
				type: 'array',
				items: { type: 'string' },
			},
			benignSignals: {
				type: 'array',
				items: { type: 'string' },
			},
			analystQuestions: {
				type: 'array',
				items: { type: 'string' },
			},
		},
		required: [
			'verdict',
			'riskScore',
			'confidence',
			'executiveSummary',
			'highlight',
			'impersonatedBrand',
			'recommendedAction',
			'suspiciousSignals',
			'benignSignals',
			'analystQuestions',
		],
	},
} as const;

const FOLLOW_UP_RESPONSE_FORMAT = {
	type: 'json_schema',
	json_schema: {
		type: 'object',
		properties: {
			reply: { type: 'string' },
			highlight: { type: 'string' },
			recommendedAction: { type: 'string' },
			analystQuestions: {
				type: 'array',
				items: { type: 'string' },
			},
		},
		required: ['reply', 'highlight', 'recommendedAction', 'analystQuestions'],
	},
} as const;

const ANALYSIS_SYSTEM_PROMPT = `You are PhishScope, an expert phishing triage analyst running on Cloudflare.

Rules:
- Base your verdict only on the supplied evidence and analyst note.
- Prefer conservative, defensible reasoning over dramatic claims.
- Focus on credential theft, brand impersonation, redirect behavior, form collection, and domain mismatch.
- Keep the summary tight and useful for a human security analyst.
- Use malicious only when the evidence strongly supports phishing or credential capture.
- Use suspicious when the evidence is concerning but not fully conclusive.
- Use benign when the evidence points away from phishing.
- Use inconclusive when the rendered evidence is too weak to decide.`;

const FOLLOW_UP_SYSTEM_PROMPT = `You are PhishScope, a phishing investigation copilot.

Rules:
- Answer using the case evidence, existing verdict, analyst note, and recent transcript.
- Do not invent telemetry you were not given.
- If the analyst asks about traffic sources, referrers, campaign origin, visitor analytics, or other telemetry not present in the case evidence, say that directly and ask for the relevant logs or analytics instead of guessing.
- Provide short, analyst-facing reasoning.
- If the analyst asks for an action, recommend block, monitor, rescan, or human review as appropriate.`;

export default {
	async fetch(request, env): Promise<Response> {
		const url = new URL(request.url);

		if (request.method === 'GET' && url.pathname === '/api/health') {
			return jsonResponse({
				app: APP_NAME,
				browserMode: shouldUseMockBrowser(env) ? 'mock' : 'browser-rendering',
				features: {
					analytics: Boolean(env.ANALYTICS),
					caseIndex: Boolean(env.DB),
					rateLimit: Boolean(env.CREATE_LIMITER && env.FOLLOWUP_LIMITER),
					scheduledRescans: true,
					turnstile: Boolean(env.TURNSTILE_SITE_KEY && env.TURNSTILE_SECRET_KEY),
				},
				model: MODEL_NAME,
				aiMode: shouldUseMockAi(env) ? 'mock' : 'workers-ai',
				status: 'ok',
				timestamp: new Date().toISOString(),
				turnstileSiteKey: env.TURNSTILE_SITE_KEY || '',
			});
		}

		if (request.method === 'GET' && url.pathname === '/api/dashboard') {
			return jsonResponse({
				dashboard: await getDashboardSummary(env),
			});
		}

		if (request.method === 'GET' && url.pathname === '/api/cases') {
			return listCases(request, env);
		}

		if (request.method === 'POST' && url.pathname === '/api/cases') {
			return createCase(request, env);
		}

		const caseMatch = url.pathname.match(/^\/api\/cases\/([^/]+)(?:\/(messages|rescan|schedule-rescan))?$/);
		if (caseMatch) {
			const [, caseId, action] = caseMatch;
			return handleCaseRoute(request, env, caseId, action);
		}

		return env.ASSETS.fetch(request);
	},
} satisfies ExportedHandler<AppEnv>;

export class InvestigationCase implements DurableObject {
	constructor(
		private readonly state: DurableObjectState,
		private readonly env: AppEnv,
	) {}

	async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url);

		if (request.method === 'POST' && url.pathname === '/initialize') {
			return this.initializeCase(request);
		}

		if (request.method === 'GET' && url.pathname === '/state') {
			const investigation = await this.loadState();
			return this.caseResponse(investigation);
		}

		if (request.method === 'POST' && url.pathname === '/rescan') {
			return this.rescan(request);
		}

		if (request.method === 'POST' && url.pathname === '/schedule-rescan') {
			return this.scheduleRescan(request);
		}

		if (request.method === 'POST' && url.pathname === '/messages') {
			return this.handleMessage(request);
		}

		return errorResponse(404, 'Case route not found.');
	}

	private async initializeCase(request: Request): Promise<Response> {
		const payload = await readJson<{ analystNote?: string; caseId?: string; url?: string }>(request);
		const targetUrl = normalizeUrl(payload?.url);
		if (!targetUrl) {
			return errorResponse(400, 'A valid http or https URL is required.');
		}

		const caseId = sanitizeText(payload?.caseId, 64) || crypto.randomUUID();
		const analystNote = sanitizeText(payload?.analystNote, 320);
		let investigation = createInvestigationState(caseId, targetUrl, analystNote);
		const userMessage = createMessage(
			'user',
			analystNote ? `Investigate ${targetUrl}. Analyst note: ${analystNote}` : `Investigate ${targetUrl}.`,
		);
		investigation.messages = [userMessage];

		const analysis = await runInvestigation(this.env, targetUrl, analystNote);
		const assistantMessage = createMessage('assistant', analysis.reply);
		const timeline = trimEvents([
			createCaseEvent('case-opened', 'Case opened and queued for analysis.', {
				actor: 'analyst',
				detail: targetUrl,
				timestamp: userMessage.timestamp,
			}),
			createCaseEvent('analysis-completed', `Initial assessment completed with ${analysis.assessment.verdict} verdict.`, {
				detail: analysis.assessment.highlight,
				timestamp: assistantMessage.timestamp,
			}),
		]);
		investigation = {
			...investigation,
			assessment: analysis.assessment,
			evidence: analysis.evidence,
			latestReply: analysis.reply,
			messages: trimMessages([...investigation.messages, assistantMessage]),
			scanCount: 1,
			status: deriveCaseStatus(analysis.assessment.verdict),
			tags: deriveCaseTags(analysis.evidence, analysis.assessment),
			targetUrl,
			timeline,
			updatedAt: assistantMessage.timestamp,
		};

		await this.persistState(investigation);
		trackMetric(this.env, 'case_opened', investigation, {
			source: shouldUseMockAi(this.env) ? 'mock' : 'workers-ai',
		});

		return this.caseResponse(investigation);
	}

	private async rescan(request: Request): Promise<Response> {
		const payload = await readJson<{ analystNote?: string; url?: string }>(request);
		const investigation = await this.loadState();
		const targetUrl = normalizeUrl(payload?.url) || investigation.targetUrl;
		const analystNote = sanitizeText(payload?.analystNote, 320) || investigation.analystNote;
		const rescanMessage = createMessage(
			'user',
			analystNote
				? `Rescan ${targetUrl}. Updated analyst note: ${analystNote}`
				: `Rescan ${targetUrl} with the current case context.`,
		);
		const analysis = await runInvestigation(this.env, targetUrl, analystNote);
		const assistantMessage = createMessage('assistant', analysis.reply);

		const nextState: InvestigationState = {
			...investigation,
			analystNote,
			assessment: analysis.assessment,
			evidence: analysis.evidence,
			latestReply: analysis.reply,
			messages: trimMessages([...investigation.messages, rescanMessage, assistantMessage]),
			scheduledRescanAt: '',
			scanCount: investigation.scanCount + 1,
			status: deriveCaseStatus(analysis.assessment.verdict),
			tags: deriveCaseTags(analysis.evidence, analysis.assessment),
			targetUrl,
			timeline: trimEvents([
				...investigation.timeline,
				createCaseEvent('rescan-requested', 'Manual rescan requested by analyst.', {
					actor: 'analyst',
					detail: analystNote || targetUrl,
					timestamp: rescanMessage.timestamp,
				}),
				createCaseEvent('rescan-completed', `Manual rescan completed with ${analysis.assessment.verdict} verdict.`, {
					detail: analysis.assessment.highlight,
					timestamp: assistantMessage.timestamp,
				}),
			]),
			updatedAt: assistantMessage.timestamp,
		};

		await this.persistState(nextState);
		trackMetric(this.env, 'manual_rescan_completed', nextState, {
			scanCount: nextState.scanCount,
		});

		return this.caseResponse(nextState);
	}

	private async handleMessage(request: Request): Promise<Response> {
		const payload = await readJson<{ message?: string }>(request);
		const question = sanitizeText(payload?.message, 1200);
		if (!question) {
			return errorResponse(400, 'A follow-up question is required.');
		}

		const investigation = await this.loadState();
		const userMessage = createMessage('user', question);
		investigation.messages = trimMessages([...investigation.messages, userMessage]);
		investigation.updatedAt = userMessage.timestamp;

		const followUp = await answerFollowUp(this.env, investigation, question);
		const assistantMessage = createMessage('assistant', followUp.reply);
		investigation.messages = trimMessages([...investigation.messages, assistantMessage]);
		investigation.latestReply = followUp.reply;
		investigation.assessment = {
			...investigation.assessment,
			analystQuestions: followUp.analystQuestions,
			highlight: followUp.highlight,
			recommendedAction: followUp.recommendedAction,
		};
		investigation.tags = deriveCaseTags(investigation.evidence, investigation.assessment);
		investigation.timeline = trimEvents([
			...investigation.timeline,
			createCaseEvent('follow-up-asked', 'Analyst asked a follow-up question.', {
				actor: 'analyst',
				detail: question,
				timestamp: userMessage.timestamp,
			}),
			createCaseEvent('follow-up-answered', 'PhishScope generated a follow-up response.', {
				detail: followUp.highlight,
				timestamp: assistantMessage.timestamp,
			}),
		]);
		investigation.updatedAt = assistantMessage.timestamp;

		await this.persistState(investigation);
		trackMetric(this.env, 'follow_up_completed', investigation, {
			questionLength: question.length,
		});

		return this.caseResponse(investigation, { followUp });
	}

	private async scheduleRescan(request: Request): Promise<Response> {
		const payload = await readJson<{ analystNote?: string; delaySeconds?: number; url?: string }>(request);
		const investigation = await this.loadState();
		const delaySeconds = clampScheduledDelay(payload?.delaySeconds);
		const alarmAt = Date.now() + delaySeconds * 1000;
		const alarmTimestamp = new Date(alarmAt).toISOString();

		if (payload?.analystNote) {
			investigation.analystNote = sanitizeText(payload.analystNote, 320);
		}
		if (payload?.url) {
			investigation.targetUrl = normalizeUrl(payload.url) || investigation.targetUrl;
		}

		investigation.scheduledRescanAt = alarmTimestamp;
		investigation.timeline = trimEvents([
			...investigation.timeline,
			createCaseEvent('rescan-scheduled', `Scheduled an automated rescan for ${alarmTimestamp}.`, {
				actor: 'analyst',
				detail: `Delay ${delaySeconds}s`,
			}),
		]);
		investigation.updatedAt = new Date().toISOString();
		await this.state.storage.setAlarm(alarmAt);
		await this.persistState(investigation);
		trackMetric(this.env, 'scheduled_rescan_created', investigation, {
			delaySeconds,
		});

		return this.caseResponse(investigation, {
			scheduledRescan: {
				delaySeconds,
				runAt: alarmTimestamp,
			},
		});
	}

	async alarm(): Promise<void> {
		let investigation: InvestigationState;
		try {
			investigation = await this.loadState();
		} catch {
			return;
		}

		const analysis = await runInvestigation(this.env, investigation.targetUrl, investigation.analystNote);
		const systemMessage = createMessage(
			'assistant',
			`Scheduled rescan completed. ${analysis.reply}`,
		);
		const nextState: InvestigationState = {
			...investigation,
			assessment: analysis.assessment,
			evidence: analysis.evidence,
			latestReply: analysis.reply,
			messages: trimMessages([...investigation.messages, systemMessage]),
			scheduledRescanAt: '',
			scanCount: investigation.scanCount + 1,
			status: deriveCaseStatus(analysis.assessment.verdict),
			tags: deriveCaseTags(analysis.evidence, analysis.assessment),
			timeline: trimEvents([
				...investigation.timeline,
				createCaseEvent('scheduled-rescan-completed', `Scheduled rescan completed with ${analysis.assessment.verdict} verdict.`, {
					actor: 'automation',
					detail: analysis.assessment.highlight,
					timestamp: systemMessage.timestamp,
				}),
			]),
			updatedAt: systemMessage.timestamp,
		};

		await this.persistState(nextState);
		trackMetric(this.env, 'scheduled_rescan_completed', nextState, {
			scanCount: nextState.scanCount,
		});
	}

	private async loadState(): Promise<InvestigationState> {
		const existing = await this.state.storage.get<InvestigationState>(STORAGE_KEY);
		if (existing) {
			return hydrateInvestigationState(existing);
		}

		throw new Error('Case not initialized.');
	}

	private async persistState(investigation: InvestigationState): Promise<void> {
		const nextState = hydrateInvestigationState({
			...investigation,
			messages: trimMessages(investigation.messages),
			timeline: trimEvents(investigation.timeline),
		});
		await this.state.storage.put(STORAGE_KEY, nextState);
		await upsertIndexedCase(this.env, nextState);
	}

	private async caseResponse(
		investigation: InvestigationState,
		extra: Record<string, unknown> = {},
	): Promise<Response> {
		return jsonResponse({
			caseId: investigation.caseId,
			investigation,
			model: MODEL_NAME,
			mode: {
				ai: shouldUseMockAi(this.env) ? 'mock' : 'workers-ai',
				browser: shouldUseMockBrowser(this.env) ? 'mock' : 'browser-rendering',
			},
			relatedCases: await findRelatedCases(this.env, investigation),
			...extra,
		});
	}
}

async function createCase(request: Request, env: AppEnv): Promise<Response> {
	const limitResponse = await enforceRateLimit(env.CREATE_LIMITER, request, 'create_case');
	if (limitResponse) {
		trackMetric(env, 'rate_limited', undefined, { route: 'create_case' });
		return limitResponse;
	}

	const payload = await readJson<{ analystNote?: string; turnstileToken?: string; url?: string }>(request);
	const targetUrl = normalizeUrl(payload?.url);
	if (!targetUrl) {
		return errorResponse(400, 'A valid http or https URL is required.');
	}

	if (!(await verifyTurnstile(env, request, payload?.turnstileToken))) {
		trackMetric(env, 'turnstile_rejected', undefined, { route: 'create_case' });
		return errorResponse(403, 'Human verification failed.');
	}

	const caseId = crypto.randomUUID();
	const response = await sendToCase(
		env,
		caseId,
		new Request('https://case/initialize', {
			body: JSON.stringify({
				analystNote: sanitizeText(payload?.analystNote, 320),
				caseId,
				url: targetUrl,
			}),
			headers: { 'content-type': 'application/json' },
			method: 'POST',
		}),
	);
	const payloadJson = (await response.json()) as { caseId: string; investigation: InvestigationState };

	return jsonResponse({
		...payloadJson,
		mode: {
			ai: shouldUseMockAi(env) ? 'mock' : 'workers-ai',
			browser: shouldUseMockBrowser(env) ? 'mock' : 'browser-rendering',
		},
		model: MODEL_NAME,
	});
}

async function listCases(request: Request, env: AppEnv): Promise<Response> {
	const url = new URL(request.url);
	return jsonResponse({
		cases: await listIndexedCases(env, {
			limit: Number(url.searchParams.get('limit') || 24),
			search: url.searchParams.get('search') || '',
			status: url.searchParams.get('status') || '',
			verdict: url.searchParams.get('verdict') || '',
		}),
	});
}

async function handleCaseRoute(request: Request, env: AppEnv, caseId: string, action?: string): Promise<Response> {
	if (!caseId) {
		return errorResponse(400, 'Case id is required.');
	}

	if (request.method === 'GET' && !action) {
		return sendToCase(env, caseId, new Request('https://case/state'));
	}

	if (request.method === 'POST' && action === 'rescan') {
		const limitResponse = await enforceRateLimit(env.FOLLOWUP_LIMITER, request, 'rescan_case');
		if (limitResponse) {
			trackMetric(env, 'rate_limited', undefined, { route: 'rescan_case' });
			return limitResponse;
		}
		return proxyJsonToCase(env, caseId, '/rescan', request);
	}

	if (request.method === 'POST' && action === 'messages') {
		const limitResponse = await enforceRateLimit(env.FOLLOWUP_LIMITER, request, 'follow_up');
		if (limitResponse) {
			trackMetric(env, 'rate_limited', undefined, { route: 'follow_up' });
			return limitResponse;
		}
		return proxyJsonToCase(env, caseId, '/messages', request);
	}

	if (request.method === 'POST' && action === 'schedule-rescan') {
		const limitResponse = await enforceRateLimit(env.FOLLOWUP_LIMITER, request, 'schedule_rescan');
		if (limitResponse) {
			trackMetric(env, 'rate_limited', undefined, { route: 'schedule_rescan' });
			return limitResponse;
		}
		return proxyJsonToCase(env, caseId, '/schedule-rescan', request);
	}

	return errorResponse(405, 'Method not allowed for this case route.');
}

async function proxyJsonToCase(env: AppEnv, caseId: string, path: string, request: Request): Promise<Response> {
	const body = request.method === 'GET' ? undefined : await request.text();
	return sendToCase(
		env,
		caseId,
		new Request(`https://case${path}`, {
			body,
			headers: { 'content-type': 'application/json' },
			method: request.method,
		}),
	);
}

async function sendToCase(env: AppEnv, caseId: string, request: Request): Promise<Response> {
	const id = env.CASES.idFromName(caseId);
	const stub = env.CASES.get(id);
	return stub.fetch(request);
}

async function runInvestigation(
	env: AppEnv,
	targetUrl: string,
	analystNote: string,
): Promise<{ assessment: InvestigationAssessment; evidence: RenderEvidence; reply: string }> {
	if (shouldUseMockBrowser(env) && shouldUseMockAi(env)) {
		return createMockInvestigation(targetUrl, analystNote);
	}

	const evidence = shouldUseMockBrowser(env)
		? createMockInvestigation(targetUrl, analystNote).evidence
		: await captureEvidence(env, targetUrl);

	if (shouldUseMockAi(env)) {
		const assessment = createFallbackAssessment(evidence, analystNote);
		return {
			assessment,
			evidence,
			reply: assessment.executiveSummary,
		};
	}

	try {
		const ai = env.AI as unknown as AiBinding;
		const response = await ai.run(MODEL_NAME, {
			messages: [
				{
					role: 'system',
					content: ANALYSIS_SYSTEM_PROMPT,
				},
				{
					role: 'user',
					content: `Analyst note: ${analystNote || 'No analyst note supplied.'}\n\nRendered evidence JSON:\n${buildEvidenceSnapshot(evidence)}`,
				},
			],
			max_tokens: 900,
			response_format: ANALYSIS_RESPONSE_FORMAT,
			temperature: 0.2,
		});
		const assessment = normalizeAssessment(parseAiResponse(response), createFallbackAssessment(evidence, analystNote));
		return {
			assessment,
			evidence,
			reply: assessment.executiveSummary,
		};
	} catch (error) {
		console.warn('Workers AI assessment failed, falling back to heuristic analysis.', error);
		const assessment = createFallbackAssessment(evidence, analystNote);
		return {
			assessment,
			evidence,
			reply: assessment.executiveSummary,
		};
	}
}

async function answerFollowUp(env: AppEnv, investigation: InvestigationState, question: string): Promise<FollowUpTurn> {
	const telemetryGuardrail = createUnsupportedTelemetryFollowUp(investigation, question);
	if (telemetryGuardrail) {
		return telemetryGuardrail;
	}

	if (shouldUseMockAi(env)) {
		return createMockFollowUp(investigation, question);
	}

	try {
		const ai = env.AI as unknown as AiBinding;
		const response = await ai.run(MODEL_NAME, {
			messages: [
				{
					role: 'system',
					content: FOLLOW_UP_SYSTEM_PROMPT,
				},
				{
					role: 'user',
					content: `Analyst note: ${investigation.analystNote || 'None'}\n\nCurrent assessment JSON:\n${buildAssessmentSnapshot(investigation.assessment)}\n\nEvidence JSON:\n${buildEvidenceSnapshot(investigation.evidence)}\n\nRecent transcript:\n${buildTranscript(investigation.messages)}\n\nNew analyst question: ${question}`,
				},
			],
			max_tokens: 700,
			response_format: FOLLOW_UP_RESPONSE_FORMAT,
			temperature: 0.25,
		});

		return normalizeFollowUpTurn(parseAiResponse(response));
	} catch (error) {
		console.warn('Workers AI follow-up failed, falling back to heuristic response.', error);
		return createMockFollowUp(investigation, question);
	}
}

async function captureEvidence(env: AppEnv, targetUrl: string): Promise<RenderEvidence> {
	const { default: puppeteer } = await import('@cloudflare/puppeteer');
	const browser = await puppeteer.launch(env.BROWSER, { keep_alive: 60_000 });

	try {
		const page = await browser.newPage();
		await page.setViewport({ width: 1440, height: 960 });
		await page.goto(targetUrl, { timeout: 20_000, waitUntil: 'networkidle2' });

		const finalUrl = normalizeUrl(page.url()) || targetUrl;
		const pageTitle = sanitizeText(await page.title(), 140) || 'Untitled page';
		const captureTimestamp = new Date().toISOString();
		const screenshot = (await page.screenshot({
			fullPage: false,
			quality: 60,
			type: 'jpeg',
		})) as Uint8Array;
		const pageEvidence = (await page.evaluate(() => {
			const collectText = () =>
				(document.body?.innerText || '')
					.replace(/\s+/g, ' ')
					.trim()
					.slice(0, 1800);

			const forms = Array.from(document.forms)
				.slice(0, 6)
				.map((form) => ({
					action: form.action ? String(form.action).slice(0, 240) : '',
					hasPassword: Boolean(form.querySelector('input[type="password"]')),
					inputTypes: Array.from(form.querySelectorAll('input'))
						.map((input) => (input.getAttribute('type') || 'text').slice(0, 24))
						.filter(Boolean)
						.slice(0, 8),
					method: (form.method || 'get').slice(0, 20).toLowerCase(),
				}));

			const topLinks = Array.from(document.querySelectorAll('a[href]'))
				.slice(0, 24)
				.map((link) => {
					const href = link.getAttribute('href') || '';
					try {
						const resolved = new URL(href, window.location.href);
						return {
							href: resolved.toString().slice(0, 320),
							hostname: resolved.hostname.slice(0, 120),
							text: (link.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 80),
						};
					} catch {
						return null;
					}
				})
				.filter(Boolean);

			const hintSources = Array.from(document.querySelectorAll('h1, h2, h3, title, button, label, img[alt]'))
				.map((node) => ('alt' in node ? node.getAttribute('alt') : node.textContent) || '')
				.map((value) => value.replace(/\s+/g, ' ').trim())
				.filter(Boolean)
				.slice(0, 10);

			return {
				forms,
				textExcerpt: collectText(),
				topLinks,
				visibleBrandHints: [...new Set(hintSources)].slice(0, 6),
			};
		})) as {
			forms: RenderEvidence['forms'];
			textExcerpt: string;
			topLinks: RenderEvidence['topLinks'];
			visibleBrandHints: string[];
		};

		const classifiedForms = pageEvidence.forms.map((form) => ({
			...form,
			classification: classifyForm(form.inputTypes, form.hasPassword),
		}));
		const classifiedLinks = pageEvidence.topLinks.map((link) => ({
			...link,
			classification: classifyLink(link.hostname, finalUrl, pageEvidence.visibleBrandHints),
		}));
		const hashes = await computeEvidenceHashes({
			finalUrl,
			pageTitle,
			requestedUrl: targetUrl,
			screenshotBytes: screenshot,
			textExcerpt: pageEvidence.textExcerpt,
			topLinks: classifiedLinks,
		});

		return normalizeEvidence({
			captureTimestamp,
			finalUrl,
			forms: classifiedForms,
			hashes,
			pageTitle,
			linkSummary: summarizeLinks(classifiedLinks),
			redirected: finalUrl !== targetUrl,
			requestedUrl: targetUrl,
			screenshotDataUrl: `data:image/jpeg;base64,${Buffer.from(screenshot).toString('base64')}`,
			structuralSignals: detectStructuralSignals(targetUrl, finalUrl, pageTitle, pageEvidence.textExcerpt, classifiedForms),
			textExcerpt: pageEvidence.textExcerpt,
			topLinks: classifiedLinks,
			visibleBrandHints: pageEvidence.visibleBrandHints,
		});
	} finally {
		await browser.close();
	}
}

function createFallbackAssessment(evidence: RenderEvidence, analystNote: string): InvestigationAssessment {
	const suspiciousSignals = evidence.structuralSignals.filter(
		(signal) => !/no dominant structural phishing indicator/i.test(signal),
	);
	const benignSignals: string[] = [];
	let riskScore = 14;
	const hasPasswordForm = evidence.forms.some((form) => form.hasPassword);
	const hasCredentialLikeInputs = evidence.forms.some(
		(form) => form.hasPassword || form.inputTypes.some((type) => /(email|password|tel|number)/i.test(type)),
	);
	const textCorpus = `${evidence.pageTitle} ${evidence.textExcerpt}`;
	const urlCorpus = `${evidence.requestedUrl} ${evidence.finalUrl}`;
	const credentialLanguageDetected = /(verify|password|account|secure|wallet|sign[\s-]?in|otp|mfa|login|reset|billing|unlock)/i.test(
		`${urlCorpus} ${textCorpus}`,
	);
	const platformHosted = isLikelyThirdPartyPlatformHost(evidence.hostname);
	const impersonatedBrand = inferBrandFromEvidence(evidence);

	if (hasPasswordForm) {
		riskScore += 34;
		suspiciousSignals.push('The rendered page contains a password field.');
	}

	if (evidence.finalUrl.startsWith('http://') && hasPasswordForm) {
		riskScore += 16;
		suspiciousSignals.push('A credential form appears on a non-TLS page.');
	}

	if (evidence.requestedUrl !== evidence.finalUrl) {
		riskScore += 10;
		suspiciousSignals.push('The page redirected to a different final URL.');
	}

	if (evidence.hostname.startsWith('xn--')) {
		riskScore += 18;
		suspiciousSignals.push('The hostname uses punycode, which deserves closer review.');
	}

	if (/\d+\.\d+\.\d+\.\d+/.test(evidence.hostname)) {
		riskScore += 22;
		suspiciousSignals.push('The destination hostname is an IP literal.');
	}

	if (credentialLanguageDetected) {
		riskScore += 15;
		suspiciousSignals.push('The rendered text contains account-verification or credential language.');
	}

	if (/(verify|secure|login|signin|auth|reset|mfa|otp|wallet|invoice|billing|unlock)/i.test(urlCorpus)) {
		riskScore += 12;
		suspiciousSignals.push('The URL path or hostname contains credential- or urgency-oriented keywords.');
	}

	if (hasCredentialLikeInputs && credentialLanguageDetected && !hasPasswordForm) {
		riskScore += 10;
		suspiciousSignals.push('The page combines credential-oriented copy with interactive input fields.');
	}

	if (
		impersonatedBrand !== 'Unknown' &&
		!hostMatchesVisibleBrand(evidence.hostname, impersonatedBrand) &&
		(hasPasswordForm || credentialLanguageDetected)
	) {
		riskScore += 22;
		suspiciousSignals.push(
			`Visible brand cues reference ${impersonatedBrand}, but the destination host does not match an expected ${impersonatedBrand} domain.`,
		);
	}

	const externalLinkHosts = new Set(
		evidence.topLinks.map((link) => link.hostname).filter((hostname) => hostname && hostname !== evidence.hostname),
	);
	if (externalLinkHosts.size >= 6) {
		riskScore += 8;
		suspiciousSignals.push('The rendered page sends users to many external destinations.');
	}

	if (/(cloudflare\.com|example\.com)$/.test(evidence.hostname)) {
		riskScore -= 18;
		benignSignals.push('The hostname resembles a known benign domain in mock or demo usage.');
	}

	if (!hasPasswordForm) {
		benignSignals.push('No password collection form was found in the rendered page.');
	}

	if (!credentialLanguageDetected) {
		benignSignals.push('The rendered copy does not use urgent account-verification or credential-reset language.');
	}

	if (evidence.topLinks.length >= 4) {
		benignSignals.push('The page exposes multiple ordinary navigation links, which is less common on disposable phishing pages.');
	}

	if (platformHosted && !hasPasswordForm && !credentialLanguageDetected) {
		benignSignals.push('The page appears to be hosted on a common third-party platform rather than a direct credential collection host.');
	}

	if (impersonatedBrand !== 'Unknown' && hostMatchesVisibleBrand(evidence.hostname, impersonatedBrand)) {
		riskScore -= 10;
		benignSignals.push('The destination hostname aligns with the visible brand cues on the page.');
	}

	if (analystNote && /(urgent|invoice|crypto|suspend|mfa|otp|payroll)/i.test(analystNote)) {
		riskScore += 10;
		suspiciousSignals.push('The analyst note describes an urgent lure or sensitive workflow.');
	}

	riskScore = Math.max(0, Math.min(100, riskScore));
	const verdict = riskScore >= 78 ? 'malicious' : riskScore >= 52 ? 'suspicious' : riskScore >= 28 ? 'inconclusive' : 'benign';
	const confidence =
		riskScore >= 78 || suspiciousSignals.length >= 4 ? 'high' : riskScore >= 40 || suspiciousSignals.length >= 2 ? 'medium' : 'low';

	return normalizeAssessment({
		analystQuestions: [
			'Do you want to rescan the page after more time or interaction?',
			'Should this be blocked immediately or sent for human review?',
			'Do the visible brand hints match the registrant and final hostname?',
		],
		benignSignals:
			benignSignals.length > 0
				? benignSignals
				: ['No strong benign trust signal outweighed the suspicious evidence.'],
		confidence,
		executiveSummary:
			verdict === 'malicious'
				? `The page is likely phishing. It combines a risky destination with credential-focused or impersonation-style content.`
				: verdict === 'suspicious'
					? `The page contains enough phishing indicators to warrant escalation or blocking, but a human analyst should confirm context.`
					: verdict === 'inconclusive'
						? `The current evidence is mixed. Capture more telemetry or rescan before taking a final action.`
						: `The current capture does not show strong phishing traits. Keep the case open only if you have supporting telemetry or user reports.`,
		highlight:
			suspiciousSignals[0] || benignSignals[0] || 'The current page evidence does not contain a dominant phishing indicator.',
		impersonatedBrand,
		recommendedAction:
			verdict === 'malicious'
				? 'Block the URL and escalate the case with preserved evidence.'
				: verdict === 'suspicious'
					? 'Flag the URL as suspicious and queue human review.'
					: verdict === 'inconclusive'
						? 'Rescan the page and compare the hostname with known-good infrastructure.'
						: 'Monitor only if you have additional reports or telemetry.',
		riskScore,
		suspiciousSignals:
			suspiciousSignals.length > 0
				? suspiciousSignals
				: ['No high-confidence phishing indicator was identified in the current capture.'],
		verdict,
	});
}

function createMockFollowUp(investigation: InvestigationState, question: string): FollowUpTurn {
	const lowered = question.toLowerCase();
	const containsPassword = investigation.evidence.forms.some((form) => form.hasPassword);
	const recommendsBlock = investigation.assessment.verdict === 'malicious' || containsPassword;

	return normalizeFollowUpTurn({
		analystQuestions: [
			'Do you want to compare this hostname with known-good infrastructure?',
			'Should the case be rescanned after additional page load time?',
			'Do you need a short executive note for escalation?',
		],
		highlight:
			lowered.includes('why') && investigation.assessment.suspiciousSignals[0]
				? investigation.assessment.suspiciousSignals[0]
				: investigation.assessment.highlight,
		reply:
			lowered.includes('brand')
				? `The strongest visible brand hint is "${investigation.assessment.impersonatedBrand}". You should verify whether that brand is actually associated with ${investigation.evidence.hostname}.`
				: lowered.includes('block')
					? recommendsBlock
						? `Based on the current evidence, I would block or escalate this URL rather than leave it in monitor-only status.`
						: `I would not block yet. The evidence is too thin without stronger phishing indicators or external telemetry.`
					: `The follow-up view is based on the rendered evidence, the current verdict of ${investigation.assessment.verdict}, and the preserved analyst note. The key question is whether ${investigation.evidence.hostname} has a legitimate relationship to the visible brand cues and any credential flow.`,
		recommendedAction:
			recommendsBlock ? 'Block or escalate with the preserved capture.' : investigation.assessment.recommendedAction,
	});
}

function hydrateInvestigationState(existing: InvestigationState): InvestigationState {
	const fallback = createInvestigationState(existing.caseId, existing.targetUrl, existing.analystNote);
	const assessment = normalizeAssessment(existing.assessment, fallback.assessment);
	const evidence = normalizeEvidence(existing.evidence, fallback.evidence);

	return {
		...fallback,
		...existing,
		assessment,
		evidence,
		messages: trimMessages(existing.messages || []),
		scheduledRescanAt: sanitizeText(existing.scheduledRescanAt, 64),
		scanCount: Number.isFinite(Number(existing.scanCount)) ? Math.max(0, Number(existing.scanCount)) : fallback.scanCount,
		status: isCaseStatus(existing.status) ? existing.status : deriveCaseStatus(assessment.verdict),
		tags: deriveCaseTags(evidence, assessment, existing.tags),
		timeline: trimEvents(
			Array.isArray(existing.timeline)
				? existing.timeline
						.map((event) =>
							createCaseEvent(event.type, event.summary, {
								actor: event.actor,
								detail: event.detail,
								timestamp: event.timestamp,
							}),
						)
						.filter(Boolean)
				: [],
		),
	};
}

function deriveCaseTags(
	evidence: RenderEvidence,
	assessment: InvestigationAssessment,
	existingTags: string[] = [],
): string[] {
	const tags = new Set(existingTags.filter(Boolean));

	if (assessment.verdict === 'malicious') {
		tags.add('malicious');
	}
	if (assessment.verdict === 'suspicious') {
		tags.add('suspicious');
	}
	if (assessment.verdict === 'benign') {
		tags.add('benign');
	}
	if (evidence.redirected) {
		tags.add('redirected');
	}
	if (evidence.forms.some((form) => form.classification === 'credential')) {
		tags.add('credential-form');
	}
	if (evidence.topLinks.some((link) => link.classification === 'ip-literal')) {
		tags.add('ip-destination');
	}
	if (evidence.topLinks.some((link) => link.classification === 'brand-related')) {
		tags.add('brand-linked');
	}
	if (assessment.impersonatedBrand && assessment.impersonatedBrand !== 'Unknown') {
		tags.add(`brand:${assessment.impersonatedBrand.toLowerCase()}`);
	}
	if (isLikelyThirdPartyPlatformHost(evidence.hostname)) {
		tags.add('platform-hosted');
	}
	if (evidence.hostname.startsWith('xn--')) {
		tags.add('punycode');
	}

	return [...tags].slice(0, 8);
}

function classifyForm(inputTypes: string[], hasPassword: boolean): 'credential' | 'application' | 'search' | 'input' | 'generic' {
	const normalized = inputTypes.map((type) => type.toLowerCase());
	if (hasPassword || normalized.includes('password')) {
		return 'credential';
	}
	if (normalized.includes('search')) {
		return 'search';
	}
	if (normalized.includes('tel') || normalized.includes('file') || normalized.includes('date')) {
		return 'application';
	}
	if (normalized.includes('email') || normalized.includes('text') || normalized.includes('number')) {
		return 'input';
	}

	return 'generic';
}

function classifyLink(hostname: string, finalUrl: string, visibleBrandHints: string[]): 'same-host' | 'same-root' | 'brand-related' | 'external' | 'ip-literal' {
	const finalHost = getHostname(finalUrl);
	const normalizedHost = hostname.toLowerCase();
	if (!normalizedHost) {
		return 'external';
	}
	if (/\d+\.\d+\.\d+\.\d+/.test(normalizedHost)) {
		return 'ip-literal';
	}
	if (normalizedHost === finalHost.toLowerCase()) {
		return 'same-host';
	}
	if (getRootDomain(normalizedHost) === getRootDomain(finalHost)) {
		return 'same-root';
	}
	const combinedHints = visibleBrandHints.join(' ').toLowerCase();
	if (
		(combinedHints.includes('cloudflare') && hostMatchesVisibleBrand(normalizedHost, 'Cloudflare')) ||
		(combinedHints.includes('google') && hostMatchesVisibleBrand(normalizedHost, 'Google')) ||
		(combinedHints.includes('microsoft') && hostMatchesVisibleBrand(normalizedHost, 'Microsoft')) ||
		(combinedHints.includes('paypal') && hostMatchesVisibleBrand(normalizedHost, 'PayPal')) ||
		(combinedHints.includes('apple') && hostMatchesVisibleBrand(normalizedHost, 'Apple'))
	) {
		return 'brand-related';
	}

	return 'external';
}

function summarizeLinks(topLinks: RenderEvidence['topLinks']): RenderEvidence['linkSummary'] {
	return topLinks.reduce(
		(summary, link) => {
			switch (link.classification) {
				case 'same-host':
					summary.sameHost += 1;
					break;
				case 'same-root':
					summary.sameRoot += 1;
					break;
				case 'brand-related':
					summary.brandRelated += 1;
					break;
				case 'ip-literal':
					summary.ipLiteral += 1;
					break;
				default:
					summary.external += 1;
			}
			return summary;
		},
		{
			brandRelated: 0,
			external: 0,
			ipLiteral: 0,
			sameHost: 0,
			sameRoot: 0,
		},
	);
}

async function computeEvidenceHashes(input: {
	finalUrl: string;
	pageTitle: string;
	requestedUrl: string;
	screenshotBytes: Uint8Array;
	textExcerpt: string;
	topLinks: RenderEvidence['topLinks'];
}): Promise<RenderEvidence['hashes']> {
	const metadata = JSON.stringify({
		finalUrl: input.finalUrl,
		pageTitle: input.pageTitle,
		requestedUrl: input.requestedUrl,
		topLinks: input.topLinks.slice(0, 12),
	});
	return {
		metadataSha256: await sha256Hex(metadata),
		screenshotSha256: await sha256Hex(input.screenshotBytes),
		textSha256: await sha256Hex(input.textExcerpt),
	};
}

async function sha256Hex(value: string | Uint8Array): Promise<string> {
	const bytes = typeof value === 'string' ? new TextEncoder().encode(value) : new Uint8Array(value);
	const digest = await crypto.subtle.digest('SHA-256', new Uint8Array(bytes));
	return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function enforceRateLimit(rateLimiter: RateLimit | undefined, request: Request, route: string): Promise<Response | null> {
	if (!rateLimiter) {
		return null;
	}

	const key = `${route}:${getClientKey(request)}`;
	const outcome = await rateLimiter.limit({ key });
	return outcome.success ? null : errorResponse(429, 'Rate limit exceeded for this operation.');
}

async function verifyTurnstile(env: AppEnv, request: Request, token?: string): Promise<boolean> {
	if (!env.TURNSTILE_SECRET_KEY) {
		return true;
	}

	if (!token) {
		return false;
	}

	const body = new URLSearchParams();
	body.set('secret', env.TURNSTILE_SECRET_KEY);
	body.set('response', token);
	body.set('remoteip', request.headers.get('CF-Connecting-IP') || '');

	const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
		body,
		headers: {
			'content-type': 'application/x-www-form-urlencoded',
		},
		method: 'POST',
	});
	const payload = (await response.json()) as TurnstileVerificationResponse;
	return Boolean(response.ok && payload.success);
}

function clampScheduledDelay(value: unknown): number {
	const seconds = Number(value);
	if (!Number.isFinite(seconds)) {
		return 120;
	}

	return Math.max(30, Math.min(3600, Math.round(seconds)));
}

function getClientKey(request: Request): string {
	return request.headers.get('CF-Connecting-IP') || request.headers.get('x-forwarded-for') || 'anonymous';
}

function isCaseStatus(value: unknown): value is CaseStatus {
	return value === 'triage' || value === 'monitor' || value === 'needs_review' || value === 'escalated';
}

function createUnsupportedTelemetryFollowUp(
	investigation: InvestigationState,
	question: string,
): FollowUpTurn | null {
	if (!isUnsupportedTelemetryQuestion(question)) {
		return null;
	}

	return normalizeFollowUpTurn({
		analystQuestions: [
			'Do you want to review the rendered links and page copy instead of unavailable traffic telemetry?',
			'Should this case be correlated with referrer, CDN, or marketing analytics outside PhishScope?',
			'Do you want a verdict based only on the captured page evidence and hostname context?',
		],
		highlight:
			'The current case includes rendered page evidence, outbound links, and page structure, but not inbound traffic or referrer telemetry.',
		reply:
			'The major traffic sources cannot be determined from the current case evidence. This investigation includes rendered page content, forms, links, and hostname context, but it does not include referrers, campaign metadata, visitor analytics, or inbound traffic logs. Use external analytics, referrer logs, or edge telemetry if you need source attribution.',
		recommendedAction:
			'Correlate this case with analytics, referrer logs, or HTTP traffic telemetry before making claims about traffic sources or campaign origin.',
	});
}

function detectStructuralSignals(
	requestedUrl: string,
	finalUrl: string,
	pageTitle: string,
	textExcerpt: string,
	forms: RenderEvidence['forms'],
): string[] {
	const signals: string[] = [];
	const requestedHost = getHostname(requestedUrl);
	const finalHost = getHostname(finalUrl);

	if (requestedHost && finalHost && requestedHost !== finalHost) {
		signals.push(`The request host ${requestedHost} redirected to ${finalHost}.`);
	}

	if (forms.some((form) => form.hasPassword)) {
		signals.push('At least one rendered form requests a password.');
	}

	if (/(verify|password|mfa|otp|secure|wallet|invoice|suspend)/i.test(`${pageTitle} ${textExcerpt}`)) {
		signals.push('The rendered content includes urgent account or security language.');
	}

	if (finalHost && finalHost.startsWith('xn--')) {
		signals.push('The destination hostname uses punycode.');
	}

	if (/\d+\.\d+\.\d+\.\d+/.test(finalHost)) {
		signals.push('The final host is an IP literal.');
	}

	if (signals.length === 0) {
		signals.push('No dominant structural phishing indicator was found during the render.');
	}

	return signals.slice(0, 8);
}

function inferBrandFromEvidence(evidence: RenderEvidence): string {
	const combined = `${evidence.pageTitle} ${evidence.textExcerpt} ${evidence.visibleBrandHints.join(' ')}`.toLowerCase();
	if (combined.includes('microsoft')) {
		return 'Microsoft';
	}

	if (combined.includes('paypal')) {
		return 'PayPal';
	}

	if (combined.includes('apple')) {
		return 'Apple';
	}

	if (combined.includes('google') || combined.includes('gmail')) {
		return 'Google';
	}

	if (combined.includes('cloudflare')) {
		return 'Cloudflare';
	}

	return 'Unknown';
}

function getRootDomain(hostname: string): string {
	const normalized = hostname.toLowerCase();
	if (!normalized) {
		return '';
	}

	if (/\d+\.\d+\.\d+\.\d+/.test(normalized)) {
		return normalized;
	}

	const parts = normalized.split('.').filter(Boolean);
	return parts.length <= 2 ? normalized : parts.slice(-2).join('.');
}

function isUnsupportedTelemetryQuestion(question: string): boolean {
	const lowered = question.toLowerCase();

	const trafficPatterns = [
		/\btraffic source\b/,
		/\btraffic sources\b/,
		/\bsource of traffic\b/,
		/\bvisitor source\b/,
		/\bvisitor sources\b/,
		/\breferrer\b/,
		/\breferrers\b/,
		/\breferral traffic\b/,
		/\bcampaign origin\b/,
		/\bsource\/medium\b/,
		/\butm\b/,
	];

	const analyticsPatterns = [
		/\banalytics\b/,
		/\bvisitor count\b/,
		/\bvisitors\b/,
		/\bpageviews\b/,
		/\bpage views\b/,
		/\bimpressions\b/,
		/\bclick[- ]through\b/,
		/\bctr\b/,
		/\bconversion\b/,
		/\bacquisition\b/,
	];

	return trafficPatterns.some((pattern) => pattern.test(lowered)) || analyticsPatterns.some((pattern) => pattern.test(lowered));
}

function hostMatchesVisibleBrand(hostname: string, brand: string): boolean {
	const normalizedHost = hostname.toLowerCase();
	const suffixesByBrand: Record<string, string[]> = {
		apple: ['apple.com', 'icloud.com'],
		cloudflare: ['cloudflare.com', 'cloudflare.tv', 'cloudflareinsights.com'],
		google: ['google.com', 'gmail.com', 'googleusercontent.com', 'withgoogle.com'],
		microsoft: ['microsoft.com', 'live.com', 'office.com', 'outlook.com'],
		paypal: ['paypal.com', 'paypalobjects.com'],
	};
	const allowedSuffixes = suffixesByBrand[brand.toLowerCase()] || [];

	return allowedSuffixes.some((suffix) => normalizedHost === suffix || normalizedHost.endsWith(`.${suffix}`));
}

function isLikelyThirdPartyPlatformHost(hostname: string): boolean {
	const normalizedHost = hostname.toLowerCase();
	return [
		'greenhouse.io',
		'greenhouseboards.com',
		'lever.co',
		'workdayjobs.com',
		'ashbyhq.com',
		'notion.site',
		'typeform.com',
	].some((suffix) => normalizedHost === suffix || normalizedHost.endsWith(`.${suffix}`));
}

function shouldUseMockAi(env: AppEnv): boolean {
	const ai = env.AI as unknown as AiBinding | undefined;
	return String(env.MOCK_AI) === 'true' || !ai || typeof ai.run !== 'function';
}

function shouldUseMockBrowser(env: AppEnv): boolean {
	return String(env.MOCK_BROWSER) === 'true' || !('BROWSER' in env) || !env.BROWSER;
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
