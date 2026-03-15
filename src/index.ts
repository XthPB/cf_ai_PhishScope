import {
	APP_NAME,
	MODEL_NAME,
	STORAGE_KEY,
	buildAssessmentSnapshot,
	buildEvidenceSnapshot,
	buildTranscript,
	createDefaultAssessment,
	createDefaultEvidence,
	createInvestigationState,
	createMessage,
	createMockInvestigation,
	getHostname,
	normalizeAssessment,
	normalizeEvidence,
	normalizeFollowUpTurn,
	normalizeUrl,
	parseAiResponse,
	sanitizeText,
	trimMessages,
	type FollowUpTurn,
	type InvestigationAssessment,
	type InvestigationState,
	type RenderEvidence,
} from './shared';

interface AiBinding {
	run(model: string, input: Record<string, unknown>): Promise<unknown>;
}

type AppEnv = Env;

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
- Provide short, analyst-facing reasoning.
- If the analyst asks for an action, recommend block, monitor, rescan, or human review as appropriate.`;

export default {
	async fetch(request, env): Promise<Response> {
		const url = new URL(request.url);

		if (request.method === 'GET' && url.pathname === '/api/health') {
			return jsonResponse({
				app: APP_NAME,
				browserMode: shouldUseMockBrowser(env) ? 'mock' : 'browser-rendering',
				model: MODEL_NAME,
				aiMode: shouldUseMockAi(env) ? 'mock' : 'workers-ai',
				status: 'ok',
				timestamp: new Date().toISOString(),
			});
		}

		if (request.method === 'POST' && url.pathname === '/api/cases') {
			return createCase(request, env);
		}

		const caseMatch = url.pathname.match(/^\/api\/cases\/([^/]+)(?:\/(messages|rescan))?$/);
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
			return jsonResponse({ investigation });
		}

		if (request.method === 'POST' && url.pathname === '/rescan') {
			return this.rescan(request);
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
		investigation = {
			...investigation,
			assessment: analysis.assessment,
			evidence: analysis.evidence,
			latestReply: analysis.reply,
			messages: trimMessages([...investigation.messages, assistantMessage]),
			scanCount: 1,
			targetUrl,
			updatedAt: assistantMessage.timestamp,
		};

		await this.persistState(investigation);

		return jsonResponse({
			caseId,
			investigation,
		});
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
			scanCount: investigation.scanCount + 1,
			targetUrl,
			updatedAt: assistantMessage.timestamp,
		};

		await this.persistState(nextState);

		return jsonResponse({
			caseId: nextState.caseId,
			investigation: nextState,
		});
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
		investigation.updatedAt = assistantMessage.timestamp;

		await this.persistState(investigation);

		return jsonResponse({
			caseId: investigation.caseId,
			followUp,
			investigation,
			mode: {
				ai: shouldUseMockAi(this.env) ? 'mock' : 'workers-ai',
				browser: shouldUseMockBrowser(this.env) ? 'mock' : 'browser-rendering',
			},
			model: MODEL_NAME,
		});
	}

	private async loadState(): Promise<InvestigationState> {
		const existing = await this.state.storage.get<InvestigationState>(STORAGE_KEY);
		if (existing) {
			return existing;
		}

		throw new Error('Case not initialized.');
	}

	private async persistState(investigation: InvestigationState): Promise<void> {
		await this.state.storage.put(STORAGE_KEY, {
			...investigation,
			messages: trimMessages(investigation.messages),
		});
	}
}

async function createCase(request: Request, env: AppEnv): Promise<Response> {
	const payload = await readJson<{ analystNote?: string; url?: string }>(request);
	const targetUrl = normalizeUrl(payload?.url);
	if (!targetUrl) {
		return errorResponse(400, 'A valid http or https URL is required.');
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

async function handleCaseRoute(request: Request, env: AppEnv, caseId: string, action?: string): Promise<Response> {
	if (!caseId) {
		return errorResponse(400, 'Case id is required.');
	}

	if (request.method === 'GET' && !action) {
		return sendToCase(env, caseId, new Request('https://case/state'));
	}

	if (request.method === 'POST' && action === 'rescan') {
		return proxyJsonToCase(env, caseId, '/rescan', request);
	}

	if (request.method === 'POST' && action === 'messages') {
		return proxyJsonToCase(env, caseId, '/messages', request);
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

		return normalizeEvidence({
			captureTimestamp,
			finalUrl,
			forms: pageEvidence.forms,
			pageTitle,
			requestedUrl: targetUrl,
			screenshotDataUrl: `data:image/jpeg;base64,${Buffer.from(screenshot).toString('base64')}`,
			structuralSignals: detectStructuralSignals(targetUrl, finalUrl, pageTitle, pageEvidence.textExcerpt, pageEvidence.forms),
			textExcerpt: pageEvidence.textExcerpt,
			topLinks: pageEvidence.topLinks,
			visibleBrandHints: pageEvidence.visibleBrandHints,
		});
	} finally {
		await browser.close();
	}
}

function createFallbackAssessment(evidence: RenderEvidence, analystNote: string): InvestigationAssessment {
	const suspiciousSignals = [...evidence.structuralSignals];
	const benignSignals: string[] = [];
	let riskScore = 18;

	if (evidence.forms.some((form) => form.hasPassword)) {
		riskScore += 34;
		suspiciousSignals.push('The rendered page contains a password field.');
	}

	if (evidence.finalUrl.startsWith('http://') && evidence.forms.some((form) => form.hasPassword)) {
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

	if (/(verify|password|account|secure|wallet|sign in|otp|mfa)/i.test(`${evidence.pageTitle} ${evidence.textExcerpt}`)) {
		riskScore += 15;
		suspiciousSignals.push('The rendered text contains account-verification or credential language.');
	}

	if (/(cloudflare\.com|example\.com)$/.test(evidence.hostname)) {
		riskScore -= 18;
		benignSignals.push('The hostname resembles a known benign domain in mock or demo usage.');
	}

	if (!evidence.forms.some((form) => form.hasPassword)) {
		benignSignals.push('No password collection form was found in the rendered page.');
	}

	if (evidence.topLinks.length <= 2) {
		benignSignals.push('The page exposes a limited number of visible links.');
	}

	if (analystNote && /(urgent|invoice|crypto|suspend|mfa|otp|payroll)/i.test(analystNote)) {
		riskScore += 10;
		suspiciousSignals.push('The analyst note describes an urgent lure or sensitive workflow.');
	}

	riskScore = Math.max(0, Math.min(100, riskScore));
	const verdict = riskScore >= 80 ? 'malicious' : riskScore >= 55 ? 'suspicious' : riskScore >= 30 ? 'inconclusive' : 'benign';
	const confidence = riskScore >= 80 ? 'high' : riskScore >= 55 ? 'medium' : 'low';
	const impersonatedBrand = inferBrandFromEvidence(evidence);

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
						: `The current capture does not show strong phishing traits, although external telemetry could still change the decision.`,
		highlight:
			suspiciousSignals[0] || 'The current page evidence does not contain a dominant phishing indicator.',
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
		suspiciousSignals,
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
