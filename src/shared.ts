export const APP_NAME = 'PhishScope';
export const MODEL_NAME = '@cf/meta/llama-3.3-70b-instruct-fp8-fast';
export const STORAGE_KEY = 'phishscope-case';
export const MAX_CASE_MESSAGES = 16;
export const MAX_CASE_EVENTS = 24;

export type ChatRole = 'user' | 'assistant';
export type Confidence = 'low' | 'medium' | 'high';
export type CaseStatus = 'triage' | 'monitor' | 'needs_review' | 'escalated';
export type CaseActor = 'system' | 'analyst' | 'automation';
export type FormClassification = 'credential' | 'application' | 'search' | 'input' | 'generic';
export type LinkClassification = 'same-host' | 'same-root' | 'brand-related' | 'external' | 'ip-literal';
export type Verdict = 'malicious' | 'suspicious' | 'benign' | 'inconclusive';

export interface CaseMessage {
	id: string;
	role: ChatRole;
	content: string;
	timestamp: string;
}

export interface FormEvidence {
	action: string;
	classification: FormClassification;
	method: string;
	inputTypes: string[];
	hasPassword: boolean;
}

export interface LinkEvidence {
	classification: LinkClassification;
	href: string;
	hostname: string;
	text: string;
}

export interface EvidenceHashes {
	metadataSha256: string;
	screenshotSha256: string;
	textSha256: string;
}

export interface LinkSummary {
	brandRelated: number;
	external: number;
	ipLiteral: number;
	sameHost: number;
	sameRoot: number;
}

export interface RenderEvidence {
	captureTimestamp: string;
	finalUrl: string;
	forms: FormEvidence[];
	hashes: EvidenceHashes;
	hostname: string;
	linkSummary: LinkSummary;
	pageTitle: string;
	redirected: boolean;
	requestedUrl: string;
	screenshotDataUrl: string;
	structuralSignals: string[];
	textExcerpt: string;
	topLinks: LinkEvidence[];
	visibleBrandHints: string[];
}

export interface InvestigationAssessment {
	analystQuestions: string[];
	benignSignals: string[];
	confidence: Confidence;
	executiveSummary: string;
	highlight: string;
	impersonatedBrand: string;
	recommendedAction: string;
	riskScore: number;
	suspiciousSignals: string[];
	verdict: Verdict;
}

export interface CaseEvent {
	actor: CaseActor;
	detail: string;
	id: string;
	summary: string;
	timestamp: string;
	type: string;
}

export interface InvestigationState {
	analystNote: string;
	caseId: string;
	createdAt: string;
	evidence: RenderEvidence;
	latestReply: string;
	messages: CaseMessage[];
	scheduledRescanAt: string;
	scanCount: number;
	status: CaseStatus;
	tags: string[];
	targetUrl: string;
	timeline: CaseEvent[];
	updatedAt: string;
	assessment: InvestigationAssessment;
}

export interface FollowUpTurn {
	analystQuestions: string[];
	highlight: string;
	reply: string;
	recommendedAction: string;
}

export interface CaseListItem {
	caseId: string;
	confidence: Confidence;
	hostname: string;
	impersonatedBrand: string;
	pageTitle: string;
	riskScore: number;
	scanCount: number;
	status: CaseStatus;
	summary: string;
	tags: string[];
	targetUrl: string;
	updatedAt: string;
	verdict: Verdict;
}

export interface DashboardSummary {
	averageRiskScore: number;
	escalatedCases: number;
	monitorCases: number;
	needsReviewCases: number;
	recentCases: CaseListItem[];
	totalCases: number;
	triageCases: number;
}

export function createDefaultEvidence(targetUrl = ''): RenderEvidence {
	const url = normalizeUrl(targetUrl) || 'https://example.com';
	const hostname = getHostname(url) || 'example.com';

	return {
		captureTimestamp: new Date().toISOString(),
		finalUrl: url,
		forms: [],
		hashes: {
			metadataSha256: '',
			screenshotSha256: '',
			textSha256: '',
		},
		hostname,
		linkSummary: {
			brandRelated: 0,
			external: 0,
			ipLiteral: 0,
			sameHost: 0,
			sameRoot: 0,
		},
		pageTitle: 'No capture yet',
		redirected: false,
		requestedUrl: targetUrl || url,
		screenshotDataUrl: createPlaceholderScreenshot(hostname, 'Pending capture'),
		structuralSignals: ['No render evidence collected yet.'],
		textExcerpt: 'Submit a URL to render the page and inspect forms, links, and visible text.',
		topLinks: [],
		visibleBrandHints: [],
	};
}

export function createDefaultAssessment(): InvestigationAssessment {
	return {
		analystQuestions: [
			'Does the hostname match the brand the page claims to represent?',
			'Is the page collecting credentials or payment details?',
			'Does the redirect chain land on an unexpected domain?',
		],
		benignSignals: ['No render evidence collected yet.'],
		confidence: 'low',
		executiveSummary: 'Run a capture to generate an analyst summary and recommended action.',
		highlight: 'Waiting for the first scan.',
		impersonatedBrand: 'Unknown',
		recommendedAction: 'Run a scan before making a triage decision.',
		riskScore: 0,
		suspiciousSignals: ['No suspicious signals collected yet.'],
		verdict: 'inconclusive',
	};
}

export function createInvestigationState(caseId: string, targetUrl: string, analystNote = ''): InvestigationState {
	const now = new Date().toISOString();
	const normalizedUrl = normalizeUrl(targetUrl) || targetUrl || 'https://example.com';

	return {
		analystNote: sanitizeText(analystNote, 320),
		assessment: createDefaultAssessment(),
		caseId,
		createdAt: now,
		evidence: createDefaultEvidence(normalizedUrl),
		latestReply: 'Submit a suspicious URL to start the investigation.',
		messages: [],
		scheduledRescanAt: '',
		scanCount: 0,
		status: 'triage',
		tags: [],
		targetUrl: normalizedUrl,
		timeline: [],
		updatedAt: now,
	};
}

export function createMessage(role: ChatRole, content: string, timestamp = new Date().toISOString()): CaseMessage {
	return {
		id: crypto.randomUUID(),
		role,
		content: sanitizeText(content, 2600),
		timestamp,
	};
}

export function trimMessages(messages: CaseMessage[]): CaseMessage[] {
	return messages.slice(-MAX_CASE_MESSAGES);
}

export function trimEvents(events: CaseEvent[]): CaseEvent[] {
	return events.slice(-MAX_CASE_EVENTS);
}

export function createCaseEvent(
	type: string,
	summary: string,
	options: { actor?: CaseActor; detail?: string; timestamp?: string } = {},
): CaseEvent {
	return {
		actor: options.actor || 'system',
		detail: sanitizeText(options.detail, 320),
		id: crypto.randomUUID(),
		summary: sanitizeText(summary, 180),
		timestamp: options.timestamp || new Date().toISOString(),
		type: sanitizeText(type, 64) || 'event',
	};
}

export function deriveCaseStatus(verdict: Verdict): CaseStatus {
	switch (verdict) {
		case 'malicious':
			return 'escalated';
		case 'suspicious':
			return 'needs_review';
		case 'benign':
			return 'monitor';
		default:
			return 'triage';
	}
}

export function sanitizeText(value: unknown, maxLength: number): string {
	if (typeof value !== 'string') {
		return '';
	}

	return value.replace(/\s+/g, ' ').trim().slice(0, maxLength);
}

export function sanitizeList(value: unknown, maxLength: number, maxItems: number, fallback: string[]): string[] {
	if (!Array.isArray(value)) {
		return fallback;
	}

	const normalized = value
		.map((item) => sanitizeText(item, maxLength))
		.filter(Boolean)
		.slice(0, maxItems);

	return normalized.length > 0 ? [...new Set(normalized)] : fallback;
}

export function normalizeEvidence(input: unknown, previous = createDefaultEvidence()): RenderEvidence {
	const candidate = isRecord(input) ? input : {};
	const requestedUrl = normalizeUrl(candidate.requestedUrl) || previous.requestedUrl;
	const finalUrl = normalizeUrl(candidate.finalUrl) || previous.finalUrl;

	return {
		captureTimestamp: sanitizeText(candidate.captureTimestamp, 64) || previous.captureTimestamp,
		finalUrl,
		forms: normalizeForms(candidate.forms, previous.forms),
		hashes: normalizeHashes(candidate.hashes, previous.hashes),
		hostname: getHostname(finalUrl) || getHostname(requestedUrl) || previous.hostname,
		linkSummary: normalizeLinkSummary(candidate.linkSummary, previous.linkSummary),
		pageTitle: sanitizeText(candidate.pageTitle, 140) || previous.pageTitle,
		redirected: typeof candidate.redirected === 'boolean' ? candidate.redirected : previous.redirected,
		requestedUrl,
		screenshotDataUrl: sanitizeDataUrl(candidate.screenshotDataUrl) || previous.screenshotDataUrl,
		structuralSignals: sanitizeList(candidate.structuralSignals, 160, 8, previous.structuralSignals),
		textExcerpt: sanitizeText(candidate.textExcerpt, 2000) || previous.textExcerpt,
		topLinks: normalizeLinks(candidate.topLinks, previous.topLinks),
		visibleBrandHints: sanitizeList(candidate.visibleBrandHints, 80, 6, previous.visibleBrandHints),
	};
}

export function normalizeAssessment(input: unknown, previous = createDefaultAssessment()): InvestigationAssessment {
	const candidate = isRecord(input) ? input : {};

	return {
		analystQuestions: sanitizeList(candidate.analystQuestions, 140, 4, previous.analystQuestions),
		benignSignals: sanitizeList(candidate.benignSignals, 160, 6, previous.benignSignals),
		confidence: normalizeConfidence(candidate.confidence, previous.confidence),
		executiveSummary: sanitizeText(candidate.executiveSummary, 900) || previous.executiveSummary,
		highlight: sanitizeText(candidate.highlight, 180) || previous.highlight,
		impersonatedBrand: sanitizeText(candidate.impersonatedBrand, 80) || previous.impersonatedBrand,
		recommendedAction: sanitizeText(candidate.recommendedAction, 220) || previous.recommendedAction,
		riskScore: normalizeRiskScore(candidate.riskScore, previous.riskScore),
		suspiciousSignals: sanitizeList(candidate.suspiciousSignals, 160, 8, previous.suspiciousSignals),
		verdict: normalizeVerdict(candidate.verdict, previous.verdict),
	};
}

export function normalizeFollowUpTurn(input: unknown): FollowUpTurn {
	const candidate = isRecord(input) ? input : {};

	return {
		analystQuestions: sanitizeList(candidate.analystQuestions, 140, 4, [
			'Does the page ask for credentials, payment, or MFA codes?',
			'Is the visible brand actually owned by the destination hostname?',
			'Should this URL be blocked, monitored, or escalated?',
		]),
		highlight:
			sanitizeText(candidate.highlight, 180) ||
			'The response is based on the captured evidence, existing verdict, and analyst notes.',
		reply:
			sanitizeText(candidate.reply, 1800) ||
			'No additional insight was produced. Ask a narrower question about the page evidence or verdict.',
		recommendedAction:
			sanitizeText(candidate.recommendedAction, 220) || 'Review the captured evidence before changing the action.',
	};
}

export function parseAiResponse(response: unknown): unknown {
	if (isRecord(response) && 'response' in response) {
		return parseAiResponse(response.response);
	}

	if (isRecord(response) && 'result' in response) {
		return parseAiResponse(response.result);
	}

	if (isRecord(response) && 'output_text' in response) {
		return parseAiResponse(response.output_text);
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

export function buildEvidenceSnapshot(evidence: RenderEvidence): string {
	const snapshot = {
		captureTimestamp: evidence.captureTimestamp,
		finalUrl: evidence.finalUrl,
		forms: evidence.forms.slice(0, 4).map((form) => ({
			action: sanitizeText(form.action, 180),
			classification: form.classification,
			hasPassword: form.hasPassword,
			inputTypes: form.inputTypes.slice(0, 6),
			method: form.method,
		})),
		hashes: evidence.hashes,
		hostname: evidence.hostname,
		linkSummary: evidence.linkSummary,
		pageTitle: evidence.pageTitle,
		redirected: evidence.redirected,
		requestedUrl: evidence.requestedUrl,
		screenshotCaptured: Boolean(evidence.screenshotDataUrl),
		structuralSignals: evidence.structuralSignals.slice(0, 6),
		textExcerpt: sanitizeText(evidence.textExcerpt, 1200),
		topLinks: evidence.topLinks.slice(0, 8).map((link) => ({
			classification: link.classification,
			href: sanitizeText(link.href, 180),
			hostname: sanitizeText(link.hostname, 120),
			text: sanitizeText(link.text, 60),
		})),
		visibleBrandHints: evidence.visibleBrandHints.slice(0, 6),
	};

	return JSON.stringify(snapshot, null, 2);
}

export function buildAssessmentSnapshot(assessment: InvestigationAssessment): string {
	const snapshot = {
		analystQuestions: assessment.analystQuestions.slice(0, 3),
		benignSignals: assessment.benignSignals.slice(0, 4),
		confidence: assessment.confidence,
		executiveSummary: sanitizeText(assessment.executiveSummary, 420),
		highlight: sanitizeText(assessment.highlight, 180),
		impersonatedBrand: assessment.impersonatedBrand,
		recommendedAction: sanitizeText(assessment.recommendedAction, 220),
		riskScore: assessment.riskScore,
		suspiciousSignals: assessment.suspiciousSignals.slice(0, 6),
		verdict: assessment.verdict,
	};

	return JSON.stringify(snapshot, null, 2);
}

export function toCaseListItem(investigation: InvestigationState): CaseListItem {
	return {
		caseId: investigation.caseId,
		confidence: investigation.assessment.confidence,
		hostname: investigation.evidence.hostname,
		impersonatedBrand: investigation.assessment.impersonatedBrand,
		pageTitle: investigation.evidence.pageTitle,
		riskScore: investigation.assessment.riskScore,
		scanCount: investigation.scanCount,
		status: investigation.status,
		summary: sanitizeText(investigation.assessment.executiveSummary, 260),
		tags: investigation.tags.slice(0, 8),
		targetUrl: investigation.targetUrl,
		updatedAt: investigation.updatedAt,
		verdict: investigation.assessment.verdict,
	};
}

export function buildTranscript(messages: CaseMessage[]): string {
	return messages
		.slice(-8)
		.map((message) => `${message.role.toUpperCase()}: ${sanitizeText(message.content, 320)}`)
		.join('\n');
}

export function createMockInvestigation(targetUrl: string, analystNote = ''): {
	assessment: InvestigationAssessment;
	evidence: RenderEvidence;
	reply: string;
} {
	const normalizedUrl = normalizeUrl(targetUrl) || 'https://example.com/security-check';
	const hostname = getHostname(normalizedUrl) || 'example.com';
	const suspicious = inferSuspicion(normalizedUrl, analystNote);
	const verdict: Verdict = suspicious.score >= 85 ? 'malicious' : suspicious.score >= 55 ? 'suspicious' : 'benign';
	const confidence: Confidence = suspicious.score >= 85 ? 'high' : suspicious.score >= 55 ? 'medium' : 'medium';
	const brand = inferBrand(normalizedUrl, analystNote);
	const evidence = normalizeEvidence({
		captureTimestamp: new Date().toISOString(),
		finalUrl: normalizedUrl,
		forms: [
			{
				action: suspicious.score >= 55 ? `${normalizedUrl}/submit` : '',
				method: suspicious.score >= 55 ? 'post' : 'get',
				inputTypes: suspicious.score >= 55 ? ['email', 'password'] : ['email'],
				hasPassword: suspicious.score >= 55,
			},
		],
		pageTitle: suspicious.score >= 55 ? `${brand} account verification` : `${brand} support landing page`,
		requestedUrl: normalizedUrl,
		screenshotDataUrl: createPlaceholderScreenshot(hostname, verdict.toUpperCase()),
		structuralSignals:
			suspicious.score >= 55
				? ['Credential form present on a non-canonical hostname.', 'Brand language appears in the page title.']
				: ['Page structure looks simple and contains no credential request.'],
		textExcerpt:
			suspicious.score >= 55
				? `Please verify your ${brand} account to avoid interruption. Enter your password and one-time code to continue.`
				: `${brand} landing page with basic informational content and no urgent security prompt.`,
		topLinks: [
			{
				href: normalizedUrl,
				hostname,
				text: suspicious.score >= 55 ? 'Verify account' : 'Home',
			},
			{
				href: `https://${brand.toLowerCase().replace(/\s+/g, '')}.com/help`,
				hostname: `${brand.toLowerCase().replace(/\s+/g, '')}.com`,
				text: 'Official help',
			},
		],
		visibleBrandHints: brand === 'Unknown' ? [] : [brand],
	});

	const assessment = normalizeAssessment({
		analystQuestions: [
			'Has this hostname been reported elsewhere in the environment?',
			'Do you want a rescan with a fresh render after the page settles?',
			'Should this indicator be sent for human review or immediate block?',
		],
		benignSignals:
			suspicious.score >= 55 ? ['No benign trust signals outweighed the credential-harvesting indicators.'] : ['No password form detected.', 'No urgent account language detected.'],
		confidence,
		executiveSummary:
			suspicious.score >= 55
				? `The page shows classic phishing traits, including brand impersonation cues and a credential form on ${hostname}.`
				: `The captured page looks lower risk, but should still be reviewed against known-good infrastructure before closing the case.`,
		highlight:
			suspicious.score >= 55
				? 'Credential capture on an untrusted or brand-mismatched hostname is the strongest indicator.'
				: 'No direct credential-harvesting flow was found in mock mode.',
		impersonatedBrand: brand,
		recommendedAction:
			suspicious.score >= 85
				? 'Block the URL, preserve the evidence, and escalate to a human analyst immediately.'
				: suspicious.score >= 55
					? 'Flag the URL as suspicious, preserve the capture, and request analyst review.'
					: 'Keep the case open only if you have external reports or telemetry suggesting abuse.',
		riskScore: suspicious.score,
		suspiciousSignals: suspicious.signals,
		verdict,
	});

	return {
		assessment,
		evidence,
		reply: `Mock mode analyzed ${hostname} and returned a ${verdict} verdict with a risk score of ${assessment.riskScore}. The main driver is ${assessment.highlight.toLowerCase()}`,
	};
}

export function normalizeUrl(input: unknown): string {
	const candidate = sanitizeText(input, 2048);
	if (!candidate) {
		return '';
	}

	try {
		const withProtocol = /^[a-z]+:\/\//i.test(candidate) ? candidate : `https://${candidate}`;
		const url = new URL(withProtocol);
		if (!['http:', 'https:'].includes(url.protocol)) {
			return '';
		}

		return url.toString();
	} catch {
		return '';
	}
}

export function getHostname(targetUrl: string): string {
	try {
		return new URL(targetUrl).hostname;
	} catch {
		return '';
	}
}

function normalizeForms(value: unknown, fallback: FormEvidence[]): FormEvidence[] {
	if (!Array.isArray(value)) {
		return fallback;
	}

	const normalized = value
		.map((entry) => {
			const candidate = isRecord(entry) ? entry : {};
			const method = sanitizeText(candidate.method, 20).toLowerCase() || 'get';
			return {
				action: sanitizeText(candidate.action, 240),
				classification: normalizeFormClassification(candidate.classification, 'generic'),
				hasPassword: Boolean(candidate.hasPassword),
				inputTypes: sanitizeList(candidate.inputTypes, 24, 8, []),
				method,
			} satisfies FormEvidence;
		})
		.slice(0, 6);

	return normalized.length > 0 ? normalized : fallback;
}

function normalizeLinks(value: unknown, fallback: LinkEvidence[]): LinkEvidence[] {
	if (!Array.isArray(value)) {
		return fallback;
	}

	const normalized = value
		.map((entry) => {
			const candidate = isRecord(entry) ? entry : {};
			const href = sanitizeText(candidate.href, 320);
			return {
				classification: normalizeLinkClassification(candidate.classification, 'external'),
				href,
				hostname: sanitizeText(candidate.hostname, 120) || getHostname(href),
				text: sanitizeText(candidate.text, 80),
			} satisfies LinkEvidence;
		})
		.filter((entry) => entry.href)
		.slice(0, 10);

	return normalized.length > 0 ? normalized : fallback;
}

function sanitizeDataUrl(value: unknown): string {
	const candidate = sanitizeText(value, 900000);
	return candidate.startsWith('data:image/') ? candidate : '';
}

function normalizeHashes(value: unknown, fallback: EvidenceHashes): EvidenceHashes {
	const candidate = isRecord(value) ? value : {};
	return {
		metadataSha256: sanitizeText(candidate.metadataSha256, 96) || fallback.metadataSha256,
		screenshotSha256: sanitizeText(candidate.screenshotSha256, 96) || fallback.screenshotSha256,
		textSha256: sanitizeText(candidate.textSha256, 96) || fallback.textSha256,
	};
}

function normalizeLinkSummary(value: unknown, fallback: LinkSummary): LinkSummary {
	const candidate = isRecord(value) ? value : {};
	return {
		brandRelated: normalizeCount(candidate.brandRelated, fallback.brandRelated),
		external: normalizeCount(candidate.external, fallback.external),
		ipLiteral: normalizeCount(candidate.ipLiteral, fallback.ipLiteral),
		sameHost: normalizeCount(candidate.sameHost, fallback.sameHost),
		sameRoot: normalizeCount(candidate.sameRoot, fallback.sameRoot),
	};
}

function normalizeConfidence(value: unknown, fallback: Confidence): Confidence {
	if (value === 'low' || value === 'medium' || value === 'high') {
		return value;
	}

	return fallback;
}

function normalizeVerdict(value: unknown, fallback: Verdict): Verdict {
	if (value === 'malicious' || value === 'suspicious' || value === 'benign' || value === 'inconclusive') {
		return value;
	}

	return fallback;
}

function normalizeRiskScore(value: unknown, fallback: number): number {
	const numeric = typeof value === 'number' ? value : Number(value);
	if (Number.isFinite(numeric)) {
		return Math.max(0, Math.min(100, Math.round(numeric)));
	}

	return fallback;
}

function normalizeCount(value: unknown, fallback: number): number {
	const numeric = typeof value === 'number' ? value : Number(value);
	if (Number.isFinite(numeric)) {
		return Math.max(0, Math.round(numeric));
	}

	return fallback;
}

function normalizeFormClassification(value: unknown, fallback: FormClassification): FormClassification {
	if (value === 'credential' || value === 'application' || value === 'search' || value === 'input' || value === 'generic') {
		return value;
	}

	return fallback;
}

function normalizeLinkClassification(value: unknown, fallback: LinkClassification): LinkClassification {
	if (
		value === 'same-host' ||
		value === 'same-root' ||
		value === 'brand-related' ||
		value === 'external' ||
		value === 'ip-literal'
	) {
		return value;
	}

	return fallback;
}

function inferSuspicion(targetUrl: string, analystNote: string): { score: number; signals: string[] } {
	const url = targetUrl.toLowerCase();
	const note = analystNote.toLowerCase();
	const signals: string[] = [];
	let score = 18;

	if (/(verify|secure|login|update|wallet|pay|auth|mfa|signin)/.test(url)) {
		score += 28;
		signals.push('The URL contains common credential-theft keywords.');
	}

	if (/\d+\.\d+\.\d+\.\d+/.test(url)) {
		score += 24;
		signals.push('The destination uses an IP-style hostname rather than a branded domain.');
	}

	if (/(urgent|suspended|password|mfa|otp|invoice|crypto)/.test(note)) {
		score += 14;
		signals.push('The analyst note describes urgency or credential-related language.');
	}

	if (url.includes('cloudflare.com') || url.includes('example.com')) {
		score -= 22;
		signals.push('The hostname resembles a known, benign domain.');
	}

	if (signals.length === 0) {
		signals.push('The mock engine did not find a strong structural indicator in the URL alone.');
	}

	return {
		score: Math.max(8, Math.min(96, score)),
		signals: signals.slice(0, 6),
	};
}

function inferBrand(targetUrl: string, analystNote: string): string {
	const combined = `${targetUrl} ${analystNote}`.toLowerCase();
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

function createPlaceholderScreenshot(hostname: string, label: string): string {
	const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="720" viewBox="0 0 1280 720" fill="none">
  <rect width="1280" height="720" rx="32" fill="#0d1117"/>
  <rect x="48" y="48" width="1184" height="624" rx="24" fill="#111827" stroke="#1f2937"/>
  <rect x="84" y="96" width="220" height="28" rx="14" fill="#ef4444"/>
  <rect x="324" y="96" width="220" height="28" rx="14" fill="#f59e0b"/>
  <rect x="564" y="96" width="220" height="28" rx="14" fill="#22c55e"/>
  <text x="84" y="180" fill="#f9fafb" font-family="Arial, sans-serif" font-size="48" font-weight="700">PhishScope Mock Capture</text>
  <text x="84" y="246" fill="#93c5fd" font-family="Arial, sans-serif" font-size="28">${escapeXml(hostname)}</text>
  <text x="84" y="318" fill="#fca5a5" font-family="Arial, sans-serif" font-size="54" font-weight="700">${escapeXml(label)}</text>
  <rect x="84" y="382" width="1112" height="180" rx="18" fill="#1f2937"/>
  <text x="120" y="448" fill="#d1d5db" font-family="Arial, sans-serif" font-size="30">Mock mode stores a placeholder screenshot so the UI and persistence flow stay testable.</text>
  <text x="120" y="502" fill="#9ca3af" font-family="Arial, sans-serif" font-size="24">Use live Browser Rendering to capture the actual page and visual evidence.</text>
</svg>`;
	return `data:image/svg+xml;base64,${toBase64(svg)}`;
}

function toBase64(value: string): string {
	if (typeof Buffer !== 'undefined') {
		return Buffer.from(value).toString('base64');
	}

	return btoa(value);
}

function escapeXml(value: string): string {
	return value
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&apos;');
}

function isRecord(value: unknown): value is Record<string, any> {
	return typeof value === 'object' && value !== null;
}
