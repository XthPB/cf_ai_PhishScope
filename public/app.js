const STORAGE_KEY = 'phishscope-active-case';
const PLACEHOLDER_SCREENSHOT =
	'data:image/svg+xml;base64,' +
	btoa(`<svg xmlns="http://www.w3.org/2000/svg" width="1440" height="960" viewBox="0 0 1440 960" fill="none">
	<rect width="1440" height="960" rx="28" fill="#08131f"/>
	<rect x="36" y="36" width="1368" height="888" rx="24" fill="#0d1d2f" stroke="#18324b"/>
	<text x="92" y="164" fill="#e8f1ff" font-family="Arial, sans-serif" font-size="56" font-weight="700">PhishScope Analyst Console</text>
	<text x="92" y="238" fill="#8ea6c0" font-family="Arial, sans-serif" font-size="30">Run or load a case to render preserved evidence.</text>
	<rect x="92" y="314" width="1256" height="516" rx="20" fill="#0a1624" stroke="#18324b"/>
	<text x="128" y="410" fill="#7f9bbb" font-family="Arial, sans-serif" font-size="28">Screenshot will appear here after Browser Rendering captures the page.</text>
</svg>`);

const state = {
	activeTab: 'overviewTab',
	activeVoiceButton: null,
	activeVoiceField: null,
	caseId: null,
	caseList: [],
	dashboard: null,
	health: null,
	investigation: null,
	loadingState: null,
	pendingMessage: null,
	recognition: null,
	relatedCases: [],
	statusMessage: 'Loading dashboard.',
	turnstileToken: '',
	turnstileWidgetId: null,
};

const elements = {
	aiModeBadge: document.getElementById('aiModeBadge'),
	analyzeButton: document.getElementById('analyzeButton'),
	analyzeForm: document.getElementById('analyzeForm'),
	analystQuestions: document.getElementById('analystQuestions'),
	avgRiskMetric: document.getElementById('avgRiskMetric'),
	benignSignals: document.getElementById('benignSignals'),
	brandHints: document.getElementById('brandHints'),
	brandValue: document.getElementById('brandValue'),
	browserModeBadge: document.getElementById('browserModeBadge'),
	caseLabel: document.getElementById('caseLabel'),
	caseList: document.getElementById('caseList'),
	caseListCount: document.getElementById('caseListCount'),
	caseFilterApplyButton: document.getElementById('caseFilterApplyButton'),
	caseFilterForm: document.getElementById('caseFilterForm'),
	caseFilterResetButton: document.getElementById('caseFilterResetButton'),
	caseSearchInput: document.getElementById('caseSearchInput'),
	caseStatusFilter: document.getElementById('caseStatusFilter'),
	caseVerdictFilter: document.getElementById('caseVerdictFilter'),
	chatForm: document.getElementById('chatForm'),
	chatInput: document.getElementById('chatInput'),
	chatSendButton: document.getElementById('chatSendButton'),
	chatVoiceButton: document.getElementById('chatVoiceButton'),
	captureMeta: document.getElementById('captureMeta'),
	confidenceValue: document.getElementById('confidenceValue'),
	copyLinkButton: document.getElementById('copyLinkButton'),
	escalatedMetric: document.getElementById('escalatedMetric'),
	finalUrl: document.getElementById('finalUrl'),
	formsList: document.getElementById('formsList'),
	highlightText: document.getElementById('highlightText'),
	hostValue: document.getElementById('hostValue'),
	intelChecks: document.getElementById('intelChecks'),
	intelConfidenceValue: document.getElementById('intelConfidenceValue'),
	intelContext: document.getElementById('intelContext'),
	intelFindings: document.getElementById('intelFindings'),
	intelLastUpdatedValue: document.getElementById('intelLastUpdatedValue'),
	intelQuickFacts: document.getElementById('intelQuickFacts'),
	intelSignals: document.getElementById('intelSignals'),
	intelSourceValue: document.getElementById('intelSourceValue'),
	intelStatusValue: document.getElementById('intelStatusValue'),
	intelSummaryText: document.getElementById('intelSummaryText'),
	intelThreatCategoryValue: document.getElementById('intelThreatCategoryValue'),
	linkSummaryList: document.getElementById('linkSummaryList'),
	linksList: document.getElementById('linksList'),
	messages: document.getElementById('messages'),
	mitigationApprovalValue: document.getElementById('mitigationApprovalValue'),
	mitigationModeValue: document.getElementById('mitigationModeValue'),
	mitigationOwnerValue: document.getElementById('mitigationOwnerValue'),
	mitigationQuickFacts: document.getElementById('mitigationQuickFacts'),
	mitigationRationale: document.getElementById('mitigationRationale'),
	mitigationSummaryText: document.getElementById('mitigationSummaryText'),
	mitigationWaf: document.getElementById('mitigationWaf'),
	monitoringText: document.getElementById('monitoringText'),
	needsReviewMetric: document.getElementById('needsReviewMetric'),
	noteInput: document.getElementById('noteInput'),
	noteVoiceButton: document.getElementById('noteVoiceButton'),
	pageTitle: document.getElementById('pageTitle'),
	provenanceList: document.getElementById('provenanceList'),
	radarModeBadge: document.getElementById('radarModeBadge'),
	rateLimitText: document.getElementById('rateLimitText'),
	recommendedAction: document.getElementById('recommendedAction'),
	relatedCasesList: document.getElementById('relatedCasesList'),
	requestedUrl: document.getElementById('requestedUrl'),
	rescanButton: document.getElementById('rescanButton'),
	riskMeterFill: document.getElementById('riskMeterFill'),
	riskScoreValue: document.getElementById('riskScoreValue'),
	rollbackList: document.getElementById('rollbackList'),
	rolloutList: document.getElementById('rolloutList'),
	scanCountValue: document.getElementById('scanCountValue'),
	scheduleDelaySelect: document.getElementById('scheduleDelaySelect'),
	scheduleRescanButton: document.getElementById('scheduleRescanButton'),
	scheduledRescanValue: document.getElementById('scheduledRescanValue'),
	screenshotImage: document.getElementById('screenshotImage'),
	scoreDriversList: document.getElementById('scoreDriversList'),
	statusText: document.getElementById('statusText'),
	statusValue: document.getElementById('statusValue'),
	structuralSignals: document.getElementById('structuralSignals'),
	summaryText: document.getElementById('summaryText'),
	suspiciousSignals: document.getElementById('suspiciousSignals'),
	tabButtons: [...document.querySelectorAll('[data-tab-target]')],
	tagList: document.getElementById('tagList'),
	textExcerpt: document.getElementById('textExcerpt'),
	timelineList: document.getElementById('timelineList'),
	totalCasesMetric: document.getElementById('totalCasesMetric'),
	turnstileText: document.getElementById('turnstileText'),
	turnstileBadge: document.getElementById('turnstileBadge'),
	turnstileContainer: document.getElementById('turnstileContainer'),
	turnstileSection: document.getElementById('turnstileSection'),
	typing: document.getElementById('typing'),
	urlInput: document.getElementById('urlInput'),
	verdictBadge: document.getElementById('verdictBadge'),
	verdictValue: document.getElementById('verdictValue'),
	workspaceHost: document.getElementById('workspaceHost'),
};

bindEvents();
setupVoiceInput();
render();

bootstrap().catch((error) => {
	console.error(error);
	setStatus('Initialization failed.');
});

async function bootstrap() {
	await Promise.all([refreshHealth(), refreshDashboard(), refreshCaseList()]);

	const preferredCase = getPreferredCaseId();
	if (preferredCase) {
		try {
			await loadCase(preferredCase);
			setStatus('Loaded an existing investigation case.');
			return;
		} catch (error) {
			console.warn('Existing case could not be loaded.', error);
			clearPersistedCase();
		}
	}

	setStatus(state.caseList.length ? 'Dashboard ready. Select an indexed case or open a new one.' : 'Dashboard ready. Open a new phishing case to begin.');
	render();
}

function bindEvents() {
	elements.analyzeForm.addEventListener('submit', async (event) => {
		event.preventDefault();

		const url = elements.urlInput.value.trim();
		if (!url || state.loadingState) {
			return;
		}

		setLoading('analysis');
		setStatus('Opening a new case and capturing evidence.');

		try {
			const payload = await fetchJson('/api/cases', {
				body: JSON.stringify({
					analystNote: elements.noteInput.value.trim(),
					turnstileToken: state.turnstileToken || undefined,
					url,
				}),
				headers: { 'content-type': 'application/json' },
				method: 'POST',
			});
			state.pendingMessage = null;
			await applyPayload(payload, { refreshCatalog: true });
			resetTurnstile();
			setStatus('Case opened and indexed.');
		} catch (error) {
			console.error(error);
			setStatus(error.message || 'Investigation failed.');
		} finally {
			setLoading(null);
		}
	});

	elements.rescanButton.addEventListener('click', async () => {
		if (!state.caseId || state.loadingState) {
			return;
		}

		setLoading('analysis');
		setStatus('Running a fresh capture for the active case.');

		try {
			const payload = await fetchJson(`/api/cases/${state.caseId}/rescan`, {
				body: JSON.stringify({
					analystNote: elements.noteInput.value.trim(),
					url: elements.urlInput.value.trim(),
				}),
				headers: { 'content-type': 'application/json' },
				method: 'POST',
			});
			await applyPayload(payload, { refreshCatalog: true });
			setStatus('Manual rescan completed.');
		} catch (error) {
			console.error(error);
			setStatus(error.message || 'Rescan failed.');
		} finally {
			setLoading(null);
		}
	});

	elements.scheduleRescanButton.addEventListener('click', async () => {
		if (!state.caseId || state.loadingState) {
			return;
		}

		setLoading('analysis');
		setStatus('Scheduling an automated rescan.');

		try {
			const payload = await fetchJson(`/api/cases/${state.caseId}/schedule-rescan`, {
				body: JSON.stringify({
					analystNote: elements.noteInput.value.trim(),
					delaySeconds: Number(elements.scheduleDelaySelect.value),
					url: elements.urlInput.value.trim(),
				}),
				headers: { 'content-type': 'application/json' },
				method: 'POST',
			});
			await applyPayload(payload, { refreshCatalog: true });
			setStatus(`Automated rescan queued for ${formatDate(payload.scheduledRescan?.runAt || state.investigation?.scheduledRescanAt)}.`);
		} catch (error) {
			console.error(error);
			setStatus(error.message || 'Scheduled rescan failed.');
		} finally {
			setLoading(null);
		}
	});

	elements.copyLinkButton.addEventListener('click', async () => {
		if (!state.caseId) {
			return;
		}

		try {
			await navigator.clipboard.writeText(buildCaseUrl(state.caseId));
			setStatus('Case link copied.');
		} catch (error) {
			console.error(error);
			setStatus('Clipboard access failed.');
		}
	});

	elements.chatForm.addEventListener('submit', async (event) => {
		event.preventDefault();
		if (!state.caseId || state.loadingState) {
			return;
		}

		const message = elements.chatInput.value.trim();
		if (!message) {
			return;
		}

		elements.chatInput.value = '';
		state.pendingMessage = {
			content: message,
			role: 'user',
			timestamp: new Date().toISOString(),
		};
		setLoading('followup');
		setStatus('Processing follow-up against the active case.');
		renderMessages();

		try {
			const payload = await fetchJson(`/api/cases/${state.caseId}/messages`, {
				body: JSON.stringify({ message }),
				headers: { 'content-type': 'application/json' },
				method: 'POST',
			});
			state.pendingMessage = null;
			await applyPayload(payload, { refreshCatalog: true });
			setStatus('Follow-up response added to the case timeline.');
		} catch (error) {
			console.error(error);
			state.pendingMessage = null;
			renderMessages();
			setStatus(error.message || 'Follow-up failed.');
		} finally {
			setLoading(null);
		}
	});

	elements.caseFilterForm.addEventListener('submit', async (event) => {
		event.preventDefault();
		try {
			await refreshCaseList();
			setStatus('Applied queue filters.');
		} catch (error) {
			console.error(error);
			setStatus(error.message || 'Case filter failed.');
		}
	});
	elements.caseFilterResetButton.addEventListener('click', async () => {
		elements.caseSearchInput.value = '';
		elements.caseVerdictFilter.value = 'all';
		elements.caseStatusFilter.value = 'all';
		try {
			await refreshCaseList();
			setStatus('Cleared queue filters.');
		} catch (error) {
			console.error(error);
			setStatus(error.message || 'Queue reset failed.');
		}
	});

	elements.caseList.addEventListener('click', async (event) => {
		const row = event.target.closest('[data-case-id]');
		if (!row || state.loadingState) {
			return;
		}

		try {
			setStatus('Loading indexed case.');
			await loadCase(row.dataset.caseId);
			setStatus('Indexed case loaded.');
		} catch (error) {
			console.error(error);
			setStatus(error.message || 'Case load failed.');
		}
	});

	elements.analystQuestions.addEventListener('click', (event) => {
		const button = event.target.closest('[data-question]');
		if (!button) {
			return;
		}

		elements.chatInput.value = button.dataset.question || '';
		elements.chatInput.focus();
	});

	elements.chatInput.addEventListener('keydown', (event) => {
		if (event.key === 'Enter' && !event.shiftKey) {
			event.preventDefault();
			elements.chatForm.requestSubmit();
		}
	});

	elements.tabButtons.forEach((button) => {
		button.addEventListener('click', () => setActiveTab(button.dataset.tabTarget));
	});

	elements.noteVoiceButton.addEventListener('click', () => startVoiceCapture(elements.noteInput, elements.noteVoiceButton));
	elements.chatVoiceButton.addEventListener('click', () => startVoiceCapture(elements.chatInput, elements.chatVoiceButton));
}

async function refreshHealth() {
	try {
		state.health = await fetchJson('/api/health');
		renderHealth();
		renderTurnstile();
	} catch (error) {
		console.warn('Health request failed.', error);
	}
}

async function refreshDashboard() {
	try {
		const payload = await fetchJson('/api/dashboard');
		state.dashboard = payload.dashboard || null;
		renderDashboard();
	} catch (error) {
		console.warn('Dashboard request failed.', error);
	}
}

async function refreshCaseList() {
	const params = new URLSearchParams();
	params.set('limit', '24');

	if (elements.caseSearchInput.value.trim()) {
		params.set('search', elements.caseSearchInput.value.trim());
	}
	if (elements.caseVerdictFilter.value !== 'all') {
		params.set('verdict', elements.caseVerdictFilter.value);
	}
	if (elements.caseStatusFilter.value !== 'all') {
		params.set('status', elements.caseStatusFilter.value);
	}

	const payload = await fetchJson(`/api/cases?${params.toString()}`);
	state.caseList = Array.isArray(payload.cases) ? payload.cases : [];
	renderCaseList();
}

async function loadCase(caseId) {
	const payload = await fetchJson(`/api/cases/${caseId}`);
	await applyPayload({ caseId, ...payload });
}

async function applyPayload(payload, options = {}) {
	if (payload.caseId) {
		state.caseId = payload.caseId;
	}

	if (payload.investigation) {
		state.investigation = payload.investigation;
		elements.urlInput.value = payload.investigation.targetUrl || '';
		elements.noteInput.value = payload.investigation.analystNote || '';
	}

	state.relatedCases = Array.isArray(payload.relatedCases) ? payload.relatedCases : [];

	if (payload.mode && state.health) {
		state.health.aiMode = payload.mode.ai;
		state.health.browserMode = payload.mode.browser;
	}

	persistActiveCase();
	render();

	if (options.refreshCatalog) {
		await Promise.all([refreshDashboard(), refreshCaseList()]);
	}
}

function render() {
	renderHealth();
	renderDashboard();
	renderCaseList();
	renderWorkspace();
	renderQuestions();
	renderMessages();
	renderTabs();
}

function renderHealth() {
	const aiLive = state.health?.aiMode === 'workers-ai';
	const browserLive = state.health?.browserMode === 'browser-rendering';
	const radarLive = Boolean(state.health?.features?.radarOps);
	const turnstileEnabled = Boolean(state.health?.features?.turnstile);

	elements.aiModeBadge.textContent = aiLive ? 'Workers AI live' : 'Mock AI mode';
	elements.aiModeBadge.className = `status-pill ${aiLive ? '' : 'status-pill--warning'}`.trim();
	elements.browserModeBadge.textContent = browserLive ? 'Browser Rendering live' : 'Mock browser mode';
	elements.browserModeBadge.className = `status-pill ${browserLive ? 'status-pill--quiet' : 'status-pill--warning'}`.trim();
	elements.radarModeBadge.textContent = radarLive ? 'RadarOps live' : 'RadarOps heuristic';
	elements.radarModeBadge.className = `status-pill ${radarLive ? '' : 'status-pill--quiet'}`.trim();
	elements.turnstileBadge.textContent = turnstileEnabled ? 'Turnstile enforced' : 'Intake hardening optional';
	elements.turnstileBadge.className = `status-pill ${turnstileEnabled ? '' : 'status-pill--quiet'}`.trim();
	elements.statusText.textContent = state.statusMessage;
}

function renderDashboard() {
	const dashboard = state.dashboard || {
		averageRiskScore: 0,
		escalatedCases: 0,
		needsReviewCases: 0,
		totalCases: 0,
	};

	elements.totalCasesMetric.textContent = String(dashboard.totalCases || 0);
	elements.needsReviewMetric.textContent = String(dashboard.needsReviewCases || 0);
	elements.escalatedMetric.textContent = String(dashboard.escalatedCases || 0);
	elements.avgRiskMetric.textContent = String(dashboard.averageRiskScore || 0);
}

function renderCaseList() {
	elements.caseList.replaceChildren();
	elements.caseListCount.textContent = `${state.caseList.length} case${state.caseList.length === 1 ? '' : 's'}`;

	if (!state.caseList.length) {
		elements.caseList.append(createEmptyText('No indexed cases match the current filters.'));
		return;
	}

	state.caseList.forEach((item) => {
		const button = document.createElement('button');
		button.type = 'button';
		button.className = `case-row ${item.caseId === state.caseId ? 'is-active' : ''}`.trim();
		button.dataset.caseId = item.caseId;
		button.innerHTML = `
			<div class="case-row__top">
				<div>
					<p class="case-row__title">${escapeHtml(item.hostname || item.impersonatedBrand || 'Unknown host')}</p>
					<p class="case-row__url">${escapeHtml(item.pageTitle || item.targetUrl)}</p>
				</div>
				<span class="mini-pill mini-pill--${escapeHtml(item.verdict)}">${escapeHtml(formatVerdict(item.verdict))}</span>
			</div>
			<div class="case-row__bottom">
				<div class="case-row__meta">
					<span class="mini-pill">risk ${escapeHtml(String(item.riskScore))}</span>
					<span class="mini-pill">${escapeHtml(formatStatus(item.status))}</span>
					<span class="mini-pill">${escapeHtml(String(item.scanCount))} scans</span>
				</div>
				<span class="mini-pill">${escapeHtml(item.impersonatedBrand || 'Unknown')}</span>
			</div>
		`;
		elements.caseList.append(button);
	});
}

function renderWorkspace() {
	const investigation = state.investigation;
	const evidence = investigation?.evidence;
	const assessment = investigation?.assessment;
	const radar = investigation?.radar;
	const mitigation = investigation?.mitigation;
	const scoreDrivers = investigation?.scoreDrivers || [];
	const hasCase = Boolean(investigation);
	const isBusy = Boolean(state.loadingState);

	elements.rescanButton.disabled = !hasCase || isBusy;
	elements.scheduleRescanButton.disabled = !hasCase || isBusy;
	elements.copyLinkButton.disabled = !hasCase;
	elements.chatSendButton.disabled = !hasCase || isBusy;

	if (!investigation || !evidence || !assessment) {
		elements.caseLabel.textContent = 'No case selected';
		elements.workspaceHost.textContent = 'Run a case to populate the investigation workspace.';
		elements.verdictBadge.textContent = 'Awaiting scan';
		elements.verdictBadge.className = 'verdict-pill verdict-pill--neutral';
		elements.riskScoreValue.textContent = '0';
		elements.verdictValue.textContent = 'Pending';
		elements.statusValue.textContent = 'TRIAGE';
		elements.scanCountValue.textContent = '0';
		elements.confidenceValue.textContent = 'LOW';
		elements.scheduledRescanValue.textContent = 'None';
		elements.summaryText.textContent = 'Run a case to generate an executive summary.';
		elements.highlightText.textContent = 'No evidence collected yet.';
		elements.recommendedAction.textContent = 'Run a scan before making a decision.';
		elements.brandValue.textContent = 'Unknown';
		elements.hostValue.textContent = 'N/A';
		elements.captureMeta.textContent = 'No capture yet';
		elements.requestedUrl.textContent = 'N/A';
		elements.finalUrl.textContent = 'N/A';
		elements.pageTitle.textContent = 'No capture yet.';
		elements.textExcerpt.textContent = 'No rendered text yet.';
		elements.screenshotImage.src = PLACEHOLDER_SCREENSHOT;
		elements.riskMeterFill.style.width = '0%';
		elements.intelSummaryText.textContent = 'RadarOps context will appear after the first scan.';
		elements.intelContext.textContent = 'RadarOps context will appear after the first scan.';
		elements.intelSourceValue.textContent = 'Unavailable';
		elements.intelStatusValue.textContent = 'Not run';
		elements.intelThreatCategoryValue.textContent = 'Unavailable';
		elements.intelConfidenceValue.textContent = 'LOW';
		elements.intelLastUpdatedValue.textContent = 'N/A';
		elements.mitigationSummaryText.textContent = 'Mitigation drafting will appear after the first assessment.';
		elements.mitigationModeValue.textContent = 'Awaiting assessment';
		elements.mitigationOwnerValue.textContent = 'Security analyst';
		elements.mitigationApprovalValue.textContent = 'Yes';
		elements.mitigationRationale.textContent = 'No mitigation rationale is available yet.';
		elements.mitigationWaf.textContent = '(not generated yet)';
		elements.rateLimitText.textContent = 'No rate-limit recommendation available yet.';
		elements.turnstileText.textContent = 'No Turnstile recommendation available yet.';
		elements.monitoringText.textContent = 'No monitoring recommendation available yet.';
		renderTextList(elements.suspiciousSignals, ['No suspicious evidence collected yet.']);
		renderTextList(elements.benignSignals, ['No benign evidence collected yet.']);
		renderTextList(elements.structuralSignals, ['No structural indicators available yet.']);
		renderTextList(elements.brandHints, ['No visible brand hints extracted.']);
		renderTextList(elements.intelSignals, ['No RadarOps anomaly signals attached yet.']);
		renderTextList(elements.intelChecks, ['Run the first scan to populate RadarOps guidance.']);
		renderTagList([]);
		renderScoreDrivers([]);
		renderProvenanceList([]);
		renderKeyValueList(elements.intelQuickFacts, [], 'Intel source details will appear after a case scan.');
		renderKeyValueList(elements.mitigationQuickFacts, [], 'Mitigation quick facts will appear after a case scan.');
		renderLinkSummary(null);
		renderIntelFindings([]);
		renderForms([]);
		renderLinks([]);
		renderStepList(elements.rolloutList, [], 'Rollout steps will appear once a mitigation plan exists.');
		renderStepList(elements.rollbackList, [], 'Rollback steps will appear once a mitigation plan exists.');
		renderTimeline([]);
		renderRelatedCases([]);
		return;
	}

	elements.caseLabel.textContent = `Case ${investigation.caseId.slice(0, 8).toUpperCase()}`;
	elements.workspaceHost.textContent = `${evidence.hostname || 'Unknown host'} • updated ${formatDate(investigation.updatedAt)}`;
	elements.verdictBadge.textContent = `${formatVerdict(assessment.verdict)} · ${assessment.riskScore}`;
	elements.verdictBadge.className = `verdict-pill verdict-pill--${assessment.verdict}`;
	elements.riskScoreValue.textContent = String(assessment.riskScore);
	elements.verdictValue.textContent = formatVerdict(assessment.verdict);
	elements.statusValue.textContent = formatStatus(investigation.status);
	elements.scanCountValue.textContent = String(investigation.scanCount);
	elements.confidenceValue.textContent = assessment.confidence.toUpperCase();
	elements.scheduledRescanValue.textContent = investigation.scheduledRescanAt ? formatDate(investigation.scheduledRescanAt) : 'None';
	elements.summaryText.textContent = assessment.executiveSummary;
	elements.highlightText.textContent = assessment.highlight;
	elements.recommendedAction.textContent = assessment.recommendedAction;
	elements.brandValue.textContent = assessment.impersonatedBrand || 'Unknown';
	elements.hostValue.textContent = evidence.hostname || 'N/A';
	elements.captureMeta.textContent = `Captured ${formatDate(evidence.captureTimestamp)}`;
	elements.requestedUrl.textContent = evidence.requestedUrl;
	elements.finalUrl.textContent = evidence.finalUrl;
	elements.pageTitle.textContent = evidence.pageTitle;
	elements.textExcerpt.textContent = evidence.textExcerpt || 'No rendered text captured.';
	elements.screenshotImage.src = evidence.screenshotDataUrl || PLACEHOLDER_SCREENSHOT;
	elements.riskMeterFill.style.width = `${assessment.riskScore}%`;
	elements.intelSummaryText.textContent = radar?.summary || 'No RadarOps summary is attached to this case.';
	elements.intelContext.textContent = radar?.networkContext || 'No RadarOps network context is attached to this case.';
	elements.intelSourceValue.textContent = formatIntelSource(radar?.source);
	elements.intelStatusValue.textContent = formatTitleCase(radar?.urlScanStatus || 'not-run');
	elements.intelThreatCategoryValue.textContent = radar?.threatCategory || 'Unavailable';
	elements.intelConfidenceValue.textContent = String(radar?.confidence || 'low').toUpperCase();
	elements.intelLastUpdatedValue.textContent = formatDate(radar?.lastUpdated);
	elements.mitigationSummaryText.textContent = mitigation?.summary || 'No mitigation summary is attached to this case.';
	elements.mitigationModeValue.textContent = formatMitigationMode(mitigation?.mode);
	elements.mitigationOwnerValue.textContent = mitigation?.suggestedOwner || 'Security analyst';
	elements.mitigationApprovalValue.textContent = mitigation?.approvalRequired ? 'Yes' : 'No';
	elements.mitigationRationale.textContent = mitigation?.rationale || 'No mitigation rationale is available yet.';
	elements.mitigationWaf.textContent = mitigation?.wafExpression || '(not generated yet)';
	elements.rateLimitText.textContent = mitigation?.rateLimitRecommendation || 'No rate-limit recommendation available yet.';
	elements.turnstileText.textContent = mitigation?.turnstileRecommendation || 'No Turnstile recommendation available yet.';
	elements.monitoringText.textContent =
		mitigation?.monitoringRecommendation || 'No monitoring recommendation available yet.';

	renderTextList(elements.suspiciousSignals, assessment.suspiciousSignals);
	renderTextList(elements.benignSignals, assessment.benignSignals);
	renderTextList(elements.structuralSignals, evidence.structuralSignals);
	renderTextList(elements.brandHints, evidence.visibleBrandHints.length ? evidence.visibleBrandHints : ['No visible brand hints extracted.']);
	renderTextList(elements.intelSignals, radar?.anomalySignals?.length ? radar.anomalySignals : ['No RadarOps anomaly signals attached yet.']);
	renderTextList(elements.intelChecks, radar?.recommendedChecks?.length ? radar.recommendedChecks : ['No RadarOps follow-up checks were generated.']);
	renderTagList(investigation.tags);
	renderScoreDrivers(scoreDrivers);
	renderProvenanceList([
		{ label: 'Screenshot SHA-256', value: evidence.hashes?.screenshotSha256 || 'Unavailable' },
		{ label: 'Text SHA-256', value: evidence.hashes?.textSha256 || 'Unavailable' },
		{ label: 'Metadata SHA-256', value: evidence.hashes?.metadataSha256 || 'Unavailable' },
		{ label: 'Redirected', value: evidence.redirected ? 'Yes' : 'No' },
	]);
	renderKeyValueList(
		elements.intelQuickFacts,
		[
			{ label: 'Source', value: formatIntelSource(radar?.source) },
			{ label: 'Status', value: formatTitleCase(radar?.urlScanStatus || 'not-run') },
			{ label: 'Category', value: radar?.threatCategory || 'Unavailable' },
		],
		'Intel source details will appear after a case scan.',
	);
	renderKeyValueList(
		elements.mitigationQuickFacts,
		[
			{ label: 'Mode', value: formatMitigationMode(mitigation?.mode) },
			{ label: 'Owner', value: mitigation?.suggestedOwner || 'Security analyst' },
			{ label: 'Approval', value: mitigation?.approvalRequired ? 'Required' : 'Not required' },
		],
		'Mitigation quick facts will appear after a case scan.',
	);
	renderLinkSummary(evidence.linkSummary);
	renderIntelFindings(radar?.findings || []);
	renderForms(evidence.forms);
	renderLinks(evidence.topLinks);
	renderStepList(
		elements.rolloutList,
		mitigation?.rolloutSteps || [],
		'Rollout steps will appear once a mitigation plan exists.',
	);
	renderStepList(
		elements.rollbackList,
		mitigation?.rollbackSteps || [],
		'Rollback steps will appear once a mitigation plan exists.',
	);
	renderTimeline(investigation.timeline || []);
	renderRelatedCases(state.relatedCases);
}

function renderQuestions() {
	elements.analystQuestions.replaceChildren();

	const questions = state.investigation?.assessment?.analystQuestions || [];
	if (!questions.length) {
		elements.analystQuestions.append(createEmptyText('Suggested analyst prompts will appear after the first assessment.'));
		return;
	}

	questions.forEach((question) => {
		const button = document.createElement('button');
		button.className = 'follow-up__button';
		button.type = 'button';
		button.dataset.question = question;
		button.textContent = question;
		elements.analystQuestions.append(button);
	});
}

function renderMessages() {
	elements.messages.replaceChildren();

	const messages = [...(state.investigation?.messages || [])];
	if (state.pendingMessage) {
		messages.push(state.pendingMessage);
	}

	if (!messages.length) {
		elements.messages.append(createEmptyText('Open a case to preserve analyst notes, verdict updates, and follow-up answers in the case timeline.'));
	} else {
		messages.forEach((message) => {
			const article = document.createElement('article');
			article.className = `message message--${message.role}`;

			const meta = document.createElement('div');
			meta.className = 'message__meta';
			meta.textContent = `${message.role === 'assistant' ? 'PhishScope' : 'Analyst'} · ${formatTime(message.timestamp)}`;

			const body = document.createElement('p');
			body.className = 'message__body';
			body.textContent = message.content;

			article.append(meta, body);
			elements.messages.append(article);
		});
	}

	elements.typing.hidden = state.loadingState !== 'followup';
	scrollToBottom(elements.messages);
}

function renderTextList(root, values) {
	root.replaceChildren();
	values.forEach((value) => {
		const item = document.createElement('li');
		item.textContent = value;
		root.append(item);
	});
}

function renderTagList(tags) {
	elements.tagList.replaceChildren();

	if (!tags.length) {
		elements.tagList.append(createEmptyText('No case tags assigned yet.'));
		return;
	}

	tags.forEach((tag) => {
		const chip = document.createElement('span');
		chip.className = 'tag';
		chip.textContent = tag;
		elements.tagList.append(chip);
	});
}

function renderScoreDrivers(drivers) {
	elements.scoreDriversList.replaceChildren();

	if (!drivers.length) {
		elements.scoreDriversList.append(createEmptyText('Score drivers will appear after the first assessment.'));
		return;
	}

	drivers.forEach((driver) => {
		const row = document.createElement('div');
		const directionClass = driver.impact >= 0 ? 'driver-row--positive' : 'driver-row--negative';
		row.className = `driver-row ${directionClass}`;
		row.innerHTML = `
			<div class="driver-row__top">
				<p class="detail-label">${escapeHtml(driver.label)}</p>
				<span class="driver-impact ${driver.impact >= 0 ? 'driver-impact--positive' : 'driver-impact--negative'}">${escapeHtml(
					formatImpact(driver.impact),
				)}</span>
			</div>
			<p class="detail-text">${escapeHtml(driver.detail)}</p>
		`;
		elements.scoreDriversList.append(row);
	});
}

function renderKeyValueList(root, rows, emptyMessage, valueClass = 'detail-text') {
	root.replaceChildren();

	if (!rows.length) {
		root.append(createEmptyText(emptyMessage));
		return;
	}

	rows.forEach((row) => {
		const wrapper = document.createElement('div');
		wrapper.className = 'provenance-row';
		wrapper.innerHTML = `
			<p class="detail-label">${escapeHtml(row.label)}</p>
			<p class="${escapeHtml(valueClass)}">${escapeHtml(row.value)}</p>
		`;
		root.append(wrapper);
	});
}

function renderProvenanceList(rows) {
	renderKeyValueList(
		elements.provenanceList,
		rows,
		'Evidence provenance will be attached after a render.',
		'detail-text detail-text--mono',
	);
}

function renderLinkSummary(summary) {
	elements.linkSummaryList.replaceChildren();

	if (!summary) {
		elements.linkSummaryList.append(createEmptyText('Network summary is unavailable until links are extracted.'));
		return;
	}

	const rows = [
		{ label: 'Same host', value: summary.sameHost },
		{ label: 'Same root', value: summary.sameRoot },
		{ label: 'Brand related', value: summary.brandRelated },
		{ label: 'External', value: summary.external },
		{ label: 'IP literal', value: summary.ipLiteral },
	];

	rows.forEach((row) => {
		const wrapper = document.createElement('div');
		wrapper.className = 'provenance-row';
		wrapper.innerHTML = `
			<p class="detail-label">${escapeHtml(row.label)}</p>
			<p class="detail-text">${escapeHtml(String(row.value))}</p>
		`;
		elements.linkSummaryList.append(wrapper);
	});
}

function renderIntelFindings(findings) {
	elements.intelFindings.replaceChildren();

	if (!findings.length) {
		elements.intelFindings.append(createEmptyText('RadarOps findings will appear after enrichment is attached.'));
		return;
	}

	findings.forEach((finding) => {
		const row = document.createElement('div');
		row.className = `intel-finding intel-finding--${finding.emphasis || 'neutral'}`;
		row.innerHTML = `
			<p class="detail-label">${escapeHtml(finding.label || 'Finding')}</p>
			<p class="detail-text">${escapeHtml(finding.value || 'Unavailable')}</p>
		`;
		elements.intelFindings.append(row);
	});
}

function renderForms(forms) {
	elements.formsList.replaceChildren();

	if (!forms.length) {
		elements.formsList.append(createEmptyText('No forms were extracted from the rendered page.'));
		return;
	}

	forms.forEach((form) => {
		const row = document.createElement('div');
		row.className = 'artifact-row';
		row.innerHTML = `
			<span class="artifact-chip">${escapeHtml(form.classification)}</span>
			<p><strong>Action:</strong> ${escapeHtml(form.action || 'None')}</p>
			<p><strong>Method:</strong> ${escapeHtml((form.method || 'get').toUpperCase())}</p>
			<p><strong>Password field:</strong> ${form.hasPassword ? 'Yes' : 'No'}</p>
			<p><strong>Inputs:</strong> ${escapeHtml((form.inputTypes || []).join(', ') || 'None')}</p>
		`;
		elements.formsList.append(row);
	});
}

function renderLinks(links) {
	elements.linksList.replaceChildren();

	if (!links.length) {
		elements.linksList.append(createEmptyText('No visible links were extracted from the rendered page.'));
		return;
	}

	links.forEach((link) => {
		const row = document.createElement('div');
		row.className = 'artifact-row';
		row.innerHTML = `
			<span class="artifact-chip">${escapeHtml(link.classification)}</span>
			<p><strong>Host:</strong> ${escapeHtml(link.hostname || 'Unknown')}</p>
			<p><strong>Text:</strong> ${escapeHtml(link.text || 'No visible text')}</p>
			<p class="artifact-row__mono">${escapeHtml(link.href)}</p>
		`;
		elements.linksList.append(row);
	});
}

function renderStepList(root, steps, emptyMessage) {
	root.replaceChildren();

	if (!steps.length) {
		root.append(createEmptyText(emptyMessage));
		return;
	}

	steps.forEach((step) => {
		const item = document.createElement('li');
		item.textContent = step;
		root.append(item);
	});
}

function renderTimeline(events) {
	elements.timelineList.replaceChildren();

	if (!events.length) {
		elements.timelineList.append(createEmptyText('Case activity will appear here after the first scan.'));
		return;
	}

	[...events].reverse().forEach((event) => {
		const row = document.createElement('div');
		row.className = 'timeline-row';
		row.innerHTML = `
			<div class="timeline-row__top">
				<p class="detail-label">${escapeHtml(event.type)}</p>
				<span class="mini-pill">${escapeHtml(formatTime(event.timestamp))}</span>
			</div>
			<p class="timeline-row__summary">${escapeHtml(event.summary)}</p>
			<p class="detail-text">${escapeHtml(event.detail || `${formatActor(event.actor)} activity`)}</p>
		`;
		elements.timelineList.append(row);
	});
}

function renderRelatedCases(cases) {
	elements.relatedCasesList.replaceChildren();

	if (!cases.length) {
		elements.relatedCasesList.append(createEmptyText('No related cases have been indexed yet.'));
		return;
	}

	cases.forEach((item) => {
		const row = document.createElement('button');
		row.type = 'button';
		row.className = 'related-row';
		row.dataset.caseId = item.caseId;
		row.innerHTML = `
			<div class="related-row__top">
				<p class="detail-label">${escapeHtml(item.hostname || item.impersonatedBrand || 'Unknown host')}</p>
				<span class="mini-pill mini-pill--${escapeHtml(item.verdict)}">${escapeHtml(formatVerdict(item.verdict))}</span>
			</div>
			<p class="related-row__summary">${escapeHtml(item.summary || item.pageTitle || item.targetUrl)}</p>
		`;
		row.addEventListener('click', async () => {
			try {
				setStatus('Loading related case.');
				await loadCase(item.caseId);
				setStatus('Related case loaded.');
			} catch (error) {
				console.error(error);
				setStatus(error.message || 'Related case load failed.');
			}
		});
		elements.relatedCasesList.append(row);
	});
}

function renderTabs() {
	elements.tabButtons.forEach((button) => {
		button.classList.toggle('is-active', button.dataset.tabTarget === state.activeTab);
	});

	document.querySelectorAll('.tab-panel').forEach((panel) => {
		panel.classList.toggle('is-active', panel.id === state.activeTab);
	});
}

function renderTurnstile() {
	const siteKey = state.health?.turnstileSiteKey;
	const enabled = Boolean(state.health?.features?.turnstile && siteKey);

	elements.turnstileSection.hidden = !enabled;
	if (!enabled || state.turnstileWidgetId !== null) {
		return;
	}

	if (!window.turnstile?.render) {
		window.setTimeout(renderTurnstile, 250);
		return;
	}

	state.turnstileWidgetId = window.turnstile.render(elements.turnstileContainer, {
		callback(token) {
			state.turnstileToken = token;
			setStatus('Turnstile verification completed.');
		},
		'expired-callback'() {
			state.turnstileToken = '';
			setStatus('Turnstile token expired. Verify again before intake.');
		},
		sitekey: siteKey,
		'theme': 'dark',
	});
}

function setupVoiceInput() {
	const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
	if (!SpeechRecognition) {
		elements.noteVoiceButton.disabled = true;
		elements.chatVoiceButton.disabled = true;
		return;
	}

	const recognition = new SpeechRecognition();
	recognition.continuous = false;
	recognition.interimResults = true;
	recognition.lang = 'en-US';

	recognition.addEventListener('start', () => {
		if (state.activeVoiceButton) {
			state.activeVoiceButton.textContent = 'Stop voice';
		}
		setStatus('Listening for voice input.');
	});

	recognition.addEventListener('result', (event) => {
		const transcript = Array.from(event.results)
			.map((result) => result[0]?.transcript || '')
			.join(' ')
			.trim();

		if (state.activeVoiceField) {
			state.activeVoiceField.value = transcript;
		}
	});

	recognition.addEventListener('end', () => {
		if (state.activeVoiceButton) {
			state.activeVoiceButton.textContent = state.activeVoiceButton === elements.noteVoiceButton ? 'Voice note' : 'Voice question';
		}
		state.activeVoiceButton = null;
		state.activeVoiceField = null;
		setStatus('Voice transcript inserted.');
	});

	recognition.addEventListener('error', (event) => {
		console.warn('Voice error', event.error);
		setStatus(`Voice input error: ${event.error}`);
	});

	state.recognition = recognition;
}

function startVoiceCapture(target, button) {
	if (!state.recognition) {
		setStatus('Voice input is not supported in this browser.');
		return;
	}

	if (state.activeVoiceButton === button) {
		state.recognition.stop();
		return;
	}

	state.activeVoiceField = target;
	state.activeVoiceButton = button;
	state.recognition.start();
}

function resetTurnstile() {
	state.turnstileToken = '';
	if (state.turnstileWidgetId !== null && window.turnstile?.reset) {
		window.turnstile.reset(state.turnstileWidgetId);
	}
}

function persistActiveCase() {
	if (!state.caseId) {
		clearPersistedCase();
		return;
	}

	window.localStorage.setItem(STORAGE_KEY, state.caseId);
	const url = new URL(window.location.href);
	url.searchParams.set('case', state.caseId);
	window.history.replaceState({}, '', url);
}

function clearPersistedCase() {
	state.caseId = null;
	window.localStorage.removeItem(STORAGE_KEY);
	const url = new URL(window.location.href);
	url.searchParams.delete('case');
	window.history.replaceState({}, '', url);
}

function getPreferredCaseId() {
	const url = new URL(window.location.href);
	return url.searchParams.get('case') || window.localStorage.getItem(STORAGE_KEY);
}

function setActiveTab(tabId) {
	state.activeTab = tabId || 'overviewTab';
	renderTabs();
}

function setLoading(nextState) {
	state.loadingState = nextState;
	const isLoading = Boolean(nextState);
	elements.analyzeButton.disabled = isLoading;
	elements.caseFilterApplyButton.disabled = isLoading;
	elements.caseFilterResetButton.disabled = isLoading;
	elements.rescanButton.disabled = !state.investigation || isLoading;
	elements.scheduleRescanButton.disabled = !state.investigation || isLoading;
	elements.chatSendButton.disabled = !state.investigation || isLoading;
}

function setStatus(message) {
	state.statusMessage = message;
	elements.statusText.textContent = message;
}

async function fetchJson(path, init = {}) {
	const response = await fetch(path, init);
	let payload = null;

	try {
		payload = await response.json();
	} catch {
		payload = null;
	}

	if (!response.ok) {
		const message = payload?.error || `Request failed with status ${response.status}`;
		throw new Error(message);
	}

	return payload || {};
}

function createEmptyText(text) {
	const paragraph = document.createElement('p');
	paragraph.className = 'empty-text';
	paragraph.textContent = text;
	return paragraph;
}

function buildCaseUrl(caseId) {
	const url = new URL(window.location.href);
	url.searchParams.set('case', caseId);
	return url.toString();
}

function formatVerdict(verdict) {
	return String(verdict || 'inconclusive').replace(/_/g, ' ').toUpperCase();
}

function formatStatus(status) {
	return String(status || 'triage').replace(/_/g, ' ').toUpperCase();
}

function formatTitleCase(value) {
	return String(value || '')
		.split(/[_\s-]+/)
		.filter(Boolean)
		.map((segment) => segment.charAt(0).toUpperCase() + segment.slice(1).toLowerCase())
		.join(' ');
}

function formatImpact(value) {
	const amount = Number(value || 0);
	return `${amount > 0 ? '+' : ''}${amount}`;
}

function formatIntelSource(source) {
	if (source === 'radar-url-scanner') {
		return 'Radar URL Scanner';
	}

	return 'Heuristic correlation';
}

function formatMitigationMode(mode) {
	switch (mode) {
		case 'block':
			return 'Block candidate';
		case 'review':
			return 'Analyst review';
		default:
			return 'Monitor only';
	}
}

function formatActor(actor) {
	return actor === 'automation' ? 'Automated' : actor === 'analyst' ? 'Analyst' : 'System';
}

function formatDate(value) {
	if (!value) {
		return 'N/A';
	}

	const date = new Date(value);
	if (Number.isNaN(date.getTime())) {
		return 'N/A';
	}

	return new Intl.DateTimeFormat(undefined, {
		dateStyle: 'medium',
		timeStyle: 'short',
	}).format(date);
}

function formatTime(value) {
	if (!value) {
		return 'N/A';
	}

	const date = new Date(value);
	if (Number.isNaN(date.getTime())) {
		return 'N/A';
	}

	return new Intl.DateTimeFormat(undefined, {
		hour: 'numeric',
		minute: '2-digit',
	}).format(date);
}

function stringifyValue(value) {
	return value == null ? '' : String(value);
}

function escapeHtml(value) {
	return stringifyValue(value)
		.replaceAll('&', '&amp;')
		.replaceAll('<', '&lt;')
		.replaceAll('>', '&gt;')
		.replaceAll('"', '&quot;')
		.replaceAll("'", '&#39;');
}

function scrollToBottom(root) {
	root.scrollTop = root.scrollHeight;
}
