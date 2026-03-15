const STORAGE_KEY = 'phishscope-active-case';

const state = {
	activeVoiceButton: null,
	activeVoiceField: null,
	caseId: null,
	health: null,
	investigation: null,
	loadingState: null,
	pendingMessage: null,
	recognition: null,
};

const elements = {
	aiModeBadge: document.getElementById('aiModeBadge'),
	analyzeButton: document.getElementById('analyzeButton'),
	analyzeForm: document.getElementById('analyzeForm'),
	analystQuestions: document.getElementById('analystQuestions'),
	benignSignals: document.getElementById('benignSignals'),
	brandHints: document.getElementById('brandHints'),
	brandValue: document.getElementById('brandValue'),
	browserModeBadge: document.getElementById('browserModeBadge'),
	caseLabel: document.getElementById('caseLabel'),
	chatForm: document.getElementById('chatForm'),
	chatInput: document.getElementById('chatInput'),
	chatSendButton: document.getElementById('chatSendButton'),
	chatVoiceButton: document.getElementById('chatVoiceButton'),
	captureMeta: document.getElementById('captureMeta'),
	confidenceValue: document.getElementById('confidenceValue'),
	copyLinkButton: document.getElementById('copyLinkButton'),
	finalUrl: document.getElementById('finalUrl'),
	formsList: document.getElementById('formsList'),
	highlightText: document.getElementById('highlightText'),
	hostValue: document.getElementById('hostValue'),
	linksList: document.getElementById('linksList'),
	messages: document.getElementById('messages'),
	noteInput: document.getElementById('noteInput'),
	noteVoiceButton: document.getElementById('noteVoiceButton'),
	pageTitle: document.getElementById('pageTitle'),
	recommendedAction: document.getElementById('recommendedAction'),
	requestedUrl: document.getElementById('requestedUrl'),
	rescanButton: document.getElementById('rescanButton'),
	riskMeterFill: document.getElementById('riskMeterFill'),
	riskScoreValue: document.getElementById('riskScoreValue'),
	scanCountValue: document.getElementById('scanCountValue'),
	screenshotImage: document.getElementById('screenshotImage'),
	statusText: document.getElementById('statusText'),
	structuralSignals: document.getElementById('structuralSignals'),
	summaryText: document.getElementById('summaryText'),
	suspiciousSignals: document.getElementById('suspiciousSignals'),
	textExcerpt: document.getElementById('textExcerpt'),
	typing: document.getElementById('typing'),
	urlInput: document.getElementById('urlInput'),
	verdictBadge: document.getElementById('verdictBadge'),
	verdictValue: document.getElementById('verdictValue'),
};

bindEvents();
setupVoiceInput();
bootstrap().catch((error) => {
	console.error(error);
	setStatus('Initialization failed.');
});

async function bootstrap() {
	await refreshHealth();

	const url = new URL(window.location.href);
	const caseFromUrl = url.searchParams.get('case');
	const caseFromStorage = window.localStorage.getItem(STORAGE_KEY);
	const preferredCase = caseFromUrl || caseFromStorage;

	if (!preferredCase) {
		render();
		return;
	}

	try {
		const payload = await fetchJson(`/api/cases/${preferredCase}`);
		applyPayload({ caseId: preferredCase, ...payload });
		setStatus('Loaded an existing investigation case.');
	} catch (error) {
		console.warn('Existing case could not be loaded.', error);
		window.localStorage.removeItem(STORAGE_KEY);
		render();
	}
}

function bindEvents() {
	elements.analyzeForm.addEventListener('submit', async (event) => {
		event.preventDefault();

		const url = elements.urlInput.value.trim();
		const analystNote = elements.noteInput.value.trim();
		if (!url || state.loadingState) {
			return;
		}

		setLoading('analysis');
		setStatus('Opening a new phishing investigation.');

		try {
			const payload = await fetchJson('/api/cases', {
				body: JSON.stringify({ analystNote, url }),
				headers: { 'content-type': 'application/json' },
				method: 'POST',
			});
			applyPayload(payload);
			setStatus('Case opened and evidence captured.');
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
		setStatus('Re-scanning the current case.');

		try {
			const payload = await fetchJson(`/api/cases/${state.caseId}/rescan`, {
				body: JSON.stringify({
					analystNote: elements.noteInput.value.trim(),
					url: elements.urlInput.value.trim(),
				}),
				headers: { 'content-type': 'application/json' },
				method: 'POST',
			});
			applyPayload(payload);
			setStatus('Case re-scanned.');
		} catch (error) {
			console.error(error);
			setStatus(error.message || 'Re-scan failed.');
		} finally {
			setLoading(null);
		}
	});

	elements.copyLinkButton.addEventListener('click', async () => {
		if (!state.caseId) {
			return;
		}

		try {
			await navigator.clipboard.writeText(window.location.href);
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
		renderMessages();
		setLoading('followup');
		setStatus('Running analyst follow-up.');

		try {
			const payload = await fetchJson(`/api/cases/${state.caseId}/messages`, {
				body: JSON.stringify({ message }),
				headers: { 'content-type': 'application/json' },
				method: 'POST',
			});
			state.pendingMessage = null;
			applyPayload(payload);
			setStatus('Follow-up added to the case.');
		} catch (error) {
			console.error(error);
			state.pendingMessage = null;
			renderMessages();
			setStatus(error.message || 'Follow-up failed.');
		} finally {
			setLoading(null);
		}
	});

	elements.noteVoiceButton.addEventListener('click', () => startVoiceCapture(elements.noteInput, elements.noteVoiceButton));
	elements.chatVoiceButton.addEventListener('click', () => startVoiceCapture(elements.chatInput, elements.chatVoiceButton));

	elements.chatInput.addEventListener('keydown', (event) => {
		if (event.key === 'Enter' && !event.shiftKey) {
			event.preventDefault();
			elements.chatForm.requestSubmit();
		}
	});
}

async function refreshHealth() {
	try {
		state.health = await fetchJson('/api/health');
		renderHealth();
	} catch (error) {
		console.warn('Health request failed.', error);
	}
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
			state.activeVoiceButton.textContent = 'Stop Voice';
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
			state.activeVoiceButton.textContent = state.activeVoiceButton === elements.noteVoiceButton ? 'Voice Note' : 'Voice Question';
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

function applyPayload(payload) {
	if (payload.caseId) {
		state.caseId = payload.caseId;
	}

	if (payload.investigation) {
		state.investigation = payload.investigation;
		elements.urlInput.value = payload.investigation.targetUrl || '';
		elements.noteInput.value = payload.investigation.analystNote || '';
	}

	if (payload.mode && state.health) {
		state.health.aiMode = payload.mode.ai;
		state.health.browserMode = payload.mode.browser;
	}

	window.localStorage.setItem(STORAGE_KEY, state.caseId);
	const url = new URL(window.location.href);
	url.searchParams.set('case', state.caseId);
	window.history.replaceState({}, '', url);

	render();
}

function render() {
	renderHealth();
	renderCaseSnapshot();
	renderAssessment();
	renderEvidence();
	renderArtifacts();
	renderQuestions();
	renderMessages();
}

function renderHealth() {
	if (!state.health) {
		return;
	}

	const aiLive = state.health.aiMode === 'workers-ai';
	const browserLive = state.health.browserMode === 'browser-rendering';
	elements.aiModeBadge.textContent = aiLive ? 'Workers AI live' : 'Mock AI mode';
	elements.aiModeBadge.className = `status-pill ${aiLive ? '' : 'status-pill--warning'}`.trim();
	elements.browserModeBadge.textContent = browserLive ? 'Browser Rendering live' : 'Mock browser mode';
	elements.browserModeBadge.className = `status-pill ${browserLive ? 'status-pill--quiet' : 'status-pill--warning'}`.trim();
}

function renderCaseSnapshot() {
	const investigation = state.investigation;
	const hasCase = Boolean(investigation);
	elements.rescanButton.disabled = !hasCase || Boolean(state.loadingState);
	elements.copyLinkButton.disabled = !hasCase || Boolean(state.loadingState);
	elements.chatSendButton.disabled = !hasCase || Boolean(state.loadingState);

	if (!investigation) {
		elements.caseLabel.textContent = 'No case';
		elements.riskScoreValue.textContent = '0';
		elements.verdictValue.textContent = 'Pending';
		elements.scanCountValue.textContent = '0';
		elements.hostValue.textContent = 'N/A';
		elements.recommendedAction.textContent = 'Run a scan before making a decision.';
		elements.brandValue.textContent = 'Unknown';
		elements.confidenceValue.textContent = 'LOW';
		return;
	}

	elements.caseLabel.textContent = `Case ${investigation.caseId.slice(0, 8)}`;
	elements.riskScoreValue.textContent = String(investigation.assessment.riskScore);
	elements.verdictValue.textContent = investigation.assessment.verdict.toUpperCase();
	elements.scanCountValue.textContent = String(investigation.scanCount);
	elements.hostValue.textContent = investigation.evidence.hostname || 'N/A';
	elements.recommendedAction.textContent = investigation.assessment.recommendedAction;
	elements.brandValue.textContent = investigation.assessment.impersonatedBrand || 'Unknown';
	elements.confidenceValue.textContent = investigation.assessment.confidence.toUpperCase();
}

function renderAssessment() {
	const investigation = state.investigation;
	if (!investigation) {
		elements.summaryText.textContent = 'Run a capture to generate the executive summary, risk score, and suggested response.';
		elements.highlightText.textContent = 'No evidence collected yet.';
		elements.verdictBadge.textContent = 'Awaiting scan';
		elements.verdictBadge.className = 'verdict-pill verdict-pill--neutral';
		elements.riskMeterFill.style.width = '0%';
		return;
	}

	const { assessment } = investigation;
	elements.summaryText.textContent = assessment.executiveSummary;
	elements.highlightText.textContent = assessment.highlight;
	elements.verdictBadge.textContent = `${assessment.verdict.toUpperCase()} · ${assessment.riskScore}`;
	elements.verdictBadge.className = `verdict-pill verdict-pill--${assessment.verdict}`;
	elements.riskMeterFill.style.width = `${assessment.riskScore}%`;
}

function renderEvidence() {
	const evidence = state.investigation?.evidence;
	if (!evidence) {
		elements.captureMeta.textContent = 'No capture yet';
		elements.screenshotImage.src = '';
		elements.requestedUrl.textContent = 'N/A';
		elements.finalUrl.textContent = 'N/A';
		elements.pageTitle.textContent = 'No capture yet.';
		elements.textExcerpt.textContent = 'No rendered text yet.';
		return;
	}

	elements.captureMeta.textContent = `Captured ${formatDate(evidence.captureTimestamp)}`;
	elements.screenshotImage.src = evidence.screenshotDataUrl;
	elements.requestedUrl.textContent = evidence.requestedUrl;
	elements.finalUrl.textContent = evidence.finalUrl;
	elements.pageTitle.textContent = evidence.pageTitle;
	elements.textExcerpt.textContent = evidence.textExcerpt;
	renderList(elements.suspiciousSignals, state.investigation.assessment.suspiciousSignals);
	renderList(elements.benignSignals, state.investigation.assessment.benignSignals);
	renderList(elements.structuralSignals, evidence.structuralSignals);
	renderList(elements.brandHints, evidence.visibleBrandHints.length ? evidence.visibleBrandHints : ['No brand hints extracted.']);
}

function renderArtifacts() {
	const evidence = state.investigation?.evidence;
	elements.formsList.replaceChildren();
	elements.linksList.replaceChildren();

	if (!evidence) {
		elements.formsList.append(createEmptyText('No form evidence yet.'));
		elements.linksList.append(createEmptyText('No link evidence yet.'));
		return;
	}

	if (evidence.forms.length === 0) {
		elements.formsList.append(createEmptyText('No forms were extracted from the rendered page.'));
	} else {
		evidence.forms.forEach((form) => {
			const card = document.createElement('div');
			card.className = 'artifact-row';
			card.innerHTML = `
				<p><strong>Action:</strong> ${escapeHtml(form.action || 'None')}</p>
				<p><strong>Method:</strong> ${escapeHtml((form.method || 'get').toUpperCase())}</p>
				<p><strong>Password field:</strong> ${form.hasPassword ? 'Yes' : 'No'}</p>
				<p><strong>Inputs:</strong> ${escapeHtml(form.inputTypes.join(', ') || 'None')}</p>
			`;
			elements.formsList.append(card);
		});
	}

	if (evidence.topLinks.length === 0) {
		elements.linksList.append(createEmptyText('No visible links were extracted from the rendered page.'));
	} else {
		evidence.topLinks.forEach((link) => {
			const row = document.createElement('div');
			row.className = 'artifact-row';
			row.innerHTML = `
				<p><strong>Host:</strong> ${escapeHtml(link.hostname || 'Unknown')}</p>
				<p><strong>Text:</strong> ${escapeHtml(link.text || 'No visible text')}</p>
				<p class="artifact-row__mono">${escapeHtml(link.href)}</p>
			`;
			elements.linksList.append(row);
		});
	}
}

function renderQuestions() {
	elements.analystQuestions.replaceChildren();

	const questions = state.investigation?.assessment.analystQuestions || [];
	if (questions.length === 0) {
		elements.analystQuestions.append(createEmptyText('Suggested analyst questions will appear after the first scan.'));
		return;
	}

	questions.forEach((question) => {
		const button = document.createElement('button');
		button.className = 'follow-up__button';
		button.type = 'button';
		button.textContent = question;
		button.addEventListener('click', () => {
			elements.chatInput.value = question;
			elements.chatInput.focus();
		});
		elements.analystQuestions.append(button);
	});
}

function renderMessages() {
	elements.messages.replaceChildren();

	const messages = [...(state.investigation?.messages || [])];
	if (state.pendingMessage) {
		messages.push(state.pendingMessage);
	}

	if (messages.length === 0) {
		elements.messages.append(
			createEmptyText('Open a case to preserve analyst notes, verdict updates, and follow-up answers in one investigation thread.'),
		);
	} else {
		messages.forEach((message, index) => {
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
	elements.messages.scrollTop = elements.messages.scrollHeight;
}

function renderList(root, values) {
	root.replaceChildren();
	values.forEach((value) => {
		const item = document.createElement('li');
		item.textContent = value;
		root.append(item);
	});
}

function createEmptyText(text) {
	const paragraph = document.createElement('p');
	paragraph.className = 'empty-text';
	paragraph.textContent = text;
	return paragraph;
}

function setLoading(nextState) {
	state.loadingState = nextState;
	const isLoading = Boolean(nextState);
	elements.analyzeButton.disabled = isLoading;
	elements.rescanButton.disabled = isLoading || !state.caseId;
	elements.copyLinkButton.disabled = isLoading || !state.caseId;
	elements.chatSendButton.disabled = isLoading || !state.caseId;
	elements.typing.hidden = nextState !== 'followup';
}

function setStatus(message) {
	elements.statusText.textContent = message;
}

async function fetchJson(url, options) {
	const response = await fetch(url, options);
	const payload = await response.json().catch(() => ({}));
	if (!response.ok) {
		throw new Error(payload.error || 'Request failed.');
	}

	return payload;
}

function formatTime(timestamp) {
	return new Intl.DateTimeFormat(undefined, {
		hour: 'numeric',
		minute: '2-digit',
	}).format(new Date(timestamp));
}

function formatDate(timestamp) {
	return new Intl.DateTimeFormat(undefined, {
		dateStyle: 'medium',
		timeStyle: 'short',
	}).format(new Date(timestamp));
}

function escapeHtml(value) {
	return String(value)
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#39;');
}
