const STARTER_PROMPTS = [
	'Plan a two-week launch for a support copilot aimed at Shopify merchants with only one engineer available.',
	'Help me define an onboarding assistant for a B2B SaaS app, including audience, risks, and a thin-slice MVP.',
	'Turn a rough idea for an AI research dashboard into a scoped plan with constraints, milestones, and open questions.',
];

const STORAGE_KEY = 'signalboard-active-session';

const state = {
	followUps: [],
	highlight: 'Waiting for the first turn.',
	listening: false,
	loading: false,
	mode: 'Initializing',
	model: '',
	pendingMessage: null,
	recognition: null,
	session: null,
	sessionId: null,
};

const elements = {
	boardAudience: document.getElementById('boardAudience'),
	boardConfidence: document.getElementById('boardConfidence'),
	boardConstraints: document.getElementById('boardConstraints'),
	boardHighlight: document.getElementById('boardHighlight'),
	boardNextActions: document.getElementById('boardNextActions'),
	boardObjective: document.getElementById('boardObjective'),
	boardProject: document.getElementById('boardProject'),
	boardRisks: document.getElementById('boardRisks'),
	boardTone: document.getElementById('boardTone'),
	composerForm: document.getElementById('composerForm'),
	copyLinkButton: document.getElementById('copyLinkButton'),
	followUps: document.getElementById('followUps'),
	messageInput: document.getElementById('messageInput'),
	messages: document.getElementById('messages'),
	modeBadge: document.getElementById('modeBadge'),
	newSessionButton: document.getElementById('newSessionButton'),
	promptGrid: document.getElementById('promptGrid'),
	resetButton: document.getElementById('resetButton'),
	sendButton: document.getElementById('sendButton'),
	sessionLabel: document.getElementById('sessionLabel'),
	statusText: document.getElementById('statusText'),
	typing: document.getElementById('typing'),
	voiceButton: document.getElementById('voiceButton'),
	voiceSupportLabel: document.getElementById('voiceSupportLabel'),
};

renderPromptGrid();
setupVoiceInput();
bindEvents();
bootstrap().catch((error) => {
	console.error(error);
	setStatus('Could not initialize the app.');
});

async function bootstrap() {
	await refreshHealth();

	const url = new URL(window.location.href);
	const sessionFromUrl = url.searchParams.get('session');
	const sessionFromStorage = window.localStorage.getItem(STORAGE_KEY);
	const preferredSession = sessionFromUrl || sessionFromStorage;

	if (preferredSession) {
		try {
			const data = await fetchJson(`/api/sessions/${preferredSession}`);
			applyPayload({ ...data, sessionId: preferredSession });
			setStatus('Loaded an existing session.');
			return;
		} catch (error) {
			console.warn('Existing session could not be loaded, creating a new one.', error);
		}
	}

	await createSession('Created a fresh session.');
}

function bindEvents() {
	elements.composerForm.addEventListener('submit', async (event) => {
		event.preventDefault();
		const message = elements.messageInput.value.trim();
		if (!message || state.loading) {
			return;
		}

		elements.messageInput.value = '';
		await sendMessage(message);
	});

	elements.messageInput.addEventListener('keydown', async (event) => {
		if (event.key === 'Enter' && !event.shiftKey) {
			event.preventDefault();
			elements.composerForm.requestSubmit();
		}
	});

	elements.newSessionButton.addEventListener('click', async () => {
		if (state.loading) {
			return;
		}

		await createSession('Created a new review session.');
	});

	elements.resetButton.addEventListener('click', async () => {
		if (!state.sessionId || state.loading) {
			return;
		}

		setLoading(true);
		setStatus('Resetting the board and conversation.');

		try {
			const payload = await fetchJson(`/api/sessions/${state.sessionId}/reset`, {
				method: 'POST',
			});
			applyPayload(payload);
			setStatus('Session reset.');
		} catch (error) {
			console.error(error);
			setStatus('Reset failed. Try again.');
		} finally {
			setLoading(false);
		}
	});

	elements.copyLinkButton.addEventListener('click', async () => {
		if (!state.sessionId) {
			return;
		}

		try {
			await navigator.clipboard.writeText(window.location.href);
			setStatus('Session link copied.');
		} catch (error) {
			console.error(error);
			setStatus('Clipboard access failed.');
		}
	});

	elements.voiceButton.addEventListener('click', () => {
		if (!state.recognition) {
			setStatus('Voice input is not supported in this browser.');
			return;
		}

		if (state.listening) {
			state.recognition.stop();
			return;
		}

		state.recognition.start();
	});
}

async function createSession(message) {
	setLoading(true);
	setStatus('Creating a new session.');

	try {
		const payload = await fetchJson('/api/sessions', { method: 'POST' });
		applyPayload(payload);
		setStatus(message);
	} catch (error) {
		console.error(error);
		setStatus('Could not create a session.');
	} finally {
		setLoading(false);
	}
}

async function sendMessage(message) {
	if (!state.sessionId) {
		await createSession('Created a new session before sending.');
	}

	state.pendingMessage = {
		content: message,
		role: 'user',
		timestamp: new Date().toISOString(),
	};
	setLoading(true);
	setStatus('Updating the board.');
	renderMessages();

	try {
		const payload = await fetchJson(`/api/sessions/${state.sessionId}/messages`, {
			body: JSON.stringify({ message }),
			headers: { 'content-type': 'application/json' },
			method: 'POST',
		});
		state.pendingMessage = null;
		applyPayload(payload);
		setStatus('Board updated.');
	} catch (error) {
		console.error(error);
		state.pendingMessage = null;
		renderMessages();
		setStatus('The model response failed. Try again.');
	} finally {
		setLoading(false);
	}
}

async function refreshHealth() {
	try {
		const health = await fetchJson('/api/health');
		state.mode = health.mode;
		state.model = health.model;
		renderHeader();
	} catch (error) {
		console.warn('Health check failed.', error);
	}
}

function setupVoiceInput() {
	const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;

	if (!SpeechRecognition) {
		elements.voiceSupportLabel.textContent = 'Voice not supported here';
		elements.voiceButton.disabled = true;
		return;
	}

	const recognition = new SpeechRecognition();
	recognition.continuous = false;
	recognition.interimResults = true;
	recognition.lang = 'en-US';

	recognition.addEventListener('start', () => {
		state.listening = true;
		elements.voiceButton.textContent = 'Stop Voice';
		setStatus('Listening for voice input.');
	});

	recognition.addEventListener('result', (event) => {
		const transcript = Array.from(event.results)
			.map((result) => result[0]?.transcript || '')
			.join(' ')
			.trim();

		elements.messageInput.value = transcript;
	});

	recognition.addEventListener('end', () => {
		state.listening = false;
		elements.voiceButton.textContent = 'Voice Input';
		setStatus('Voice transcript inserted into the composer.');
	});

	recognition.addEventListener('error', (event) => {
		console.warn('Voice input error.', event.error);
		setStatus(`Voice input error: ${event.error}`);
	});

	state.recognition = recognition;
	elements.voiceSupportLabel.textContent = 'Voice ready in supported browsers';
}

function applyPayload(payload) {
	if (payload.sessionId) {
		state.sessionId = payload.sessionId;
	}

	if (payload.session) {
		state.session = payload.session;
	}

	if (payload.mode) {
		state.mode = payload.mode;
	}

	if (payload.model) {
		state.model = payload.model;
	}

	state.highlight = payload.highlight || state.highlight;
	state.followUps = Array.isArray(payload.followUps) ? payload.followUps : state.followUps;

	if (state.sessionId) {
		window.localStorage.setItem(STORAGE_KEY, state.sessionId);
		const url = new URL(window.location.href);
		url.searchParams.set('session', state.sessionId);
		window.history.replaceState({}, '', url);
	}

	render();
}

function render() {
	renderHeader();
	renderMessages();
	renderBoard();
	renderFollowUps();
}

function renderHeader() {
	const sessionSnippet = state.sessionId ? state.sessionId.slice(0, 8) : 'pending';
	elements.sessionLabel.textContent = `Session ${sessionSnippet}`;
	elements.modeBadge.textContent =
		state.mode === 'mock' ? 'Mock AI mode' : state.model ? `Workers AI live` : 'Initializing';
	elements.modeBadge.classList.toggle('status-pill--warning', state.mode === 'mock');
}

function renderMessages() {
	const fragment = document.createDocumentFragment();
	const messages = [...(state.session?.messages || [])];

	if (state.pendingMessage) {
		messages.push(state.pendingMessage);
	}

	if (messages.length === 0) {
		const empty = document.createElement('div');
		empty.className = 'empty-state';
		empty.innerHTML =
			'<p>Start with one of the prompt cards or describe an initiative. The assistant will reply and update the persistent board on the right.</p>';
		fragment.appendChild(empty);
	} else {
		messages.forEach((message, index) => {
			const article = document.createElement('article');
			article.className = `message message--${message.role}`;
			article.style.animationDelay = `${index * 45}ms`;

			const meta = document.createElement('div');
			meta.className = 'message__meta';
			meta.textContent = `${message.role === 'assistant' ? 'Signalboard' : 'You'} · ${formatTime(message.timestamp)}`;

			const body = document.createElement('p');
			body.className = 'message__body';
			body.textContent = message.content;

			article.append(meta, body);
			fragment.appendChild(article);
		});
	}

	elements.messages.replaceChildren(fragment);
	elements.typing.hidden = !state.loading;
	elements.messages.scrollTop = elements.messages.scrollHeight;
}

function renderBoard() {
	const board = state.session?.board;
	if (!board) {
		return;
	}

	elements.boardProject.textContent = board.projectName;
	elements.boardObjective.textContent = board.objective;
	elements.boardAudience.textContent = board.audience;
	elements.boardTone.textContent = board.tone;
	elements.boardConfidence.textContent = board.confidence.toUpperCase();
	elements.boardHighlight.textContent = state.highlight;

	renderList(elements.boardConstraints, board.constraints);
	renderList(elements.boardRisks, board.risks);
	renderList(elements.boardNextActions, board.nextActions);
}

function renderFollowUps() {
	elements.followUps.replaceChildren();

	if (!state.followUps.length) {
		const muted = document.createElement('p');
		muted.className = 'hint';
		muted.textContent = 'Follow-up questions will appear after the first reply.';
		elements.followUps.appendChild(muted);
		return;
	}

	state.followUps.forEach((prompt) => {
		const button = document.createElement('button');
		button.className = 'follow-up__button';
		button.textContent = prompt;
		button.type = 'button';
		button.addEventListener('click', () => {
			elements.messageInput.value = prompt;
			elements.messageInput.focus();
		});
		elements.followUps.appendChild(button);
	});
}

function renderPromptGrid() {
	STARTER_PROMPTS.forEach((prompt) => {
		const button = document.createElement('button');
		button.className = 'prompt-card';
		button.type = 'button';
		button.textContent = prompt;
		button.addEventListener('click', () => {
			elements.messageInput.value = prompt;
			elements.messageInput.focus();
		});
		elements.promptGrid.appendChild(button);
	});
}

function renderList(root, values) {
	root.replaceChildren();

	values.forEach((value) => {
		const item = document.createElement('li');
		item.textContent = value;
		root.appendChild(item);
	});
}

function setLoading(isLoading) {
	state.loading = isLoading;
	elements.sendButton.disabled = isLoading;
	elements.newSessionButton.disabled = isLoading;
	elements.resetButton.disabled = isLoading;
	elements.copyLinkButton.disabled = isLoading;
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
