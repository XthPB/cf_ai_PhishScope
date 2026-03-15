import { toCaseListItem, type CaseListItem, type DashboardSummary, type InvestigationState } from './shared';

interface PlatformEnv {
	ANALYTICS?: AnalyticsEngineDataset;
	DB?: D1Database;
}

const CREATE_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS cases_index (
	case_id TEXT PRIMARY KEY,
	hostname TEXT NOT NULL,
	target_url TEXT NOT NULL,
	page_title TEXT NOT NULL,
	verdict TEXT NOT NULL,
	status TEXT NOT NULL,
	risk_score INTEGER NOT NULL,
	confidence TEXT NOT NULL,
	impersonated_brand TEXT NOT NULL,
	summary TEXT NOT NULL,
	tags_json TEXT NOT NULL,
	scan_count INTEGER NOT NULL,
	redirected INTEGER NOT NULL,
	external_link_count INTEGER NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	scheduled_rescan_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cases_updated_at ON cases_index(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_cases_hostname ON cases_index(hostname);
CREATE INDEX IF NOT EXISTS idx_cases_verdict ON cases_index(verdict);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases_index(status);
CREATE INDEX IF NOT EXISTS idx_cases_brand ON cases_index(impersonated_brand);
`;

type IndexedCaseRow = {
	case_id: string;
	confidence: string;
	created_at: string;
	external_link_count: number;
	hostname: string;
	impersonated_brand: string;
	page_title: string;
	redirected: number;
	risk_score: number;
	scan_count: number;
	scheduled_rescan_at: string;
	status: string;
	summary: string;
	tags_json: string;
	target_url: string;
	updated_at: string;
	verdict: string;
};

let schemaReady = false;
const memoryIndex = new Map<string, CaseListItem>();

export function resetPlatformState(): void {
	schemaReady = false;
	memoryIndex.clear();
}

export async function ensurePlatformSchema(env: PlatformEnv): Promise<void> {
	if (!env.DB || schemaReady) {
		return;
	}

	await env.DB.exec(CREATE_SCHEMA_SQL);
	schemaReady = true;
}

export async function upsertIndexedCase(env: PlatformEnv, investigation: InvestigationState): Promise<CaseListItem> {
	const item = toCaseListItem(investigation);

	if (!env.DB) {
		memoryIndex.set(item.caseId, item);
		return item;
	}

	await ensurePlatformSchema(env);
	await env.DB
		.prepare(
			`INSERT INTO cases_index (
				case_id,
				hostname,
				target_url,
				page_title,
				verdict,
				status,
				risk_score,
				confidence,
				impersonated_brand,
				summary,
				tags_json,
				scan_count,
				redirected,
				external_link_count,
				created_at,
				updated_at,
				scheduled_rescan_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(case_id) DO UPDATE SET
				hostname = excluded.hostname,
				target_url = excluded.target_url,
				page_title = excluded.page_title,
				verdict = excluded.verdict,
				status = excluded.status,
				risk_score = excluded.risk_score,
				confidence = excluded.confidence,
				impersonated_brand = excluded.impersonated_brand,
				summary = excluded.summary,
				tags_json = excluded.tags_json,
				scan_count = excluded.scan_count,
				redirected = excluded.redirected,
				external_link_count = excluded.external_link_count,
				updated_at = excluded.updated_at,
				scheduled_rescan_at = excluded.scheduled_rescan_at`,
		)
		.bind(
			item.caseId,
			item.hostname,
			item.targetUrl,
			item.pageTitle,
			item.verdict,
			item.status,
			item.riskScore,
			item.confidence,
			item.impersonatedBrand,
			item.summary,
			JSON.stringify(item.tags),
			item.scanCount,
			investigation.evidence.redirected ? 1 : 0,
			investigation.evidence.linkSummary.external,
			investigation.createdAt,
			item.updatedAt,
			investigation.scheduledRescanAt,
		)
		.run();

	return item;
}

export async function listIndexedCases(
	env: PlatformEnv,
	options: { limit?: number; search?: string; status?: string; verdict?: string } = {},
): Promise<CaseListItem[]> {
	const limit = clampLimit(options.limit);
	const search = options.search?.trim().toLowerCase() || '';
	const status = normalizeFilter(options.status);
	const verdict = normalizeFilter(options.verdict);

	if (!env.DB) {
		return [...memoryIndex.values()]
			.filter((item) => {
				if (verdict && item.verdict !== verdict) {
					return false;
				}
				if (status && item.status !== status) {
					return false;
				}
				if (!search) {
					return true;
				}
				const haystack = `${item.hostname} ${item.pageTitle} ${item.targetUrl} ${item.impersonatedBrand}`.toLowerCase();
				return haystack.includes(search);
			})
			.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
			.slice(0, limit);
	}

	await ensurePlatformSchema(env);
	let query = `
		SELECT
			case_id,
			confidence,
			created_at,
			external_link_count,
			hostname,
			impersonated_brand,
			page_title,
			redirected,
			risk_score,
			scan_count,
			scheduled_rescan_at,
			status,
			summary,
			tags_json,
			target_url,
			updated_at,
			verdict
		FROM cases_index
		WHERE 1 = 1`;
	const bindings: unknown[] = [];

	if (search) {
		const like = `%${search}%`;
		query += ` AND (
			LOWER(hostname) LIKE ?
			OR LOWER(page_title) LIKE ?
			OR LOWER(target_url) LIKE ?
			OR LOWER(impersonated_brand) LIKE ?
			OR LOWER(summary) LIKE ?
		)`;
		bindings.push(like, like, like, like, like);
	}

	if (verdict) {
		query += ` AND verdict = ?`;
		bindings.push(verdict);
	}

	if (status) {
		query += ` AND status = ?`;
		bindings.push(status);
	}

	query += ` ORDER BY updated_at DESC LIMIT ?`;
	bindings.push(limit);

	const result = await env.DB.prepare(query).bind(...bindings).all<IndexedCaseRow>();
	return (result.results || []).map(rowToCaseListItem);
}

export async function getDashboardSummary(env: PlatformEnv): Promise<DashboardSummary> {
	if (!env.DB) {
		const items = [...memoryIndex.values()].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
		return summarizeCases(items);
	}

	await ensurePlatformSchema(env);
	const aggregate = await env.DB
		.prepare(
			`SELECT
				COUNT(*) AS total_cases,
				COALESCE(AVG(risk_score), 0) AS average_risk_score,
				SUM(CASE WHEN status = 'monitor' THEN 1 ELSE 0 END) AS monitor_cases,
				SUM(CASE WHEN status = 'needs_review' THEN 1 ELSE 0 END) AS needs_review_cases,
				SUM(CASE WHEN status = 'escalated' THEN 1 ELSE 0 END) AS escalated_cases,
				SUM(CASE WHEN status = 'triage' THEN 1 ELSE 0 END) AS triage_cases
			FROM cases_index`,
		)
		.first<Record<string, number>>();

	const recent = await listIndexedCases(env, { limit: 6 });
	return {
		averageRiskScore: Math.round(Number(aggregate?.average_risk_score || 0)),
		escalatedCases: Number(aggregate?.escalated_cases || 0),
		monitorCases: Number(aggregate?.monitor_cases || 0),
		needsReviewCases: Number(aggregate?.needs_review_cases || 0),
		recentCases: recent,
		totalCases: Number(aggregate?.total_cases || 0),
		triageCases: Number(aggregate?.triage_cases || 0),
	};
}

export async function findRelatedCases(env: PlatformEnv, investigation: InvestigationState, limit = 6): Promise<CaseListItem[]> {
	const item = toCaseListItem(investigation);
	if (!env.DB) {
		return [...memoryIndex.values()]
			.filter(
				(candidate) =>
					candidate.caseId !== item.caseId &&
					(candidate.hostname === item.hostname ||
						(item.impersonatedBrand !== 'Unknown' && candidate.impersonatedBrand === item.impersonatedBrand)),
			)
			.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
			.slice(0, limit);
	}

	await ensurePlatformSchema(env);
	const bindings: unknown[] = [item.caseId, item.hostname];
	let query = `
		SELECT
			case_id,
			confidence,
			created_at,
			external_link_count,
			hostname,
			impersonated_brand,
			page_title,
			redirected,
			risk_score,
			scan_count,
			scheduled_rescan_at,
			status,
			summary,
			tags_json,
			target_url,
			updated_at,
			verdict
		FROM cases_index
		WHERE case_id != ?
			AND (
				hostname = ?`;

	if (item.impersonatedBrand !== 'Unknown') {
		query += ` OR impersonated_brand = ?`;
		bindings.push(item.impersonatedBrand);
	}

	query += `)
		ORDER BY CASE WHEN hostname = ? THEN 0 ELSE 1 END, updated_at DESC
		LIMIT ?`;
	bindings.push(item.hostname, clampLimit(limit, 1, 12));

	const result = await env.DB.prepare(query).bind(...bindings).all<IndexedCaseRow>();
	return (result.results || []).map(rowToCaseListItem);
}

export function trackMetric(
	env: PlatformEnv,
	eventType: string,
	investigation?: InvestigationState,
	extra: Record<string, string | number | boolean | null> = {},
): void {
	if (!env.ANALYTICS) {
		return;
	}

	const item = investigation ? toCaseListItem(investigation) : null;
	env.ANALYTICS.writeDataPoint({
		blobs: [
			eventType,
			item?.caseId || null,
			item?.hostname || null,
			item?.verdict || null,
			JSON.stringify(extra).slice(0, 240),
		],
		doubles: [item?.riskScore || 0, item?.scanCount || 0],
		indexes: [item?.status || null, item?.impersonatedBrand || null],
	});
}

function rowToCaseListItem(row: IndexedCaseRow): CaseListItem {
	return {
		caseId: row.case_id,
		confidence: normalizeConfidence(row.confidence),
		hostname: row.hostname,
		impersonatedBrand: row.impersonated_brand,
		pageTitle: row.page_title,
		riskScore: Number(row.risk_score || 0),
		scanCount: Number(row.scan_count || 0),
		status: normalizeStatus(row.status),
		summary: row.summary,
		tags: parseTags(row.tags_json),
		targetUrl: row.target_url,
		updatedAt: row.updated_at,
		verdict: normalizeVerdict(row.verdict),
	};
}

function summarizeCases(items: CaseListItem[]): DashboardSummary {
	const totalCases = items.length;
	const averageRiskScore =
		totalCases === 0 ? 0 : Math.round(items.reduce((sum, item) => sum + item.riskScore, 0) / totalCases);

	return {
		averageRiskScore,
		escalatedCases: items.filter((item) => item.status === 'escalated').length,
		monitorCases: items.filter((item) => item.status === 'monitor').length,
		needsReviewCases: items.filter((item) => item.status === 'needs_review').length,
		recentCases: items.slice(0, 6),
		totalCases,
		triageCases: items.filter((item) => item.status === 'triage').length,
	};
}

function clampLimit(limit: number | undefined, min = 1, max = 40): number {
	const numeric = Number(limit || 24);
	if (!Number.isFinite(numeric)) {
		return 24;
	}

	return Math.max(min, Math.min(max, Math.round(numeric)));
}

function normalizeFilter(value: string | undefined): string {
	const candidate = (value || '').trim().toLowerCase();
	return candidate && candidate !== 'all' ? candidate : '';
}

function parseTags(value: string): string[] {
	try {
		const parsed = JSON.parse(value);
		return Array.isArray(parsed) ? parsed.filter((entry) => typeof entry === 'string').slice(0, 8) : [];
	} catch {
		return [];
	}
}

function normalizeConfidence(value: string): CaseListItem['confidence'] {
	return value === 'high' || value === 'medium' || value === 'low' ? value : 'low';
}

function normalizeStatus(value: string): CaseListItem['status'] {
	return value === 'escalated' || value === 'needs_review' || value === 'monitor' || value === 'triage' ? value : 'triage';
}

function normalizeVerdict(value: string): CaseListItem['verdict'] {
	return value === 'malicious' || value === 'suspicious' || value === 'benign' || value === 'inconclusive'
		? value
		: 'inconclusive';
}
