// API client: same-origin session auth (Django core fronts everything —
// Caddy routes only to the authenticated core, never raw services).
// CSRF: Django's SessionAuthentication requires the X-CSRFToken header on
// POSTs; the token rides the csrftoken cookie set at login.

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function csrfToken(): string {
  const m = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(path, {
    ...init,
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      ...(init?.method && init.method !== "GET"
        ? { "X-CSRFToken": csrfToken() }
        : {}),
      ...init?.headers,
    },
  });
  if (!resp.ok) {
    let detail = resp.statusText;
    try {
      const body = await resp.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body);
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(resp.status, detail);
  }
  return resp.json();
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "POST", body: body ? JSON.stringify(body) : undefined }),
};

export interface Me {
  tenant_id: string | null;
  role: string | null;
  user: string;
  is_staff?: boolean;
}

export interface Priority {
  cve: string;
  priority_millis: number;
  scored_at: string;
  weights_version: string;
  ledger_seq: number | null;
  kev: boolean | null;
  epss_millis: number | null;
  cvss_millis: number | null;
  poc_public: boolean | null;
  active_rules: number;
}

export interface Factor {
  name: string;
  raw: string;
  subscore_millis: number;
  weight_millis: number;
  contribution_millis: number;
}

export interface Decomposition {
  cve: string;
  ledger_seq: number;
  scored_at: string;
  scored_by: string;
  decomposition: {
    cve: string;
    priority_millis: number;
    weights_version: string;
    factors: Factor[];
  };
}

export interface Rule {
  rule_id: string;
  cve: string;
  format: string;
  title: string;
  content: string;
  content_sha256: string;
  signature: string;
  status: "staged" | "active" | "rejected" | "superseded";
  fp_estimate_millis: number;
  generator_version: string;
  created_at: string;
  activated_at: string | null;
}

export interface HeatTechnique {
  technique_id: string;
  claim_count: number;
  last_seen: string;
}

export interface Summary {
  top_priorities: { cve: string; priority_millis: number; kev: boolean | null }[];
  kev_in_top: number;
  rules_by_status: Record<string, number>;
  assets: { products: number; instances: number };
  identities: { total: number; privileged: number };
  scored_cves: number;
}

// ---- onboarding wizard ----

export interface LegalDoc {
  id: string;
  version: string;
  title: string;
  required: boolean;
  body: string;
}

export interface OnboardingRecord {
  tenant_id: string;
  status: "in_progress" | "completed" | "abandoned";
  current_step: string;
  state: {
    company_name?: string;
    sector?: string;
    deployment_profile?: string;
    notes?: string;
    admin?: { email: string; name: string };
    assets_registered?: number;
    domains_registered?: number;
    idp?: { provider?: string; tenant_id?: string; client_id?: string };
  };
  legal: Record<string, {
    version: string;
    accepted_by: string;
    accepted_at_iso: string;
  }>;
  created_by: string;
  created_at: string;
  completed_at: string | null;
  name?: string;
}

export const SECTORS = [
  "finance", "healthcare", "energy", "manufacturing", "government",
  "telecom", "retail", "technology", "transport", "education", "other",
] as const;

export interface AssetRow {
  cpe: string;
  count: number;
}
