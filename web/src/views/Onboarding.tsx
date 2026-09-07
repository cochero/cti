import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import {
  api, ApiError, type AssetRow, type LegalDoc, type OnboardingRecord,
  SECTORS,
} from "../api";
import { ErrorNote, Loading, Panel } from "../components";

const STEPS = [
  { key: "basics", n: 1, label: "Company", hint: "who is being onboarded" },
  { key: "legal", n: 2, label: "Legal", hint: "DPA · terms · data governance" },
  { key: "admin", n: 3, label: "Administrator", hint: "first admin account" },
  { key: "environment", n: 4, label: "Environment", hint: "stack · domains · IdP" },
  { key: "review", n: 5, label: "Activate", hint: "review & go live" },
] as const;

const PROFILES = [
  {
    id: "saas", name: "Multi-Tenant SaaS",
    desc: "Hosted by TRUVO. RLS-isolated tenant, per-tenant keys.",
  },
  {
    id: "vpc", name: "Single-Tenant VPC",
    desc: "Same charts in the customer's cloud. Data never leaves.",
  },
  {
    id: "airgap", name: "Air-Gapped On-Prem",
    desc: "k3s rack, signed offline bundles, zero vendor telemetry.",
  },
] as const;

const STEP_ORDER: Record<string, number> = {
  basics: 1, legal: 2, admin: 3, environment: 4, review: 5,
};

function StepRail({ current }: { current: number }) {
  return (
    <div className="wizard-rail">
      {STEPS.map((s, i) => {
        const state = s.n < current ? "done" : s.n === current ? "now" : "todo";
        return (
          <div className={"wizard-step " + state} key={s.key}>
            <div className="wizard-dot">{state === "done" ? "✓" : s.n}</div>
            <div className="wizard-step-text">
              <div className="wizard-step-label">{s.label}</div>
              <div className="wizard-step-hint">{s.hint}</div>
            </div>
            {i < STEPS.length - 1 && <div className="wizard-line" />}
          </div>
        );
      })}
    </div>
  );
}

export default function Onboarding() {
  const qc = useQueryClient();
  const [tenantId, setTenantId] = useState<string | null>(null);
  const [step, setStep] = useState(1);
  const [error, setError] = useState("");
  const [created, setCreated] = useState<{ password?: string; done?: boolean }>({});

  const records = useQuery({
    queryKey: ["onboarding"],
    queryFn: () => api.get<{ records: OnboardingRecord[] }>("/api/v1/onboarding"),
  });
  const docs = useQuery({
    queryKey: ["legal-docs"],
    queryFn: () => api.get<{ docs: LegalDoc[] }>("/api/v1/onboarding/legal-docs"),
    enabled: !!tenantId && step === 2,
  });

  const clear = () => {
    setTenantId(null);
    setStep(1);
    setError("");
    setCreated({});
    qc.invalidateQueries({ queryKey: ["onboarding"] });
  };

  const onError = (e: unknown) =>
    setError(e instanceof ApiError ? e.message : String(e));

  // ---- step 1: company ----
  const [name, setName] = useState("");
  const [sector, setSector] = useState<string>("finance");
  const [profile, setProfile] = useState<string>("saas");
  const [notes, setNotes] = useState("");
  const start = useMutation({
    mutationFn: () => api.post<{ tenant_id: string }>("/api/v1/onboarding", {
      company_name: name, sector, deployment_profile: profile, notes,
    }),
    onSuccess: (r) => {
      setError("");
      setTenantId(r.tenant_id);
      setStep(2);
    },
    onError: onError,
  });

  // ---- step 2: legal ----
  const [accepted, setAccepted] = useState<Record<string, boolean>>({});
  const [accName, setAccName] = useState("");
  const [accEmail, setAccEmail] = useState("");
  const [accRole, setAccRole] = useState("");
  const legal = useMutation({
    mutationFn: () => api.post(`/api/v1/onboarding/${tenantId}/legal`, {
      accepted, acceptor_name: accName, acceptor_email: accEmail,
      acceptor_role: accRole,
    }),
    onSuccess: () => { setError(""); setStep(3); },
    onError: onError,
  });

  // ---- step 3: admin ----
  const [adminEmail, setAdminEmail] = useState("");
  const [adminName, setAdminName] = useState("");
  const admin = useMutation({
    mutationFn: () => api.post<{ initial_password: string }>(
      `/api/v1/onboarding/${tenantId}/admin`,
      { email: adminEmail, name: adminName }),
    onSuccess: (r) => {
      setError("");
      // stay on this step: the one-time password must be SEEN (and copied)
      // before the operator continues — advancing past it loses it forever
      setCreated((c) => ({ ...c, password: r.initial_password }));
    },
    onError: onError,
  });

  // ---- step 4: environment ----
  const [assets, setAssets] = useState<AssetRow[]>([]);
  const [cpe, setCpe] = useState("");
  const [count, setCount] = useState("1");
  const [domains, setDomains] = useState<string[]>([]);
  const [domain, setDomain] = useState("");
  const [idpProvider, setIdpProvider] = useState("");
  const [idpTenant, setIdpTenant] = useState("");
  const [idpClient, setIdpClient] = useState("");
  const environment = useMutation({
    mutationFn: () => api.post(`/api/v1/onboarding/${tenantId}/environment`, {
      sector,
      assets,
      watch_domains: domains,
      idp: idpProvider
        ? { provider: idpProvider, tenant_id: idpTenant, client_id: idpClient }
        : {},
    }),
    onSuccess: () => { setError(""); setStep(5); },
    onError: onError,
  });

  // ---- step 5: activate ----
  const complete = useMutation({
    mutationFn: () => api.post(`/api/v1/onboarding/${tenantId}/complete`, {}),
    onSuccess: () => {
      setError("");
      setCreated((c) => ({ ...c, done: true }));
      qc.invalidateQueries({ queryKey: ["onboarding"] });
    },
    onError: onError,
  });

  if (records.isPending) return <Loading what="onboarding records" />;
  if (records.isError) return <ErrorNote error={records.error} />;

  const inProgress = records.data.records.filter(
    (r) => r.status === "in_progress");
  const completedList = records.data.records.filter(
    (r) => r.status === "completed");

  // ---------------- list view (no active wizard) ----------------
  if (!tenantId && !created.done) {
    return (
      <>
        <div className="page-head">
          <h1>Tenant Onboarding</h1>
          <span className="sub">
            the full process — company, legal, administrator, environment —
            every step ledger-recorded
          </span>
        </div>
        <Panel title="Start a new onboarding">
          <div className="ob-start-form">
            <div className="ob-field">
              <label>Company name</label>
              <input value={name} onChange={(e) => setName(e.target.value)}
                     placeholder="Northwind Capital" />
            </div>
            <div className="ob-field">
              <label>Sector — drives sector-affinity scoring</label>
              <select value={sector} onChange={(e) => setSector(e.target.value)}>
                {SECTORS.map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </div>
            <div className="ob-field">
              <label>Notes (internal)</label>
              <input value={notes} onChange={(e) => setNotes(e.target.value)}
                     placeholder="design partner, procurement ref…" />
            </div>
          </div>
          <div className="ob-field">
            <label>Deployment profile — how this tenant is served</label>
            <div className="profile-cards">
              {PROFILES.map((p) => (
                <div key={p.id}
                     className={"profile-card" + (profile === p.id ? " sel" : "")}
                     onClick={() => setProfile(p.id)}>
                  <div className="profile-name">{p.name}</div>
                  <div className="profile-desc">{p.desc}</div>
                </div>
              ))}
            </div>
          </div>
          <button className="primary" disabled={name.trim().length < 2}
                  onClick={() => start.mutate()}>
            Begin onboarding →
          </button>
          {error && <div className="error-note" style={{ marginTop: 12 }}>{error}</div>}
        </Panel>

        {inProgress.length > 0 && (
          <Panel title="In progress">
            <table className="grid">
              <thead><tr><th>Company</th><th>Step</th><th>Started</th><th></th></tr></thead>
              <tbody>
                {inProgress.map((r) => (
                  <tr key={r.tenant_id}>
                    <td>{r.state.company_name}</td>
                    <td><span className="badge staged">{r.current_step}</span></td>
                    <td className="faint tiny">{r.created_at?.slice(0, 10)}</td>
                    <td>
                      <button className="tiny"
                              onClick={() => {
                                setTenantId(r.tenant_id);
                                setStep(STEP_ORDER[r.current_step] ?? 2);
                                if (r.state.company_name) setName(r.state.company_name);
                                if (r.state.sector) setSector(r.state.sector);
                              }}>
                        Resume
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Panel>
        )}

        {completedList.length > 0 && (
          <Panel title="Completed">
            <table className="grid">
              <thead><tr><th>Company</th><th>Activated</th><th>Legal accepted by</th></tr></thead>
              <tbody>
                {completedList.map((r) => (
                  <tr key={r.tenant_id}>
                    <td>{r.state.company_name}</td>
                    <td className="faint tiny">{r.completed_at?.slice(0, 10)}</td>
                    <td className="mono tiny">
                      {Object.values(r.legal)[0]?.accepted_by || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Panel>
        )}
      </>
    );
  }

  // ---------------- success screen ----------------
  if (created.done) {
    return (
      <div className="login-wrap">
        <div className="panel login-card" style={{ width: 480 }}>
          <h1 style={{ textAlign: "center" }}>✓ Tenant active</h1>
          <p className="muted" style={{ textAlign: "center" }}>
            <strong>{name}</strong> is live. The activation — including the
            legal document versions and the administrator identity — is on
            the tenant's hash-chained ledger.
          </p>
          <div className="ob-next-steps">
            {created.password ? (
              <>
                <div>1 · Share the one-time credentials with the administrator</div>
                <div className="row">
                  <code className="cred-value">{created.password}</code>
                  <button className="tiny"
                          onClick={() => navigator.clipboard?.writeText(created.password!)}>
                    copy
                  </button>
                </div>
              </>
            ) : (
              <div>1 · The administrator's one-time password was shown at the
                   administrator step — it is not stored anywhere</div>
            )}
            <div>2 · Analysts sign in at this domain and see the priority queue</div>
            <div>3 · Scoring picks up the registered stack on the next run</div>
          </div>
          <button className="primary" style={{ width: "100%" }} onClick={clear}>
            Onboard another tenant
          </button>
        </div>
      </div>
    );
  }

  // ---------------- wizard ----------------
  const docList = docs.data?.docs ?? [];
  const allAccepted = docList.length > 0 &&
    docList.every((d) => !d.required || accepted[d.id]);

  return (
    <>
      <div className="page-head">
        <h1>Onboarding — {name}</h1>
        <span className="sub">tenant {tenantId?.slice(0, 8)} · every step lands on the audit ledger</span>
      </div>
      {error && <ErrorNote error={error} />}

      <div className="wizard-grid">
        <StepRail current={step} />
        <div className="wizard-body">
          {step === 2 && (
            <Panel title="Legal — versioned acceptances, recorded on the tenant ledger">
              {docs.isPending && <Loading what="legal documents" />}
              {docList.map((d) => (
                <div className="legal-doc" key={d.id}>
                  <div className="spread">
                    <div className="row">
                      <strong>{d.title}</strong>
                      <span className="badge">v{d.version}</span>
                      {d.required && <span className="badge kev">required</span>}
                    </div>
                    <label className="row tiny">
                      <input type="checkbox"
                             checked={!!accepted[d.id]}
                             onChange={(e) =>
                               setAccepted({ ...accepted, [d.id]: e.target.checked })} />
                      accepted on behalf of the customer
                    </label>
                  </div>
                  <pre className="yaml">{d.body}</pre>
                </div>
              ))}
              <div className="ob-two-col">
                <div className="ob-field">
                  <label>Acceptor name (customer)</label>
                  <input value={accName} onChange={(e) => setAccName(e.target.value)}
                         placeholder="Jane Doe" />
                </div>
                <div className="ob-field">
                  <label>Accepto&shy;r email</label>
                  <input value={accEmail} onChange={(e) => setAccEmail(e.target.value)}
                         placeholder="jane@customer.com" />
                </div>
                <div className="ob-field">
                  <label>Role / title</label>
                  <input value={accRole} onChange={(e) => setAccRole(e.target.value)}
                         placeholder="CISO" />
                </div>
              </div>
              <div className="row">
                <button className="primary"
                        disabled={!allAccepted || !accName || !accEmail.includes("@")}
                        onClick={() => legal.mutate()}>
                  Record acceptances →
                </button>
                {!allAccepted && (
                  <span className="tiny faint">
                    every required document must be accepted — all or nothing
                  </span>
                )}
              </div>
            </Panel>
          )}

          {step === 3 && (
            <Panel title="First administrator">
              <div className="ob-two-col">
                <div className="ob-field">
                  <label>Admin email</label>
                  <input value={adminEmail}
                         onChange={(e) => setAdminEmail(e.target.value)}
                         placeholder="admin@customer.com" />
                </div>
                <div className="ob-field">
                  <label>Full name</label>
                  <input value={adminName} onChange={(e) => setAdminName(e.target.value)}
                         placeholder="Jane Doe" />
                </div>
              </div>
              <button className="primary"
                      disabled={admin.isPending || !adminEmail.includes("@") || !adminName}
                      onClick={() => admin.mutate()}>
                Create administrator →
              </button>
              {created.password && (
                <div className="cred-box">
                  <div className="stat-label">One-time initial password — shown once, never stored</div>
                  <div className="row" style={{ marginTop: 8 }}>
                    <code className="cred-value">{created.password}</code>
                    <button className="tiny"
                            onClick={() => navigator.clipboard?.writeText(created.password!)}>
                      copy
                    </button>
                  </div>
                  <p className="tiny faint" style={{ marginBottom: 0 }}>
                    The administrator should change it at first sign-in.
                  </p>
                </div>
              )}
              {created.password && (
                <button className="primary" style={{ marginTop: 14 }}
                        onClick={() => setStep(4)}>
                  Continue to environment →
                </button>
              )}
            </Panel>
          )}

          {step === 4 && (
            <Panel title="Environment — what scoring will be personalized to">
              <div className="ob-field">
                <label>Tech stack (CPE) — stack-overlap is the heaviest scoring factor</label>
                {assets.map((a, i) => (
                  <div className="chip-row" key={i}>
                    <code className="mono">{a.cpe}</code>
                    <span className="faint tiny">× {a.count}</span>
                    <button className="tiny danger"
                            onClick={() => setAssets(assets.filter((_, j) => j !== i))}>
                      remove
                    </button>
                  </div>
                ))}
                <div className="row">
                  <input style={{ flex: 1 }} value={cpe}
                         onChange={(e) => setCpe(e.target.value)}
                         placeholder="cpe:2.3:a:apache:log4j" />
                  <input style={{ width: 70 }} value={count}
                         onChange={(e) => setCount(e.target.value)} />
                  <button className="tiny"
                          disabled={!cpe.startsWith("cpe:2.3:")}
                          onClick={() => {
                            setAssets([...assets, { cpe: cpe.trim(), count: Math.max(1, parseInt(count) || 1) }]);
                            setCpe(""); setCount("1");
                          }}>add</button>
                </div>
                <div className="row tiny" style={{ marginTop: 6 }}>
                  <span className="faint">quick add:</span>
                  {["cpe:2.3:a:apache:log4j", "cpe:2.3:o:fortinet:fortios",
                    "cpe:2.3:a:atlassian:confluence_data_center",
                    "cpe:2.3:a:ivanti:connect_secure"].map((q) => (
                    <button key={q} className="tiny"
                            onClick={() => !assets.some((a) => a.cpe === q) &&
                              setAssets([...assets, { cpe: q, count: 5 }])}>
                      + {q.split(":")[3]}:{q.split(":")[4]}
                    </button>
                  ))}
                </div>
              </div>

              <div className="ob-field">
                <label>Credential-leak watch domains — monitoring is limited to these, by policy</label>
                {domains.map((d) => (
                  <div className="chip-row" key={d}>
                    <code className="mono">{d}</code>
                    <button className="tiny danger"
                            onClick={() => setDomains(domains.filter((x) => x !== d))}>
                      remove
                    </button>
                  </div>
                ))}
                <div className="row">
                  <input style={{ flex: 1 }} value={domain}
                         onChange={(e) => setDomain(e.target.value)}
                         placeholder="customer.com"
                         onKeyDown={(e) => {
                           if (e.key === "Enter" && domain.includes(".")) {
                             setDomains([...domains, domain.trim().toLowerCase()]);
                             setDomain("");
                           }
                         }} />
                  <button className="tiny"
                          disabled={!domain.includes(".")}
                          onClick={() => {
                            setDomains([...domains, domain.trim().toLowerCase()]);
                            setDomain("");
                          }}>add</button>
                </div>
              </div>

              <div className="ob-field">
                <label>Identity provider (read-only sync for blast radius) — can be deferred</label>
                <div className="row">
                  {[["", "defer"], ["entra", "Microsoft Entra ID"], ["okta", "Okta"]].map(
                    ([v, l]) => (
                      <button key={v} className="tiny"
                              style={idpProvider === v
                                ? { borderColor: "var(--accent)", color: "var(--accent)" }
                                : undefined}
                              onClick={() => setIdpProvider(v)}>{l}</button>
                    ))}
                </div>
                {idpProvider && (
                  <div className="ob-two-col" style={{ marginTop: 10 }}>
                    <div className="ob-field">
                      <label>IdP tenant id</label>
                      <input value={idpTenant} onChange={(e) => setIdpTenant(e.target.value)}
                             placeholder="contoso" />
                    </div>
                    <div className="ob-field">
                      <label>App client id</label>
                      <input value={idpClient} onChange={(e) => setIdpClient(e.target.value)}
                             placeholder="00000000-…" />
                    </div>
                  </div>
                )}
                <p className="tiny faint">
                  Read-only credentials are provisioned through the secrets
                  vault during integration — never through this form.
                </p>
              </div>

              <button className="primary" disabled={environment.isPending}
                      onClick={() => environment.mutate()}>
                Register environment →
              </button>
            </Panel>
          )}

          {step === 5 && (
            <Panel title="Review & activate">
              <table className="grid">
                <tbody>
                  <tr><th>Company</th><td>{name}</td></tr>
                  <tr><th>Sector</th><td>{sector}</td></tr>
                  <tr><th>Profile</th><td>{PROFILES.find((p) => p.id === profile)?.name}</td></tr>
                  <tr><th>Legal</th>
                    <td>{Object.entries(
                      (records.data.records.find((r) => r.tenant_id === tenantId)?.legal) ?? {})
                      .map(([id, v]) => `${id} v${v.version}`).join(" · ")}</td></tr>
                  <tr><th>Administrator</th><td className="mono">{
                    adminEmail ||
                    records.data.records.find((r) => r.tenant_id === tenantId)
                      ?.state.admin?.email || "—"
                  }</td></tr>
                  <tr><th>Stack</th><td>{assets.length} products · {assets.reduce((s, a) => s + a.count, 0)} instances</td></tr>
                  <tr><th>Watch domains</th><td className="mono">{domains.join(", ") || "—"}</td></tr>
                  <tr><th>Identity</th><td>{idpProvider || "deferred"}</td></tr>
                </tbody>
              </table>
              <p className="tiny faint">
                Activation flips the tenant to active and writes the summary —
                including legal document versions — to the tenant's
                hash-chained ledger. The admin signs in and sees an honest
                empty queue until the first scoring run.
              </p>
              <button className="primary" disabled={complete.isPending}
                      onClick={() => complete.mutate()}>
                {complete.isPending ? "Activating…" : "Activate tenant"}
              </button>
            </Panel>
          )}
        </div>
      </div>
    </>
  );
}
