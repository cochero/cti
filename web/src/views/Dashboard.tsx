import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, type Summary } from "../api";
import { ErrorNote, Loading, Panel, ScoreCell } from "../components";

export default function Dashboard() {
  const q = useQuery({
    queryKey: ["summary"],
    queryFn: () => api.get<Summary>("/api/v1/dashboard/summary"),
    refetchInterval: 60_000,
  });

  if (q.isPending) return <Loading what="posture summary" />;
  if (q.isError) return <ErrorNote error={q.error} />;

  const s = q.data;
  const privPct =
    s.identities.total > 0
      ? Math.round((s.identities.privileged / s.identities.total) * 100)
      : 0;

  return (
    <>
      <div className="page-head">
        <h1>Security Posture</h1>
        <span className="sub">
          live aggregates over this tenant's scored threats, detection
          coverage, and identity exposure
        </span>
      </div>

      <div className="card-grid">
        <div className="panel">
          <div className="stat-label">Scored threats</div>
          <div className="stat-value">{s.scored_cves}</div>
          <div className="stat-sub">distinct CVEs prioritized</div>
        </div>
        <div className="panel">
          <div className="stat-label">KEV in top 5</div>
          <div className={"stat-value " + (s.kev_in_top > 0 ? "sev-critical" : "")}>
            {s.kev_in_top}
          </div>
          <div className="stat-sub">actively exploited, ranked highest</div>
        </div>
        <div className="panel">
          <div className="stat-label">Detection coverage</div>
          <div className="stat-value" style={{ color: "var(--active)" }}>
            {s.rules_by_status.active}
            <small> / {Object.values(s.rules_by_status).reduce((a, b) => a + b, 0)}</small>
          </div>
          <div className="stat-sub">
            {s.rules_by_status.staged} staged awaiting review
          </div>
        </div>
        <div className="panel">
          <div className="stat-label">Identity exposure</div>
          <div className={"stat-value " + (privPct > 20 ? "sev-high" : "")}>
            {privPct}%
          </div>
          <div className="stat-sub">
            {s.identities.privileged} privileged of {s.identities.total} identities
          </div>
        </div>
        <div className="panel">
          <div className="stat-label">Attack surface</div>
          <div className="stat-value">
            {s.assets.products}
            <small> products</small>
          </div>
          <div className="stat-sub">{s.assets.instances} instances tracked</div>
        </div>
      </div>

      <Panel
        title="Top priorities"
        aside={<Link to="/priorities" className="tiny">full queue →</Link>}
      >
        {s.top_priorities.length === 0 ? (
          <p className="muted" style={{ margin: 0 }}>
            Nothing scored yet for this tenant.
          </p>
        ) : (
          <table className="grid">
            <thead>
              <tr>
                <th>Priority</th>
                <th>CVE</th>
                <th>Signals</th>
              </tr>
            </thead>
            <tbody>
              {s.top_priorities.map((t) => (
                <tr key={t.cve}>
                  <td style={{ width: 170 }}>
                    <ScoreCell millis={t.priority_millis} />
                  </td>
                  <td className="mono">
                    <Link to={`/priorities/${encodeURIComponent(t.cve)}`}>
                      {t.cve}
                    </Link>
                  </td>
                  <td>{t.kev && <span className="badge kev">KEV</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel title="Detection lifecycle">
        <div className="row" style={{ gap: 22 }}>
          {(
            [
              ["staged", "awaiting review"],
              ["active", "released"],
              ["rejected", "declined"],
              ["superseded", "retired"],
            ] as const
          ).map(([k, label]) => (
            <div key={k}>
              <div className="stat-label">{label}</div>
              <div className="stat-value" style={{ fontSize: 22 }}>
                <span className={`badge ${k}`} style={{ fontSize: 14, padding: "3px 10px" }}>
                  {s.rules_by_status[k]}
                </span>
              </div>
            </div>
          ))}
          <div className="tiny faint" style={{ marginLeft: "auto", maxWidth: 320 }}>
            Every transition is a ledger entry — who released what, when,
            against which content hash. Audit-grade by construction.
          </div>
        </div>
      </Panel>
    </>
  );
}
