import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { api, type Priority } from "../api";
import { ErrorNote, Loading, ScoreCell, millis, whenAgo } from "../components";

export default function Priorities() {
  const navigate = useNavigate();
  const q = useQuery({
    queryKey: ["priorities"],
    queryFn: () => api.get<{ priorities: Priority[]; count: number }>(
      "/api/v1/priorities?limit=200"),
    refetchInterval: 60_000,
  });

  if (q.isPending) return <Loading what="priority queue" />;
  if (q.isError) return <ErrorNote error={q.error} />;

  const rows = q.data.priorities;

  return (
    <>
      <div className="page-head">
        <h1>Priority Queue</h1>
        <span className="sub">
          {q.data.count} scored threats · deterministic engine · every score
          reproducible from its ledger entry
        </span>
      </div>
      <section className="panel">
        {rows.length === 0 ? (
          <div className="empty">
            <h3>No scored threats yet</h3>
            <p>
              Scores appear once the intelligence pipeline has enriched
              exploit intel and scoring has run for this tenant.
            </p>
          </div>
        ) : (
          <table className="grid">
            <thead>
              <tr>
                <th>Priority</th>
                <th>CVE</th>
                <th>Signals</th>
                <th className="num">EPSS</th>
                <th className="num">CVSS</th>
                <th className="num">Rules</th>
                <th>Scored</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr
                  key={r.cve}
                  className="clickable"
                  onClick={() => navigate(`/priorities/${encodeURIComponent(r.cve)}`)}
                >
                  <td style={{ width: 170 }}><ScoreCell millis={r.priority_millis} /></td>
                  <td className="mono">{r.cve}</td>
                  <td>
                    <span style={{ display: "flex", gap: 6 }}>
                      {r.kev && <span className="badge kev" title="CISA Known Exploited Vulnerability">KEV</span>}
                      {r.poc_public && <span className="badge poc" title="Public proof-of-concept">PoC</span>}
                    </span>
                  </td>
                  <td className="num mono">{millis(r.epss_millis)}</td>
                  <td className="num mono">{r.cvss_millis ? millis(r.cvss_millis) : "—"}</td>
                  <td className="num mono">{r.active_rules > 0 ? `${r.active_rules} active` : "—"}</td>
                  <td className="faint tiny" title={r.scored_at}>{whenAgo(r.scored_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </>
  );
}
