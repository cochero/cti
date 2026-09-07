import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ApiError, type Rule } from "../api";
import { ErrorNote, Loading, Panel, millis, whenAgo } from "../components";

const STATUSES = ["", "staged", "active", "rejected", "superseded"] as const;

function RuleCard({ rule, canRelease }: { rule: Rule; canRelease: boolean }) {
  const qc = useQueryClient();
  const [expanded, setExpanded] = useState(false);
  const [error, setError] = useState("");

  const transition = useMutation({
    mutationFn: (action: "activate" | "reject") =>
      api.post(`/api/v1/rules/${rule.rule_id}/transition`, { action }),
    onSuccess: () => {
      setError("");
      qc.invalidateQueries({ queryKey: ["rules"] });
    },
    onError: (e) =>
      setError(e instanceof ApiError ? e.message : "transition failed"),
  });

  return (
    <Panel>
      <div className="spread">
        <div>
          <div className="row">
            <span className={`badge ${rule.status}`}>{rule.status}</span>
            <strong>{rule.title}</strong>
            <span className="mono faint tiny">{rule.cve}</span>
            <span className="badge">{rule.format}</span>
          </div>
          <div className="tiny faint" style={{ marginTop: 6 }}>
            <span className="mono" title={`sha256 ${rule.content_sha256}`}>
              {rule.content_sha256.slice(0, 16)}…
            </span>{" "}
            · signed{" "}
            <span className="mono" title={`HMAC ${rule.signature}`}>
              {rule.signature.slice(0, 16)}…
            </span>{" "}
            · FP estimate {millis(rule.fp_estimate_millis)}% ·{" "}
            {rule.generator_version} · created {whenAgo(rule.created_at)}
            {rule.activated_at && ` · activated ${whenAgo(rule.activated_at)}`}
          </div>
        </div>
        <div className="row">
          <button className="tiny" onClick={() => setExpanded(!expanded)}>
            {expanded ? "Hide rule" : "View rule"}
          </button>
          {rule.status === "staged" && canRelease && (
            <>
              <button
                className="primary tiny"
                disabled={transition.isPending}
                onClick={() => transition.mutate("activate")}
                title="Promote to active — deployable content. Ledger-recorded."
              >
                Release
              </button>
              <button
                className="danger tiny"
                disabled={transition.isPending}
                onClick={() => transition.mutate("reject")}
                title="Reject — the rule stays on record, never deployable"
              >
                Reject
              </button>
            </>
          )}
        </div>
      </div>
      {error && (
        <div className="error-note" style={{ marginTop: 10 }}>
          {error}
        </div>
      )}
      {expanded && (
        <pre className="yaml" style={{ marginTop: 12 }}>{rule.content}</pre>
      )}
    </Panel>
  );
}

export default function Rules() {
  const [status, setStatus] = useState<string>("");
  const me = useQuery({
    queryKey: ["me"],
    queryFn: () => api.get<{ role: string | null }>("/api/v1/tenants/me"),
  });
  const rules = useQuery({
    queryKey: ["rules", status],
    queryFn: () =>
      api.get<{ rules: Rule[]; count: number }>(
        `/api/v1/rules${status ? `?status=${status}` : ""}`),
    refetchInterval: 60_000,
  });

  if (rules.isPending) return <Loading what="detection content" />;
  if (rules.isError) return <ErrorNote error={rules.error} />;

  const canRelease =
    me.data?.role === "admin" || me.data?.role === "analyst";
  const list = rules.data.rules;

  return (
    <>
      <div className="page-head">
        <h1>Detection Content</h1>
        <span className="sub">
          compiled · detonation-tested · signed — release is a human decision
          and every decision lands on the audit ledger
        </span>
      </div>

      <div className="row" style={{ marginBottom: 16 }}>
        {STATUSES.map((s) => (
          <button
            key={s || "all"}
            className="tiny"
            style={
              status === s
                ? { borderColor: "var(--accent)", color: "var(--accent)" }
                : undefined
            }
            onClick={() => setStatus(s)}
          >
            {s || "all"}
          </button>
        ))}
      </div>

      {list.length === 0 ? (
        <div className="panel empty">
          <h3>No rules in this state</h3>
          <p>
            The detection factory compiles prioritized threats into tested
            Sigma content; staged rules await review here.
          </p>
        </div>
      ) : (
        list.map((r) => (
          <RuleCard key={r.rule_id} rule={r} canRelease={!!canRelease} />
        ))
      )}

      {!canRelease && list.some((r) => r.status === "staged") && (
        <p className="tiny faint">
          Your role can review rule content but not release it — release
          requires analyst or admin.
        </p>
      )}
    </>
  );
}
