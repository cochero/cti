import { useQuery } from "@tanstack/react-query";
import { api, type HeatTechnique } from "../api";
import { ErrorNote, Loading, whenAgo } from "../components";
import matrix from "../data/attack-matrix.json";

interface MatrixData {
  tactics: { id: string; shortname: string; name: string }[];
  techniques: { id: string; name: string; phases: string[] }[];
}

const data = matrix as MatrixData;

function heatColor(count: number, max: number): string | null {
  if (count <= 0) return null;
  const t = Math.min(1, Math.sqrt(count / Math.max(1, max))); // sqrt: long tail
  // accent ramp: deep teal -> cyan
  const alpha = 0.12 + 0.75 * t;
  return `rgba(56, 189, 248, ${alpha.toFixed(3)})`;
}

export default function Heatmap() {
  const q = useQuery({
    queryKey: ["heatmap"],
    queryFn: () => api.get<{ techniques: HeatTechnique[] }>(
      "/api/v1/attack-heatmap"),
    refetchInterval: 120_000,
  });

  if (q.isPending) return <Loading what="ATT&CK activity" />;
  if (q.isError) return <ErrorNote error={q.error} />;

  const counts = new Map(
    q.data.techniques.map((t) => [t.technique_id, t] as const),
  );
  const max = Math.max(1, ...q.data.techniques.map((t) => t.claim_count));

  return (
    <>
      <div className="page-head">
        <h1>ATT&CK Heatmap</h1>
        <span className="sub">
          technique activity from corroborated pipeline claims · last 90
          days · {q.data.techniques.length} techniques observed
        </span>
      </div>
      <div className="panel heatmap-scroll">
        <div
          className="heatmap"
          style={{ gridTemplateColumns: `repeat(${data.tactics.length}, 1fr)` }}
        >
          {data.tactics.map((t) => (
            <div className="hm-tactic" key={t.id} title={t.name}>
              {t.shortname.replace(/-/g, " ")}
            </div>
          ))}
          {data.tactics.map((tactic) => {
            const techs = data.techniques.filter((tech) =>
              tech.phases.includes(tactic.shortname),
            );
            return (
              <div
                key={tactic.id}
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: 3,
                }}
              >
                {techs.map((tech) => {
                  const hit = counts.get(tech.id);
                  const bg = heatColor(hit?.claim_count ?? 0, max);
                  return (
                    <div
                      key={tech.id}
                      className={"hm-cell" + (hit ? " has-activity" : "")}
                      style={bg ? { background: bg } : undefined}
                      title={
                        hit
                          ? `${tech.id} ${tech.name}\n${hit.claim_count} claims · last ${whenAgo(hit.last_seen)}`
                          : `${tech.id} ${tech.name}`
                      }
                    >
                      <div className="hm-tech-id">
                        {tech.id}
                        {hit && (
                          <span className="hm-count">{hit.claim_count}</span>
                        )}
                      </div>
                      <div className="hm-tech-name">{tech.name}</div>
                    </div>
                  );
                })}
              </div>
            );
          })}
        </div>
      </div>
      <p className="tiny faint">
        Intensity = claim volume (sqrt scale). Hover a technique for exact
        counts. Empty cells are techniques with no corroborated claims in
        the window — absence of signal, not absence of risk.
      </p>
    </>
  );
}
