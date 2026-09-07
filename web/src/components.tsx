import type { ReactNode } from "react";

export function millis(m: number | null | undefined): string {
  if (m === null || m === undefined) return "—";
  return (m / 10).toFixed(m % 10 === 0 ? 0 : 1);
}

export function severity(m: number): string {
  if (m >= 800) return "sev-critical";
  if (m >= 600) return "sev-high";
  if (m >= 350) return "sev-medium";
  return "sev-low";
}

export function barColor(m: number): string {
  if (m >= 800) return "var(--critical)";
  if (m >= 600) return "var(--bad)";
  if (m >= 350) return "var(--warn)";
  return "var(--accent)";
}

export function ScoreCell({ millis: m }: { millis: number }) {
  return (
    <div className="score-cell">
      <span className={"score-num " + severity(m)}>{millis(m)}</span>
      <div className="scorebar" title={`priority ${millis(m)} / 100`}>
        <i style={{ width: `${Math.min(100, m / 10)}%`, background: barColor(m) }} />
      </div>
    </div>
  );
}

export function whenAgo(iso: string | null | undefined): string {
  if (!iso) return "—";
  const then = new Date(iso.includes("T") ? iso : iso.replace(" ", "T") + "Z");
  const s = Math.max(0, (Date.now() - then.getTime()) / 1000);
  if (s < 90) return `${Math.round(s)}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function Panel({
  title,
  children,
  aside,
}: {
  title?: string;
  children: ReactNode;
  aside?: ReactNode;
}) {
  return (
    <section className="panel" style={{ marginBottom: 18 }}>
      {(title || aside) && (
        <div className="spread" style={{ marginBottom: 12 }}>
          <h2 className="mt0" style={{ fontSize: 14, fontWeight: 650, letterSpacing: "0.04em" }}>
            {title}
          </h2>
          {aside}
        </div>
      )}
      {children}
    </section>
  );
}

export function Loading({ what }: { what: string }) {
  return <div className="spinner">loading {what}…</div>;
}

export function ErrorNote({ error }: { error: unknown }) {
  const msg = error instanceof Error ? error.message : String(error);
  return <div className="error-note">{msg}</div>;
}

export const FACTOR_LABELS: Record<string, string> = {
  stack_overlap: "Stack overlap",
  exploit_maturity: "Exploit maturity",
  actor_reach: "Actor reach",
  identity_exposure: "Identity exposure",
  campaign_momentum: "Campaign momentum",
  sector_affinity: "Sector affinity",
};
