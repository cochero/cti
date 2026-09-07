import { useMutation, useQuery } from "@tanstack/react-query";
import { NavLink, Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { api, type Me } from "./api";
import Dashboard from "./views/Dashboard";
import Heatmap from "./views/Heatmap";
import Login from "./views/Login";
import Onboarding from "./views/Onboarding";
import Priorities from "./views/Priorities";
import Rules from "./views/Rules";
import ThreatDetail from "./views/ThreatDetail";

const NAV = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/priorities", label: "Priorities" },
  { to: "/rules", label: "Rules" },
  { to: "/heatmap", label: "ATT&CK Heatmap" },
];

function Shell({ me }: { me: Me }) {
  const navigate = useNavigate();
  const logout = useMutation({
    mutationFn: () => api.post("/api/v1/auth/logout"),
    onSuccess: () => navigate("/login", { replace: true }),
  });

  return (
    <div className="shell">
      <nav className="sidenav">
        <div className="brand">
          TRU<em>VO</em>
          <span className="brand-sub">PRIORITIZE · HUNT · DETECT</span>
        </div>
        {NAV.map((n) => (
          <NavLink
            key={n.to}
            to={n.to}
            end={n.end}
            className={({ isActive }) => "navlink" + (isActive ? " active" : "")}
          >
            {n.label}
          </NavLink>
        ))}
        {me.is_staff && (
          <NavLink
            to="/onboarding"
            className={({ isActive }) => "navlink" + (isActive ? " active" : "")}
          >
            Onboarding
          </NavLink>
        )}
        <div className="nav-foot">
          <div className="who">{me.user}</div>
          <div>{me.role} · {me.tenant_id?.slice(0, 8)}</div>
          <div style={{ marginTop: 10 }}>
            <button className="tiny" onClick={() => logout.mutate()}>
              Sign out
            </button>
          </div>
        </div>
      </nav>
      <main className="main">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/priorities" element={<Priorities />} />
          <Route path="/priorities/:cve" element={<ThreatDetail />} />
          <Route path="/rules" element={<Rules />} />
          <Route path="/heatmap" element={<Heatmap />} />
          <Route path="/onboarding"
                 element={me.is_staff ? <Onboarding /> : <Navigate to="/" replace />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}

export default function App() {
  const me = useQuery({
    queryKey: ["me"],
    queryFn: () => api.get<Me>("/api/v1/tenants/me"),
    retry: false,
  });

  if (me.isPending) return <div className="spinner">…</div>;

  if (me.isError || !me.data?.tenant_id) {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    );
  }

  return (
    <Routes>
      <Route path="/login" element={<Navigate to="/" replace />} />
      <Route path="*" element={<Shell me={me.data} />} />
    </Routes>
  );
}
