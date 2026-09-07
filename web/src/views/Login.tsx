import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../api";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const qc = useQueryClient();

  const login = useMutation({
    mutationFn: () => api.post("/api/v1/auth/login", { email, password }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["me"] }),
    onError: (e) => setError(e instanceof Error ? e.message : "login failed"),
  });

  return (
    <div className="login-wrap">
      <div className="panel login-card">
        <h1>TRU<span style={{ color: "var(--accent)" }}>VO</span></h1>
        <div className="login-sub">PRIORITIZE · HUNT · DETECT</div>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            setError("");
            login.mutate();
          }}
        >
          <input
            type="email"
            placeholder="email"
            autoComplete="username"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoFocus
            required
          />
          <input
            type="password"
            placeholder="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          <button
            className="primary"
            type="submit"
            disabled={login.isPending || !email || !password}
          >
            {login.isPending ? "Signing in…" : "Sign in"}
          </button>
        </form>
        <p className="login-error">{error}</p>
        <div className="login-foot">
          SSO (OIDC / SAML) is used in production deployments; this form
          serves dev, self-hosted, and air-gap profiles.
        </div>
      </div>
    </div>
  );
}
