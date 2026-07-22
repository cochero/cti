# core (Django)

Tenancy, RBAC, SSO (OIDC/SAML), admin, adjudication queues, MIS API. Django 5 LTS + DRF.

- **Reference:** Arch SS4.2; built S1-S2
- **Owner:** Product & Integrations
- **Status:** scaffold only -- see DEVELOPMENT_PLAN.md for the sprint that builds this.

Before first staging traffic this component needs: OTel instrumentation,
a runbook in `ops/runbooks/`, and a reviewed THREAT_MODEL.md (see
`services/ledger/THREAT_MODEL.md` for the pattern).
