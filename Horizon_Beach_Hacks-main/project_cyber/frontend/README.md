# Contexta web UI

Next.js 16 / React 19 / Tailwind dashboard for the Contexta API. It renders only data returned by the
backend (`/api/v1`); there is no bundled or fallback data, so an empty system shows empty states.

```bash
cp .env.example .env.local     # NEXT_PUBLIC_API_URL must be reachable from the user's browser
npm install
npm run dev                    # http://localhost:3000
npm run build && npm start     # production build
```

Views: Overview, Top Risks, Alerts, Incidents, Playbooks, Attack Simulator, Assets, Reports, Executive View,
Audit Ledger, Settings (profile, organization, integrations, users, system). Actions are gated by role
(viewer < analyst < admin) both in the UI and, authoritatively, in the API.

Security: the build sets a Content-Security-Policy, `X-Frame-Options: DENY`, `nosniff`, a strict referrer policy and HSTS.
`NEXT_PUBLIC_API_URL` is inlined at build time and is also the only cross-origin `connect-src` allowed.
