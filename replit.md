# CyberShield AI

CyberShield AI is a defensive cybersecurity analyst workspace for triaging incidents, mapping attack paths, exploring common threats, and turning evidence into response actions.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the API server (port 5000)
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Required env: `DATABASE_URL` — Postgres connection string

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- API: Express 5
- DB: PostgreSQL + Drizzle ORM
- Validation: Zod (`zod/v4`), `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- Build: esbuild (CJS bundle)

## Where things live

- `artifacts/cybershield-ai/src/App.tsx` — main web shell, routes, and interactive incident/learning flows
- `artifacts/cybershield-ai/src/index.css` — CyberShield visual language and responsive theme
- `artifacts/api-server/src/routes/cyber.ts` — dashboard, incident, analyst, attack explorer, and learning endpoints
- `lib/api-spec/openapi.yaml` — source of truth for the typed API client and server schemas
- `lib/db/src/schema/incidents.ts` — persisted incident history model

## Architecture decisions

- The web app is a root `react-vite` artifact so the SOC workspace is the default preview.
- API contracts are OpenAPI-first; generated React Query hooks are used by the frontend.
- Incident analysis is persisted in PostgreSQL with rich analysis sections stored as JSONB.
- AI output is defensive-only and uncertainty-aware; the server falls back to safe local triage if the model is unavailable.
- The frontend uses a light telemetry canvas with a graphite command sidebar so dense data stays legible while preserving SOC character.

## Product

- SOC overview with incident metrics, volume trends, attack-surface mix, and recent activity
- Defensive AI analyst chat backed by a secure server-side model call with explicit safety boundaries
- Incident intake and history with uncertainty-aware assessment, evidence, timeline, attack flow, root cause, risk signal, and response recommendations
- Attack knowledge explorer with searchable defensive references for common attack types
- Learning center with short lessons and generated knowledge checks
- Settings surface for analyst preferences

## User preferences

No additional preferences recorded.

## Gotchas

- Run `pnpm --filter @workspace/api-spec run codegen` after changing `lib/api-spec/openapi.yaml`.
- Artifact builds need workflow-provided `PORT` and `BASE_PATH`; use the artifact workflow for runtime verification.
- The API server needs `OPENAI_API_KEY` for live model responses; its defensive fallback keeps non-AI surfaces available without it.

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
