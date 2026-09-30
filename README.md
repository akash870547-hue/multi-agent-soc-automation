# Multi-Agent SOC Automation

Implementation of the research project **“Multi-Agent Artificial Intelligence Framework for Security Operations Center (SOC) Automation and Incident Response.”**

## Goal

Build a modular SOC automation platform that ingests security events, triages alerts, enriches indicators, investigates incidents, recommends response actions, and keeps a human analyst in the approval loop.

## Architecture

Security Events → Ingestion → Detection → Correlation → Multi-Agent Analysis → Governance → Response Recommendation → Incident Report

### Agents

- Triage Agent
- Threat Intelligence Agent
- Investigation Agent
- Response Agent
- Reporting Agent

## Design principles

- Human approval for consequential response actions
- Auditable agent decisions
- Structured security events
- Reproducible experiments
- Measurable MTTD/MTTR improvements
- Local-first development
- Provider-agnostic reasoning
- Optional LLM-assisted reasoning with deterministic fallback

## Current implementation

The backend currently supports:

- Production-oriented container image with non-root runtime and persistent SQLite volume
- `/ready` readiness endpoint and API ingestion rate limiting

- Structured security event ingestion
- Rule-based alert detection
- Multi-agent incident orchestration
- IOC extraction and MITRE ATT&CK mapping
- Reusable time-window event correlation using source IP, destination IP, and username pivots
- Deterministic reasoning and incident prioritization
- SQLite persistence for events and incidents
- Human approval workflow
- Incident acknowledgement and resolution lifecycle
- MTTD and MTTR API metrics
- Automated tests and GitHub Actions CI
- Browser-based SOC dashboard prototype

## Run

```bash
python -m venv .venv
.venv\\Scripts\\activate
pip install -r requirements.txt
python -m soc_automation
```

## Browser Demo

The repository includes a SOC dashboard prototype in `dashboard/index.html`.

After GitHub Pages is enabled for the repository, the dashboard is available at:

`https://akash870547-hue.github.io/multi-agent-soc-automation/`

The dashboard is the presentation layer. The Python API and agent pipeline run separately.

## API backend

Run the SOC API locally:

```bash
uvicorn api:app --reload
```

Useful endpoints:

- `GET /health` - service health
- `GET /api/agents` - agent status
- `GET /api/incidents` - incident list
- `GET /api/incidents/{incident_id}` - incident details
- `GET /api/metrics` - SOC metrics including MTTD/MTTR
- `POST /api/events` - ingest and process a security event
- `POST /api/incidents/{incident_id}/approve` - human approval gate
- `POST /api/incidents/{incident_id}/acknowledge` - acknowledge an incident
- `POST /api/incidents/{incident_id}/resolve` - resolve an incident
- `GET /api/threat-intel/{indicator}` - optional IOC enrichment
- `GET /api/audit-logs` - recent auditable state-changing actions
- `GET /api/monitor/targets` - monitored websites with security findings
- `POST /api/public/security-test` - one-time public HTTPS security test; does not persist a target
- `GET /api/monitor/targets` - admin/responder/analyst view of persisted monitoring targets
- `POST /api/monitor/targets` - admin-only add a continuous monitoring target
- `POST /api/monitor/targets/{target_id}/check` - trigger an immediate admin-monitoring check
- `GET /api/monitor/targets/{target_id}/history` - recent admin-monitoring check history
- `DELETE /api/monitor/targets/{target_id}` - admin-only remove a monitoring target

### Optional LLM reasoning

The default reasoning engine is deterministic and requires no API key. To enable the optional OpenAI provider, install `requirements-llm.txt`, set `OPENAI_API_KEY`, and set `SOC_REASONING_PROVIDER=openai`. The model can be selected with `SOC_REASONING_MODEL`.

The adapter uses the OpenAI Responses API and keeps response actions behind the existing human approval gate. See `.env.example` for the configuration surface.

### API authentication and RBAC

Set `SOC_API_KEY` to protect state-changing endpoints with the `X-API-Key` header. For role-based access, configure `SOC_ANALYST_KEY`, `SOC_RESPONDER_KEY`, and `SOC_ADMIN_KEY`. Analysts can ingest and acknowledge events, responders can additionally approve and resolve incidents, and admins can access audit logs. The legacy `SOC_API_KEY` acts as an admin key. When no keys are configured, the local development API remains open for the dashboard demo.

```bash
SOC_API_KEY=change-me uvicorn api:app --host 0.0.0.0 --port 8000
```

The public GitHub Pages dashboard runs in demo mode by default. When an API URL is supplied with `?api=...`, the dashboard connects to the FastAPI backend and sends the optional `X-API-Key` header for state-changing operations. The API key is stored in browser local storage. To connect it to a running API, open the dashboard with an `api` query parameter, for example:

`?api=http://localhost:8000`


### SOC roles and website monitoring

The dashboard exposes role-aware controls through `GET /api/me`:

- **Analyst:** ingest events, acknowledge incidents, inspect monitored websites.
- **Responder:** analyst permissions plus approve and resolve incidents.
- **Admin:** responder permissions plus website-target administration and audit logs.

Website security monitoring has two separate surfaces. The **Public Website Security Test** uses `POST /api/public/security-test` for a single, read-only HTTPS inspection. It does not save a target, start background polling, or create SOC incidents. It is rate-limited separately and rejects private/local targets. The **Admin Continuous Website Monitoring** surface uses `POST /api/monitor/targets` and is admin-only for creating/removing persistent targets. Those targets are checked every 5 minutes by default and record availability, HTTP status, latency, TLS certificate validity/expiry, response security headers, redirect chain, a bounded content SHA-256 fingerprint, findings, and check history. Admin monitoring can generate SOC incidents for availability state changes, newly removed security headers, TLS certificates entering the 30-day expiry window, redirect-chain changes, and content changes. Analysts/responders can inspect existing targets and trigger checks, but cannot create or delete monitoring targets.

## Experiments

A reproducible synthetic SOC dataset is provided under `experiments/dataset.json`. Run the evaluation with:

```bash
python experiments/evaluate.py
```

The runner reports classification metrics for the current multi-agent pipeline and a simple keyword baseline, including accuracy, precision, recall, F1, and confusion-matrix counts. The dataset is intentionally small and synthetic; it is a development/research fixture, not a production benchmark.

## Hosted deployment blueprint

`render.yaml` provides a Docker-based deployment blueprint with a persistent SQLite disk and `/ready` health check. Set the role/API secrets in the hosting provider rather than committing them. After deployment, connect GitHub Pages with `?api=https://YOUR-API-HOST`.

The repository provides deployment configuration, but actual hosting requires the owner to create the service and supply production secrets/billing credentials.

## Test

```bash
pytest
```

## Development roadmap

- [x] Core security event and incident models
- [x] Rule-based alert detection
- [x] Initial multi-agent orchestration
- [x] SOC dashboard prototype
- [x] Threat Intelligence Agent
- [x] IOC enrichment
- [x] MITRE ATT&CK mapping
- [x] Event correlation engine
- [x] Governance and human approval workflow
- [x] SQLite persistent incident/event store
- [x] Deterministic reasoning foundation
- [x] Incident acknowledgement/resolution lifecycle
- [x] MTTD/MTTR API metrics
- [x] Pluggable reasoning provider with optional OpenAI adapter
- [x] Optional API-key authentication
- [x] Role-based API access and audit authorization
- [x] Initial MTTD/MTTR experiment dataset and classification evaluation framework
- [x] Optional threat intelligence provider adapter
- [x] API audit logging
- [x] Production deployment configuration (Docker/Compose + readiness/health checks)
- [x] Website security monitoring with TLS, headers, redirects, content and history
- [x] Production-grade dashboard/API integration
- [x] Hosted GitHub Pages dashboard
- [x] Hosted Render backend (portfolio/demo deployment)

<!-- GitHub Pages deployment trigger: dashboard deployment enabled. -->
