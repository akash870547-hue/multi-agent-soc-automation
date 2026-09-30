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

### Optional LLM reasoning

The default reasoning engine is deterministic and requires no API key. To enable the optional OpenAI provider, install `requirements-llm.txt`, set `OPENAI_API_KEY`, and set `SOC_REASONING_PROVIDER=openai`. The model can be selected with `SOC_REASONING_MODEL`.

The adapter uses the OpenAI Responses API and keeps response actions behind the existing human approval gate. See `.env.example` for the configuration surface.

### Optional API authentication

Set `SOC_API_KEY` to protect event ingestion and incident state-changing endpoints with the `X-API-Key` header. When `SOC_API_KEY` is not configured, the local development API remains open for the dashboard demo.

```bash
SOC_API_KEY=change-me uvicorn api:app --host 0.0.0.0 --port 8000
```

The public GitHub Pages dashboard runs in demo mode by default. To connect it to a running API, open the dashboard with an `api` query parameter, for example:

`?api=http://localhost:8000`

## Experiments

A reproducible synthetic SOC dataset is provided under `experiments/dataset.json`. Run the evaluation with:

```bash
python experiments/evaluate.py
```

The runner reports classification metrics for the current multi-agent pipeline and a simple keyword baseline, including accuracy, precision, recall, F1, and confusion-matrix counts. The dataset is intentionally small and synthetic; it is a development/research fixture, not a production benchmark.

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
- [ ] Role-based access
- [x] Initial MTTD/MTTR experiment dataset and classification evaluation framework
- [ ] Threat intelligence provider adapters
- [ ] Production backend deployment
- [ ] Production-grade live dashboard

<!-- GitHub Pages deployment trigger: dashboard deployment enabled. -->
