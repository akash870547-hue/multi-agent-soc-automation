# Multi-Agent SOC Automation

Implementation of the research project **“Multi-Agent Artificial Intelligence Framework for Security Operations Center (SOC) Automation and Incident Response.”**

## Goal

Build a modular SOC automation platform that ingests security events, triages alerts, enriches indicators, investigates incidents, recommends response actions, and keeps a human analyst in the approval loop.

## Architecture

Security Events → Ingestion → Detection/Correlation → Multi-Agent Analysis → Governance → Response Recommendation → Incident Report

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

## Phase 1

The initial MVP supports structured events, rule-based detection, incident creation, agent orchestration, JSON incident reports, and tests.

## Run

```bash
python -m venv .venv
.venv\\Scripts\\activate
pip install -r requirements.txt
python -m soc_automation
```

## Browser Demo

The repository includes a SOC dashboard prototype in `dashboard/index.html`.

After GitHub Pages is enabled for the repository, the dashboard will be available at:

`https://akash870547-hue.github.io/multi-agent-soc-automation/`

The dashboard is designed as the presentation layer for the project. The backend and agent pipeline remain in the Python package.

## Test

```bash
pytest
```

## Development roadmap

- [x] Core security event and incident models
- [x] Rule-based alert detection
- [x] Initial multi-agent orchestration
- [x] SOC dashboard prototype
- [ ] Threat Intelligence Agent
- [ ] IOC enrichment
- [ ] MITRE ATT&CK mapping
- [ ] Event correlation engine
- [ ] Governance and approval workflow
- [ ] LLM reasoning layer
- [ ] API and persistent incident store
- [ ] MTTD/MTTR experiment framework
- [ ] Production-grade dashboard


<!-- GitHub Pages deployment trigger: dashboard deployment enabled. -->
