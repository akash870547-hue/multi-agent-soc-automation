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

## Test

```bash
pytest
```
