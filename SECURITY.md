# Security Policy

This repository is a research and portfolio prototype. Report security issues affecting the API, dashboard, authentication, authorization, data handling, or container configuration.

## Do not commit secrets

Use environment variables for SOC_API_KEY, SOC_ANALYST_KEY, SOC_RESPONDER_KEY, SOC_ADMIN_KEY, OPENAI_API_KEY, and VIRUSTOTAL_API_KEY.

Never commit .env files, database files, credentials, or production tokens.

## Production deployment

Use HTTPS, rotate API keys, restrict CORS to trusted dashboard origins, place the API behind a reverse proxy or WAF, and use managed persistent storage before exposing the service to untrusted networks.

## Response actions

The application intentionally keeps consequential response actions behind a human approval gate. Do not remove that control without an explicit security review.
