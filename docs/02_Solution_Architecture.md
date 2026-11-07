# Solution Architecture

## Overview

The browser UI calls a versioned FastAPI service. The service applies authentication and authorization, invokes domain services, and stores records in PostgreSQL through SQLAlchemy. Alembic owns schema creation. APScheduler runs local SLA and exception-expiry jobs. NetworkX builds an in-memory graph from asset-connection rows. Synthetic exports are generated at image build time with a fixed seed, and an optional Claude client is used only when an environment API key is supplied.

```mermaid
flowchart LR
  U[Analyst / manager / auditor] -->|HTTPS optional; REST| UI[React 18 + Vite]
  UI -->|Bearer access token| API[FastAPI v1]
  API --> AUTH[JWT, bcrypt, TOTP]
  API --> SVC[Risk, ingestion, workflow, analytics services]
  SVC --> DB[(PostgreSQL 15)]
  SVC --> GRAPH[NetworkX in-memory graph]
  JOB[APScheduler] --> SVC
  SYN[Seeded synthetic exports] --> ING[Normalization and correlation]
  ING --> DB
  AI[Claude SDK optional] -. aggregate context only .-> SVC
```

## Deployment diagram

```mermaid
flowchart TB
  Browser -->|8080 HTTP| Frontend[Frontend Nginx + React assets]
  Browser -. optional TLS 8443 .-> TLS[Self-signed Nginx profile]
  TLS --> Frontend
  TLS --> Backend[FastAPI container]
  Frontend --> Backend
  Backend -->|5432 internal| DB[(PostgreSQL volume)]
```

The default Compose deployment exposes the UI on port 8080 and API/Swagger on 8000. The optional TLS profile terminates HTTPS on 8443. The self-signed certificate is for a local demo and will generate a browser trust warning.

## Import-to-score sequence

```mermaid
sequenceDiagram
  participant Analyst
  participant API
  participant Normalizer
  participant DB
  Analyst->>API: Upload CSV or JSON (max 10 MB)
  API->>Normalizer: Validate and map source fields
  Normalizer->>DB: Save batch and raw row
  Normalizer->>DB: Resolve asset and CVE
  Normalizer->>DB: Match asset-scoped fingerprint
  alt duplicate
    Normalizer->>DB: Add finding_sources provenance
  else new record
    Normalizer->>DB: Save finding and score breakdown
  end
  API-->>Analyst: Counts, status, and row errors
```

## Exception-approval sequence

```mermaid
sequenceDiagram
  participant Owner
  participant API
  participant Approver
  participant DB
  Owner->>API: Request reason, controls, and expiry
  API->>DB: Save pending exception + audit event
  Approver->>API: Approve or reject with comment
  API->>API: Reject self-approval and invalid transitions
  API->>DB: Save decision, reviewer, timestamp, audit event
  alt approved
    API->>DB: Mark finding risk_accepted
  end
  API-->>Owner: Updated decision
```

## Trust boundaries

1. The browser is untrusted; every API request is validated and authenticated.
2. The Compose network is an isolated local service boundary; only mapped ports are reachable from the host.
3. PostgreSQL stores application records and encrypted MFA secrets; the database volume is not production encrypted by this demo.
4. Optional Anthropic calls cross the local boundary. Only a short question and aggregate synthetic context are sent, with a bounded timeout and fallback.
5. Imported files are untrusted input and are size- and extension-checked before parsing.
