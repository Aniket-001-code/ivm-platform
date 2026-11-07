# Deployment

```mermaid
flowchart LR
  B[Browser] -->|HTTPS| ING[nginx / TLS ingress]
  ING -->|/| WEB[Web: React static on nginx]
  ING -->|/api, /docs| API[API replicas: FastAPI, scheduler off]
  SCH[Scheduler: 1 replica] --> DB
  API --> DB[(PostgreSQL 15)]
  EXT[Ticketing system] -->|HMAC-signed webhook| ING
  API -.optional.-> CL[Anthropic API: aggregates only]
```

Local development uses `scripts/dev.sh` (SQLite, Vite on :5173, API on :8000). `docker-compose.yml` runs PostgreSQL,
API, web and an optional TLS proxy. `deploy/k8s/` holds the Kubernetes reference manifests (HPA, NetworkPolicies,
restricted pod security).
