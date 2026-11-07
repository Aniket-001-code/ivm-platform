# Kubernetes deployment (reference)

Reference manifests for a cloud-native deployment of the academic demo. They parse as valid
Kubernetes YAML but have not been applied to a cluster (no cluster was available).

| File | Purpose |
|---|---|
| `namespace.yaml` | `ivm` namespace with the *restricted* Pod Security Standard |
| `config.yaml` / `secret.example.yaml` | Non-secret settings and a secret template (never commit real secrets) |
| `database.yaml` | PostgreSQL 15 StatefulSet with a persistent volume |
| `backend.yaml` | 2–6 API replicas (HPA), migrations as an init container, scheduler disabled |
| `scheduler.yaml` | Exactly one scheduler pod for SLA escalation and exception expiry |
| `frontend.yaml` | Static web app (nginx) |
| `ingress.yaml` | TLS ingress routing `/api` and `/docs` to the API and `/` to the web app |
| `network-policy.yaml` | Default-deny ingress; only the API and scheduler may reach PostgreSQL |

```bash
docker build -t ivm-backend:latest backend && docker build -t ivm-frontend:latest frontend
kubectl apply -f deploy/k8s/namespace.yaml
kubectl -n ivm create secret generic ivm-secrets --from-literal=...   # see secret.example.yaml
kubectl apply -f deploy/k8s/config.yaml -f deploy/k8s/database.yaml -f deploy/k8s/backend.yaml \
  -f deploy/k8s/scheduler.yaml -f deploy/k8s/frontend.yaml -f deploy/k8s/ingress.yaml \
  -f deploy/k8s/network-policy.yaml
```

Backups: run `backend/scripts/backup.sh` from a CronJob with `DATABASE_URL` from the secret.
