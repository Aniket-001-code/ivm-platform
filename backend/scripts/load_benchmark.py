"""Concurrent load test against a running API (scalability NFR evidence).

Usage: python scripts/load_benchmark.py [--users 25] [--requests 600]
Simulates concurrent users hitting the busiest read endpoints with a single analyst session.
"""

import argparse
import statistics
import time
from concurrent.futures import ThreadPoolExecutor

import httpx

BASE = "http://127.0.0.1:8000/api/v1"
ENDPOINTS = [
    "/dashboards/analyst",
    "/findings?limit=50",
    "/findings?band=critical&limit=50&sort=risk_score",
    "/assets?limit=30",
    "/tasks?limit=50",
    "/attack-paths",
    "/dashboards/trend",
    "/reports/remediation-plan",
]

parser = argparse.ArgumentParser()
parser.add_argument("--users", type=int, default=25)
parser.add_argument("--requests", type=int, default=600)
args = parser.parse_args()

with httpx.Client(timeout=120) as client:
    login = client.post(
        f"{BASE}/auth/login", json={"email": "user2@demo.bank", "password": "DemoPass!234"}
    )
    login.raise_for_status()
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}


def hit(index: int) -> tuple[str, float, int]:
    path = ENDPOINTS[index % len(ENDPOINTS)]
    start = time.perf_counter()
    with httpx.Client(timeout=120) as session:
        status = session.get(f"{BASE}{path}", headers=headers).status_code
    return path.split("?")[0], time.perf_counter() - start, status


started = time.perf_counter()
with ThreadPoolExecutor(max_workers=args.users) as pool:
    results = list(pool.map(hit, range(args.requests)))
elapsed = time.perf_counter() - started

latencies = sorted(r[1] for r in results)
errors = sum(1 for r in results if r[2] >= 400)
pct = lambda p: latencies[min(len(latencies) - 1, int(p * len(latencies)))]  # noqa: E731
print(f"concurrent users={args.users} requests={args.requests} elapsed={elapsed:.1f}s")
print(f"throughput={args.requests / elapsed:.1f} req/s errors={errors}")
print(f"latency p50={pct(0.50):.3f}s p95={pct(0.95):.3f}s max={latencies[-1]:.3f}s")
for path in sorted({r[0] for r in results}):
    values = [r[1] for r in results if r[0] == path]
    print(f"  {path:32} mean={statistics.mean(values):.3f}s")
if errors:
    raise SystemExit("Load test produced errors")
