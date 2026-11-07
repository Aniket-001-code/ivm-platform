"""Measure the executive API response time against a running seeded demo."""

import statistics
import time

import httpx

BASE = "http://127.0.0.1:8000/api/v1"
with httpx.Client(timeout=20) as client:
    login = client.post(
        f"{BASE}/auth/login",
        json={"email": "user2@demo.bank", "password": "DemoPass!234"},
    )
    login.raise_for_status()
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    samples = []
    for _ in range(10):
        start = time.perf_counter()
        response = client.get(f"{BASE}/dashboards/executive", headers=headers)
        response.raise_for_status()
        samples.append(time.perf_counter() - start)
p95 = sorted(samples)[int(0.95 * (len(samples) - 1))]
print(
    f"dashboard samples={len(samples)} mean={statistics.mean(samples):.3f}s p95={p95:.3f}s"
)
if p95 >= 3:
    raise SystemExit("Executive dashboard p95 exceeded 3 seconds")
