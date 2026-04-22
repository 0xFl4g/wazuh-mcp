"""Seed the Wazuh indexer with synthetic alerts for integration tests.

Assumes the docker-compose stack is healthy on localhost:9200 with the
default admin credentials.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta

import httpx

BASE = "https://localhost:9200"
AUTH = ("admin", "admin")
INDEX = f"wazuh-alerts-4.x-{datetime.now(UTC):%Y.%m.%d}"


def _alert(idx: int, level: int, offset_min: int) -> dict:
    ts = datetime.now(UTC) - timedelta(minutes=offset_min)
    return {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "@timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "agent": {"id": "001", "name": "web-01", "ip": "10.0.0.5"},
        "rule": {
            "id": str(5700 + idx),
            "level": level,
            "description": f"synthetic rule {idx}",
            "mitre": {"id": ["T1110.001"], "tactic": ["Credential Access"]} if level >= 10 else {},
        },
        "location": "/var/log/auth.log",
        "decoder": {"name": "sshd"},
    }


def main() -> int:
    client = httpx.Client(auth=AUTH, verify=False, timeout=30)
    docs = []
    # Offsets span the last 24h — 5 min apart for the first 5 (critical window),
    # then 1h apart for the remaining 15. Integration tests query with
    # time_range="24h" so drift up to ~1h before test run still keeps all 20
    # alerts in-range.
    offsets = [5, 10, 15, 20, 25, *range(60, 60 + 15 * 60, 60)]
    for i, offset_min in enumerate(offsets):
        lvl = 12 if i % 4 == 0 else 3
        docs.append(_alert(i, lvl, offset_min=offset_min))
    lines = []
    for d in docs:
        lines.append(json.dumps({"index": {"_index": INDEX}}))
        lines.append(json.dumps(d))
    body = "\n".join(lines) + "\n"
    r = client.post(
        f"{BASE}/_bulk",
        content=body,
        headers={"Content-Type": "application/x-ndjson"},
    )
    r.raise_for_status()
    resp = r.json()
    if resp.get("errors"):
        print("bulk errors:", json.dumps(resp)[:500], file=sys.stderr)
        return 1
    client.post(f"{BASE}/{INDEX}/_refresh").raise_for_status()
    print(f"Seeded {len(docs)} alerts into {INDEX}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
