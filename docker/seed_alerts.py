"""Seed the Wazuh indexer with synthetic alerts for integration tests.

Assumes the docker-compose stack is healthy on localhost:9200 with the
default admin credentials.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone

import httpx

BASE = "https://localhost:9200"
AUTH = ("admin", "SecretPassword")
INDEX = f"wazuh-alerts-4.x-{datetime.now(timezone.utc):%Y.%m.%d}"


def _alert(idx: int, level: int, offset_min: int) -> dict:
    ts = datetime.now(timezone.utc) - timedelta(minutes=offset_min)
    return {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "@timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "agent": {"id": "001", "name": "web-01", "ip": "10.0.0.5"},
        "rule": {
            "id": str(5700 + idx),
            "level": level,
            "description": f"synthetic rule {idx}",
            "mitre": {"id": ["T1110.001"], "tactic": ["Credential Access"]}
            if level >= 10 else {},
        },
        "location": "/var/log/auth.log",
        "decoder": {"name": "sshd"},
    }


def main() -> int:
    client = httpx.Client(auth=AUTH, verify=False, timeout=30)
    docs = []
    for i in range(20):
        lvl = 12 if i % 4 == 0 else 3
        docs.append(_alert(i, lvl, offset_min=i))
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
