"""Seed the Wazuh indexer with synthetic alerts for integration tests.

Also registers agent ``001`` against the wazuh-manager Server API so the
M4b write-tool integration tests (``write.isolate_agent``,
``write.add_agent_to_group``, etc.) have a real target — the integration
compose has no wazuh-agent container, but the manager's ``POST /agents``
endpoint will accept a registration without a running agent process.
The synthetic alerts then reference the same agent.id so the
read-and-write surfaces line up.

Assumes the docker-compose stack is healthy on localhost:9200 with the
default admin credentials.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime, timedelta

import httpx

BASE = "https://localhost:9200"
AUTH = ("admin", "admin")
INDEX = f"wazuh-alerts-4.x-{datetime.now(UTC):%Y.%m.%d}"

MANAGER_BASE = os.environ.get("WAZUH_MANAGER_URL", "https://localhost:55000")
MANAGER_USER = os.environ.get("WAZUH_MANAGER_USER", "wazuh-wui")
MANAGER_PASSWORD = os.environ.get("WAZUH_MANAGER_PASSWORD", "MCPmcp12345!")


def _register_agent_001() -> None:
    """Best-effort: register agent ``001`` with the manager so write tools have
    a real target. If the agent already exists or the manager is unreachable,
    log and continue — the alert seeding still works without it.
    """
    auth = httpx.post(
        f"{MANAGER_BASE}/security/user/authenticate?raw=true",
        auth=(MANAGER_USER, MANAGER_PASSWORD),
        verify=False,
        timeout=10,
    )
    if auth.status_code != 200:
        print(f"[seed] manager auth skipped (status {auth.status_code})", file=sys.stderr)
        return
    token = auth.text.strip()
    # POST /agents accepts {name, ip} and assigns an id. The seeded synthetic
    # alerts reference agent.id="001"; the manager picks the next free id, so
    # set ip to "any" to take the first slot deterministically on a fresh
    # fixture.
    resp = httpx.post(
        f"{MANAGER_BASE}/agents",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"name": "web-01", "ip": "any"},
        verify=False,
        timeout=10,
    )
    if resp.status_code in (200, 201):
        body = resp.json()
        new_id = body.get("data", {}).get("id")
        print(f"[seed] registered agent id={new_id}")
    elif resp.status_code == 400 and "already" in resp.text.lower():
        print("[seed] agent already registered, skipping")
    else:
        print(
            f"[seed] agent registration returned {resp.status_code}: {resp.text[:300]}",
            file=sys.stderr,
        )


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
    _register_agent_001()
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
