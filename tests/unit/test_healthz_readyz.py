from starlette.testclient import TestClient

from wazuh_mcp.transport.http import build_health_endpoints


def test_healthz_always_200():
    app = build_health_endpoints(ready_fn=lambda: False)
    client = TestClient(app)
    assert client.get("/healthz").status_code == 200


def test_readyz_503_when_not_ready():
    app = build_health_endpoints(ready_fn=lambda: False)
    client = TestClient(app)
    assert client.get("/readyz").status_code == 503


def test_readyz_200_when_ready():
    app = build_health_endpoints(ready_fn=lambda: True)
    client = TestClient(app)
    assert client.get("/readyz").status_code == 200
