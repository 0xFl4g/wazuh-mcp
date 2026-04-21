from starlette.testclient import TestClient

from wazuh_mcp.transport.http import build_metadata_endpoint


def test_metadata_body_matches_rfc9728():
    app = build_metadata_endpoint(
        resource_url="https://mcp.example.com",
        authorization_server="https://idp.example.com/realms/msp",
    )
    client = TestClient(app)
    resp = client.get("/.well-known/oauth-protected-resource")
    assert resp.status_code == 200
    body = resp.json()
    assert body["resource"] == "https://mcp.example.com"
    assert body["authorization_servers"] == ["https://idp.example.com/realms/msp"]
    assert "header" in body["bearer_methods_supported"]
