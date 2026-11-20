import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def test_playground_presets_and_execution():
    res = client.get("/api/v1/playground/presets")
    assert res.status_code == 200, res.text
    presets = res.json()["presets"]
    assert len(presets) == 6, f"Expected 6 presets, got {len(presets)}"

    for p in presets:
        pid = p["id"]
        exp = p["expected_decisions"]
        run_res = client.post("/api/v1/playground/run", json={
            "document_text": p["document_text"],
            "action": p["action"],
            "preset_id": pid
        })
        assert run_res.status_code == 200, f"Error on {pid}: {run_res.text}"
        data = run_res.json()
        lanes = data["lanes"]
        
        assert lanes["pass_through"]["decision"] == exp["pass_through"], f"Mismatch on pass_through for {pid}"
        assert lanes["phrase_filter"]["decision"] == exp["phrase_filter"], f"Mismatch on phrase_filter for {pid}"
        assert lanes["gateway"]["decision"] == exp["gateway"], f"Mismatch on gateway for {pid}"

def test_playground_payload_size_cap():
    res = client.get("/api/v1/playground/presets")
    preset = res.json()["presets"][0]
    large_text = "A" * 20000
    cap_res = client.post("/api/v1/playground/run", json={
        "document_text": large_text,
        "action": preset["action"]
    })
    assert cap_res.status_code == 413

def test_playground_findings_endpoint():
    res = client.get("/api/v1/playground/findings")
    assert res.status_code == 200
    data = res.json()
    assert "total_attempts" in data
    assert "total_bypasses" in data
    assert "findings" in data
