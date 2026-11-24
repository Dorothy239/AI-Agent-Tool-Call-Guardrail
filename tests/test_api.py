"""API tests: status codes, auth, audit log contents, fail-closed behaviour."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from guardrail.audit import AuditLogger
from guardrail.main import MAX_BODY_BYTES, create_app

ROOT = Path(__file__).resolve().parent.parent
POLICY = str(ROOT / "policy.yaml")
KEY = "k" * 32
SECRET = "s3cr3t-argument-value"


def body(tool: str = "run_sql", args: dict | None = None, url: str = "https://api.example.com/x") -> dict:
    return {"agent_id": "agent-1", "tool_name": tool, "arguments": args or {}, "target_url": url}


def audit_records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


@pytest.fixture
def audit_path(tmp_path: Path) -> Path:
    return tmp_path / "logs" / "audit.jsonl"


@pytest.fixture
def client(audit_path: Path):
    app = create_app(policy_path=POLICY, audit_path=str(audit_path), api_key=KEY)
    with TestClient(app, headers={"x-api-key": KEY}) as c:
        yield c


# --------------------------------------------------------------------------- #
# Status codes
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("payload", "status", "decision"),
    [
        pytest.param(body(args={"q": "SELECT 1"}), 200, "allow", id="allow"),
        pytest.param(body(args={"q": "dElEtE from t"}), 403, "block", id="obfuscated-sql"),
        pytest.param(body(args={"q": {"deep": ["%44ROP TABLE t"]}}), 403, "block", id="nested-encoded-sql"),
        pytest.param(body("http_request", url="https://api.example.com.evil.com/"), 403, "block", id="lookalike"),
        pytest.param(body("rm_rf"), 403, "block", id="unknown-tool"),
        pytest.param(body("send_email", {"to": "a@b.co"}), 202, "require_approval", id="needs-approval"),
    ],
)
def test_status_codes(client, payload, status, decision):
    response = client.post("/v1/evaluate", json=payload)
    assert response.status_code == status
    data = response.json()
    assert data["decision"] == decision
    assert data["allowed"] is (decision == "allow")
    assert (data["approval_id"] is not None) is (decision == "require_approval")


# --------------------------------------------------------------------------- #
# Audit log
# --------------------------------------------------------------------------- #


def test_audit_record_per_decision_without_arguments(client, audit_path):
    client.post("/v1/evaluate", json=body(args={"q": "SELECT 1", "token": SECRET}))
    client.post("/v1/evaluate", json=body(args={"q": "delete from t"}))
    records = audit_records(audit_path)
    assert [r["decision"] for r in records] == ["allow", "block"]
    assert set(records[0]) == {
        "timestamp", "request_id", "agent_id", "tool_name", "decision", "matched_rules", "reason", "fail_closed",
    }
    assert records[1]["matched_rules"] == ["block-destructive-sql", "allow-basic-tools"]
    assert SECRET not in audit_path.read_text()


def test_audit_file_is_owner_only(client, audit_path):
    assert audit_path.stat().st_mode & 0o077 == 0


# --------------------------------------------------------------------------- #
# Malformed input
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({"agent_id": "a"}, id="missing-fields"),
        pytest.param({**body(), "extra": 1}, id="unknown-field"),
        pytest.param(body(url="https://user:hunter2-secret@api.example.com/"), id="credentials-in-url"),
        pytest.param(body(url="https://api.example.com\\@evil.com/"), id="backslash-url"),
    ],
)
def test_invalid_payload_is_422_logged_and_not_echoed(client, audit_path, payload):
    response = client.post("/v1/evaluate", json=payload)
    assert response.status_code == 422
    assert "hunter2-secret" not in response.text
    (record,) = audit_records(audit_path)
    assert record["decision"] == "block" and record["fail_closed"] is True


def test_non_json_body_is_422(client):
    response = client.post("/v1/evaluate", content=b"not json", headers={"content-type": "application/json"})
    assert response.status_code == 422


def test_oversized_body_is_413(client):
    response = client.post(
        "/v1/evaluate", content=b"x" * (MAX_BODY_BYTES + 1), headers={"content-type": "application/json"}
    )
    assert response.status_code == 413


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("headers", [{}, {"x-api-key": "wrong" * 8}, {"x-api-key": ""}])
def test_missing_or_wrong_key_is_401_and_not_audited(audit_path, headers):
    app = create_app(policy_path=POLICY, audit_path=str(audit_path), api_key=KEY)
    with TestClient(app) as anonymous:
        assert anonymous.post("/v1/evaluate", json=body(), headers=headers).status_code == 401
        # malformed payloads must not let unauthenticated callers write audit records either
        assert anonymous.post("/v1/evaluate", json={"bad": 1}, headers=headers).status_code == 401
    assert audit_path.read_text() == ""


def test_refuses_to_start_without_key(monkeypatch, tmp_path):
    monkeypatch.delenv("GUARDRAIL_API_KEY", raising=False)
    monkeypatch.delenv("GUARDRAIL_ALLOW_UNAUTHENTICATED", raising=False)
    app = create_app(policy_path=POLICY, audit_path=str(tmp_path / "a.jsonl"))
    with pytest.raises(RuntimeError, match="GUARDRAIL_API_KEY"):
        with TestClient(app):
            pass


def test_refuses_weak_key(tmp_path):
    app = create_app(policy_path=POLICY, audit_path=str(tmp_path / "a.jsonl"), api_key="short")
    with pytest.raises(RuntimeError, match="at least"):
        with TestClient(app):
            pass


def test_auth_can_be_disabled_explicitly_for_dev(tmp_path):
    app = create_app(policy_path=POLICY, audit_path=str(tmp_path / "a.jsonl"), allow_unauthenticated=True)
    with TestClient(app) as c:
        assert c.post("/v1/evaluate", json=body(args={"q": "SELECT 1"})).status_code == 200


# --------------------------------------------------------------------------- #
# Fail-closed behaviour
# --------------------------------------------------------------------------- #


def test_audit_failure_turns_allow_into_block(client, monkeypatch):
    def boom(self, decision):
        raise OSError("disk full")

    monkeypatch.setattr(AuditLogger, "log_decision", boom)
    allowed = client.post("/v1/evaluate", json=body(args={"q": "SELECT 1"}))
    approval = client.post("/v1/evaluate", json=body("send_email"))
    for response in (allowed, approval):
        assert response.status_code == 403
        data = response.json()
        assert data["decision"] == "block" and data["fail_closed"] and data["approval_id"] is None


def test_missing_policy_blocks_everything_and_healthz_reports_it(tmp_path):
    app = create_app(policy_path=str(tmp_path / "nope.yaml"), audit_path=str(tmp_path / "a.jsonl"), api_key=KEY)
    with TestClient(app, headers={"x-api-key": KEY}) as c:
        assert c.post("/v1/evaluate", json=body(args={"q": "SELECT 1"})).status_code == 403
        assert c.get("/healthz").status_code == 503


def test_healthz_ok_with_policy(client):
    assert client.get("/healthz").status_code == 200
