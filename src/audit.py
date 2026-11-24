"""Append-only JSONL audit log: one JSON object per line, one line per decision.

Tool `arguments` are deliberately NOT logged; they may contain secrets or PII.
The file is created owner-only (0600). Rotate it externally (logrotate or the
container runtime): if the disk fills, writes fail and requests are blocked.
"""

import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from .schemas import GuardrailDecision


class AuditLogger:
    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.touch(mode=0o600, exist_ok=True)  # raises if unwritable -> app won't start
        self._lock = threading.Lock()

    def log_decision(self, decision: GuardrailDecision) -> None:
        self._append(
            {
                "timestamp": decision.timestamp.isoformat(),
                "request_id": str(decision.request_id),
                "agent_id": decision.agent_id,
                "tool_name": decision.tool_name,
                "decision": decision.decision.value,
                "matched_rules": decision.matched_rule_ids,
                "reason": decision.reason,
                "fail_closed": decision.fail_closed,
            }
        )

    def log_invalid_request(self) -> None:
        """A payload that failed schema validation is recorded as a fail-closed block."""
        self._append(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "request_id": str(uuid4()),
                "agent_id": None,
                "tool_name": None,
                "decision": "block",
                "matched_rules": [],
                "reason": "invalid request payload",
                "fail_closed": True,
            }
        )

    def _append(self, record: dict[str, object]) -> None:
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=True)  # one line, newlines escaped
        with self._lock, self._path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
