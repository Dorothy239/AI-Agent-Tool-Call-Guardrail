"""FastAPI entrypoint for the tool-call guardrail.

Run:  uvicorn guardrail.main:app

POST /v1/evaluate  ->  200 allow | 202 pending human approval | 403 block
                       401 bad/missing API key | 413 body too large
                       422 malformed payload (treat anything but 200 as "do not run")

Config (env vars):
  GUARDRAIL_API_KEY                 required (>= 16 chars) unless the next flag is set
  GUARDRAIL_ALLOW_UNAUTHENTICATED   "true" disables auth (local development only)
  GUARDRAIL_POLICY_PATH             default: policy.yaml
  GUARDRAIL_AUDIT_LOG               default: logs/audit.jsonl
"""

import asyncio
import hmac
import logging
import os
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .audit import AuditLogger
from .policy_engine import PolicyEngine
from .schemas import Action, GuardrailDecision, ToolCallRequest

logger = logging.getLogger("guardrail")

MAX_BODY_BYTES = 1_048_576
MIN_API_KEY_LENGTH = 16

STATUS_BY_ACTION: dict[Action, int] = {
    Action.ALLOW: 200,
    Action.REQUIRE_APPROVAL: 202,
    Action.BLOCK: 403,
}


def _key_is_valid(request: Request) -> bool:
    expected: str | None = request.app.state.api_key
    if expected is None:  # auth explicitly disabled for local development
        return True
    supplied = request.headers.get("x-api-key", "")
    return hmac.compare_digest(supplied.encode(), expected.encode())  # constant-time


async def require_api_key(request: Request) -> None:
    if not _key_is_valid(request):
        logger.warning("rejected request with missing or invalid API key")
        raise HTTPException(status_code=401, detail="invalid or missing API key")


def create_app(
    policy_path: str | None = None,
    audit_path: str | None = None,
    api_key: str | None = None,
    allow_unauthenticated: bool | None = None,
) -> FastAPI:
    policy_path = policy_path or os.getenv("GUARDRAIL_POLICY_PATH", "policy.yaml")
    audit_path = audit_path or os.getenv("GUARDRAIL_AUDIT_LOG", "logs/audit.jsonl")
    api_key = api_key or os.getenv("GUARDRAIL_API_KEY") or None
    if allow_unauthenticated is None:
        allow_unauthenticated = os.getenv("GUARDRAIL_ALLOW_UNAUTHENTICATED", "").lower() == "true"

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # Refuse to start misconfigured: no key (unless explicitly disabled), a weak
        # key, or an unwritable audit log. A bad POLICY does not stop startup;
        # the engine simply blocks everything.
        if api_key is None and not allow_unauthenticated:
            raise RuntimeError("GUARDRAIL_API_KEY is not set (or set GUARDRAIL_ALLOW_UNAUTHENTICATED=true for dev)")
        if api_key is not None and len(api_key) < MIN_API_KEY_LENGTH:
            raise RuntimeError(f"GUARDRAIL_API_KEY must be at least {MIN_API_KEY_LENGTH} characters")
        app.state.api_key = api_key
        app.state.engine = PolicyEngine.from_yaml(policy_path)
        app.state.audit = AuditLogger(audit_path)
        yield

    app = FastAPI(title="AI Agent Tool-Call Guardrail", version="0.2.0", lifespan=lifespan)

    @app.middleware("http")
    async def limit_body_size(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        # Rejects oversized declared bodies. Chunked uploads carry no length, so also
        # cap request size at your reverse proxy / ingress.
        declared = request.headers.get("content-length")
        if declared is not None:
            try:
                too_big = int(declared) > MAX_BODY_BYTES
            except ValueError:
                too_big = True
            if too_big:
                return JSONResponse({"detail": "request body too large"}, status_code=413)
        return await call_next(request)

    @app.post(
        "/v1/evaluate",
        response_model=GuardrailDecision,
        dependencies=[Depends(require_api_key)],
        responses={
            202: {"description": "Pending human approval", "model": GuardrailDecision},
            403: {"description": "Blocked by policy", "model": GuardrailDecision},
        },
    )
    async def evaluate(payload: ToolCallRequest, request: Request, response: Response) -> GuardrailDecision:
        engine: PolicyEngine = request.app.state.engine
        audit: AuditLogger = request.app.state.audit

        # Evaluation and file I/O are synchronous; keep them off the event loop.
        decision = await asyncio.to_thread(engine.evaluate, payload)

        try:
            await asyncio.to_thread(audit.log_decision, decision)
        except Exception:  # noqa: BLE001
            logger.exception("audit write failed")
            if decision.decision is not Action.BLOCK:
                # Fail-closed: an allow/approval we cannot record must not go through.
                decision = decision.model_copy(
                    update={
                        "decision": Action.BLOCK,
                        "reason": "audit log unavailable",
                        "fail_closed": True,
                        "approval_id": None,
                        "forwarded": False,
                    }
                )

        response.status_code = STATUS_BY_ACTION[decision.decision]
        return decision

    @app.get("/healthz")
    async def healthz(request: Request) -> JSONResponse:
        loaded = request.app.state.engine.policy_loaded
        return JSONResponse({"status": "ok" if loaded else "no_policy"}, status_code=200 if loaded else 503)

    @app.exception_handler(RequestValidationError)
    async def invalid_payload(request: Request, exc: RequestValidationError) -> JSONResponse:
        # FastAPI parses the body before running dependencies, so check the key here too:
        # unauthenticated callers must not be able to write audit records.
        if not _key_is_valid(request):
            return JSONResponse({"detail": "invalid or missing API key"}, status_code=401)
        try:
            await asyncio.to_thread(request.app.state.audit.log_invalid_request)
        except Exception:  # noqa: BLE001
            logger.exception("audit write failed for invalid request")
        # Report where/why it failed, but never echo the submitted values back.
        errors = [{"loc": list(e["loc"]), "msg": e["msg"]} for e in exc.errors()]
        return JSONResponse({"detail": errors}, status_code=422)

    return app


app = create_app()
