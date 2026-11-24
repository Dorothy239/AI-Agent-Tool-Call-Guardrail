"""Pydantic v2 schemas for the AI Agent Tool-Call Guardrail.

Three groups of models:
  1. ToolCallRequest   - incoming payload from an agent
  2. PolicyRule/File   - YAML policy definitions (validated at load time)
  3. GuardrailDecision - response returned (and audited) for every request

Design notes (fail-closed):
  * Every model forbids unknown fields, so typos in YAML or payloads are
    rejected instead of silently ignored.
  * Regexes are compiled AND analysed for catastrophic backtracking while the
    policy loads, so a bad policy fails at load time, never at request time.
  * `default_action` can never be ALLOW. ALLOW rules must name specific tools
    and may only use `domains` conditions (pattern-based allow is bypassable).
  * `target_url` is parsed strictly: anything a different URL parser could
    read differently (backslashes, credentials, %-encoded hosts, whitespace)
    is rejected outright.
  * Intended evaluation semantics: deny-overrides. If several rules match, the
    most restrictive action wins (BLOCK > REQUIRE_APPROVAL > ALLOW).
"""

import re
import re._constants as _sre_const
import re._parser as _sre_parse
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID, uuid4

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    JsonValue,
    StringConstraints,
    computed_field,
    field_validator,
    model_validator,
)

# --------------------------------------------------------------------------- #
# Shared types / base config
# --------------------------------------------------------------------------- #

Identifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:\-/]*$",
    ),
]

ToolSelector = Identifier | Literal["*"]

_DOMAIN_RE = re.compile(r"^(\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_SQL_KEYWORD_RE = re.compile(r"^[A-Za-z_]+(?: [A-Za-z_]+)*$")


def _normalise_domain(value: str) -> str:
    value = value.strip().lower()
    if not _DOMAIN_RE.fullmatch(value):
        raise ValueError(f"invalid domain {value!r}: use 'example.com' or '*.example.com' (no scheme/path/port)")
    return value


DomainPattern = Annotated[str, AfterValidator(_normalise_domain)]


class _StrictModel(BaseModel):
    """Base: reject unknown fields, trim strings, immutable after validation."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class Action(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


# Higher number = more restrictive. Used by the evaluator for deny-overrides.
ACTION_SEVERITY: dict[Action, int] = {
    Action.ALLOW: 0,
    Action.REQUIRE_APPROVAL: 1,
    Action.BLOCK: 2,
}


# --------------------------------------------------------------------------- #
# 1) Incoming tool-call request
# --------------------------------------------------------------------------- #

# Whitespace, control characters and backslashes are where URL parsers disagree
# (WHATWG treats "\" like "/", urllib does not, some strip \t\n silently).
_URL_BAD_CHARS = re.compile(r"[\x00-\x20\x7f\\]")
_URL_AUTHORITY = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://([^/?#]*)")


class ToolCallRequest(_StrictModel):
    """A tool call an agent wants to make, intercepted by the guardrail."""

    agent_id: Identifier = Field(description="Stable identifier of the calling agent.")
    tool_name: Identifier = Field(description="Name of the tool being invoked.")
    arguments: dict[str, JsonValue] = Field(
        default_factory=dict,
        description="Tool arguments; any JSON-serialisable structure.",
    )
    target_url: HttpUrl = Field(description="Downstream URL the call will be forwarded to.")

    @field_validator("target_url", mode="before")
    @classmethod
    def _reject_ambiguous_url(cls, value: object) -> str:
        raw = str(value)
        if _URL_BAD_CHARS.search(raw):
            raise ValueError("target_url must not contain whitespace, control characters or backslashes")
        match = _URL_AUTHORITY.match(raw)
        if match is None:
            raise ValueError("target_url must be an absolute http(s) URL")
        authority = match.group(1)
        if "@" in authority or "%" in authority:
            raise ValueError("target_url must not contain credentials or percent-encoding in the host")
        return raw


# --------------------------------------------------------------------------- #
# 2) YAML policy rules
# --------------------------------------------------------------------------- #

_REPEATS = (_sre_const.MAX_REPEAT, _sre_const.MIN_REPEAT)


def _has_catastrophic_backtracking(items, inside_unbounded: bool = False) -> bool:  # noqa: ANN001
    """True for an unbounded repeat that contains another repeat or an alternation.

    Catches the classic ReDoS shapes such as (a+)+, (a*)*, (a|aa)+ and (\\d+\\s*)*.
    Deliberately conservative: it may reject some harmless patterns.
    """
    for op, av in items:
        if op in _REPEATS:
            _low, high, body = av
            if inside_unbounded and high > 1:
                return True
            if _has_catastrophic_backtracking(body, inside_unbounded or high == _sre_const.MAXREPEAT):
                return True
        elif op is _sre_const.BRANCH:
            if inside_unbounded:
                return True
            if any(_has_catastrophic_backtracking(branch, inside_unbounded) for branch in av[1]):
                return True
        else:
            sub = None
            if op is _sre_const.SUBPATTERN:
                sub = av[3]
            elif op in (_sre_const.ASSERT, _sre_const.ASSERT_NOT):
                sub = av[1]
            elif op is _sre_const.ATOMIC_GROUP:
                sub = av
            if sub is not None and _has_catastrophic_backtracking(sub, inside_unbounded):
                return True
    return False


class RegexMatcher(_StrictModel):
    """Match a regex against argument values (after decoding and normalisation)."""

    pattern: str = Field(min_length=1, max_length=512)
    argument: str | None = Field(
        default=None,
        description="Top-level argument key to inspect. None = all string values (recursive). "
        "Prefer None: a named key is easy to dodge by putting the payload under another key.",
    )
    ignore_case: bool = True

    @field_validator("pattern")
    @classmethod
    def _valid_and_safe(cls, v: str) -> str:
        try:
            re.compile(v)
            parsed = _sre_parse.parse(v)
            risky = _has_catastrophic_backtracking(parsed)
        except (re.error, RecursionError) as exc:
            raise ValueError(f"invalid regex {v!r}: {exc}") from exc
        if risky:
            raise ValueError(
                f"regex {v!r} risks catastrophic backtracking (nested unbounded repeat or alternation "
                "under a repeat); rewrite it"
            )
        return v


class SqlKeywordMatcher(_StrictModel):
    """Match whole-word SQL keywords/phrases (e.g. 'DROP TABLE') in argument values."""

    keywords: list[str] = Field(min_length=1, max_length=64)
    argument: str | None = Field(
        default=None,
        description="Top-level argument key to inspect. None = all string values (recursive).",
    )

    @field_validator("keywords")
    @classmethod
    def _normalise(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for kw in v:
            kw = " ".join(kw.split()).upper()
            if not _SQL_KEYWORD_RE.fullmatch(kw):
                raise ValueError(f"invalid SQL keyword {kw!r}: letters, underscores and single spaces only")
            out.append(kw)
        return out


class RuleConditions(_StrictModel):
    """Conditions a request must satisfy for a rule to fire."""

    regex: list[RegexMatcher] = Field(default_factory=list)
    sql_keywords: list[SqlKeywordMatcher] = Field(default_factory=list)
    domains: list[DomainPattern] = Field(
        default_factory=list,
        description="Hostnames matched against target_url. 'example.com' = exact, '*.example.com' = subdomains.",
    )
    mode: Literal["any", "all"] = Field(
        default="any",
        description="'any': one matching condition fires the rule. 'all': every non-empty condition type must match.",
    )

    @property
    def is_empty(self) -> bool:
        return not (self.regex or self.sql_keywords or self.domains)


class PolicyRule(_StrictModel):
    """One rule: for these tools, when conditions match, apply this action."""

    id: Identifier
    description: str = Field(default="", max_length=500)
    action: Action
    tool_names: list[ToolSelector] = Field(
        min_length=1,
        description="Tools this rule applies to. Use ['*'] for all tools (not permitted for allow rules).",
    )
    conditions: RuleConditions = Field(default_factory=RuleConditions)

    @model_validator(mode="after")
    def _allow_rules_are_narrow(self) -> "PolicyRule":
        if self.action is Action.ALLOW:
            if "*" in self.tool_names:
                raise ValueError(f"rule {self.id!r}: allow rules must name specific tools, not '*'")
            if self.conditions.regex or self.conditions.sql_keywords:
                raise ValueError(
                    f"rule {self.id!r}: allow rules may only use 'domains' conditions; "
                    "pattern-based allow can be bypassed by encoding tricks"
                )
        return self


class PolicyFile(_StrictModel):
    """Top-level YAML document."""

    version: Literal[1] = 1
    default_action: Action = Field(
        default=Action.BLOCK,
        description="Applied when no rule matches (known tools, unmatched calls).",
    )
    allowed_domains: list[DomainPattern] = Field(
        min_length=1,
        max_length=200,
        description="Global egress allowlist: a request whose target host is not listed here is blocked, "
        "whatever the tool. Required, so an incomplete policy fails closed.",
    )
    rules: list[PolicyRule] = Field(default_factory=list, max_length=500)

    @field_validator("default_action")
    @classmethod
    def _default_never_allow(cls, v: Action) -> Action:
        if v is Action.ALLOW:
            raise ValueError("default_action must be 'block' or 'require_approval' (fail-closed)")
        return v

    @model_validator(mode="after")
    def _unique_rule_ids(self) -> "PolicyFile":
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                raise ValueError(f"duplicate rule id {rule.id!r}")
            seen.add(rule.id)
        return self


# --------------------------------------------------------------------------- #
# 3) Guardrail decision response
# --------------------------------------------------------------------------- #


class GuardrailDecision(_StrictModel):
    """Result of evaluating a ToolCallRequest. Returned to the caller and audited."""

    request_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    decision: Action
    reason: str = Field(max_length=1000)
    agent_id: str
    tool_name: str
    matched_rule_ids: list[str] = Field(default_factory=list)
    fail_closed: bool = Field(
        default=False,
        description="True when the decision came from an error path (bad policy, unknown tool, limits, exception).",
    )
    approval_id: UUID | None = Field(
        default=None,
        description="Set only when decision == require_approval.",
    )
    forwarded: bool = Field(
        default=False,
        description="True only if the call was allowed and actually sent downstream.",
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def allowed(self) -> bool:
        return self.decision is Action.ALLOW

    @model_validator(mode="after")
    def _consistency(self) -> "GuardrailDecision":
        if self.forwarded and self.decision is not Action.ALLOW:
            raise ValueError("only allowed calls can be forwarded")
        if self.approval_id is not None and self.decision is not Action.REQUIRE_APPROVAL:
            raise ValueError("approval_id is only valid for require_approval decisions")
        return self
