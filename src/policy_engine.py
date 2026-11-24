"""Policy engine: loads policy.yaml and evaluates a ToolCallRequest.

Evaluation in plain English:
  1. No valid policy loaded?              -> BLOCK (fail-closed)
  2. Tool name not mentioned in policy?   -> BLOCK (fail-closed)
  3. Target host not in allowed_domains?  -> BLOCK (global egress allowlist)
  4. Decode + normalise every string in the arguments (see "Inspection").
     Anything too big, too deep or too heavily encoded -> BLOCK (fail-closed).
  5. Collect every rule that names this tool AND whose conditions match.
  6. No rule matched?                     -> policy.default_action (block/approval)
  7. Otherwise the MOST RESTRICTIVE matched action wins
     (BLOCK > REQUIRE_APPROVAL > ALLOW).
  8. Any unexpected exception anywhere    -> BLOCK (fail-closed)

Inspection: attackers hide payloads from keyword matching, so each string is
matched in several forms: Unicode-folded (fullwidth, accents, zero-width and
lookalike characters), comment-stripped and comment-unwrapped, plus decoded
from percent-encoding, HTML entities, \\uXXXX escapes, base64 and hex, repeated
up to MAX_DECODE_ROUNDS layers. Strings that parse as JSON are walked as JSON.
Text is never *executed* or forwarded in decoded form; decoding is only for matching.

This is defence in depth, not a proof: a blocklist cannot be complete (see README).
"""

import base64
import html
import json
import logging
import re
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote
from uuid import uuid4

import yaml
from pydantic import ValidationError

from .schemas import (
    ACTION_SEVERITY,
    Action,
    GuardrailDecision,
    PolicyFile,
    PolicyRule,
    RegexMatcher,
    SqlKeywordMatcher,
    ToolCallRequest,
)

logger = logging.getLogger(__name__)

# --- Resource limits: exceeding any of them blocks the request (fail-closed) --- #
MAX_POLICY_BYTES = 256 * 1024
MAX_ARGUMENT_DEPTH = 20
MAX_NODES = 10_000
MAX_STRING_CHARS = 65_536
MAX_SOURCE_CHARS = 262_144  # total characters across all argument strings
MAX_EXPANDED_CHARS = 2_097_152  # total characters across all decoded/normalised variants
MAX_DECODE_ROUNDS = 3  # a 4th layer of encoding is treated as hostile
MAX_VARIANTS_PER_STRING = 256


class InspectionLimitError(Exception):
    """Arguments are too large, too deep or too heavily encoded to inspect safely."""


# --------------------------------------------------------------------------- #
# Loading (strict, safe YAML)
# --------------------------------------------------------------------------- #


class PolicyLoadError(Exception):
    """Raised when policy.yaml is missing, unparseable, or invalid."""


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys (PyYAML silently keeps the last one)."""

    def construct_mapping(self, node, deep=False):  # noqa: ANN001, ANN201
        if isinstance(node, yaml.MappingNode):
            seen: set[object] = set()
            for key_node, _value_node in node.value:
                key = self.construct_object(key_node, deep=True)
                if key in seen:
                    raise yaml.constructor.ConstructorError(
                        None, None, f"duplicate key {key!r}", key_node.start_mark
                    )
                seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _parse_policy_yaml(text: str) -> object:
    # Anchors/aliases are never needed in a policy and enable "billion laughs"
    # memory/CPU bombs, so refuse them before anything is constructed.
    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        if getattr(event, "anchor", None) is not None or isinstance(event, yaml.AliasEvent):
            raise PolicyLoadError("YAML anchors and aliases are not allowed in policies")
    return yaml.load(text, Loader=_StrictLoader)  # noqa: S506  # nosec B506 - SafeLoader subclass


def load_policy(path: str | Path) -> PolicyFile:
    """Read and validate a YAML policy. Any problem at all raises PolicyLoadError."""
    try:
        path = Path(path)
        if path.stat().st_size > MAX_POLICY_BYTES:
            raise PolicyLoadError(f"policy {path} is larger than {MAX_POLICY_BYTES} bytes")
        raw = _parse_policy_yaml(path.read_bytes().decode("utf-8"))
        if not isinstance(raw, dict):
            raise PolicyLoadError(f"policy {path} is empty or not a YAML mapping")
        return PolicyFile.model_validate(raw)
    except PolicyLoadError:
        raise
    except ValidationError as exc:
        raise PolicyLoadError(f"policy {path} is invalid: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 - parser/IO/recursion errors: every failure must fail closed
        raise PolicyLoadError(f"cannot load policy {path}: {type(exc).__name__}: {exc}") from exc


# --------------------------------------------------------------------------- #
# Text normalisation and decoding (matching only; never forwarded)
# --------------------------------------------------------------------------- #

_SQL_COMMENT_RE = re.compile(r"/\*.*?\*/|--[^\n]*", re.DOTALL)
_COMMENT_DELIMS_RE = re.compile(r"/\*[!+]?\d*|\*/")  # unwraps MySQL "/*!50000DELETE*/"
_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})")
_B64_RE = re.compile(r"[A-Za-z0-9+/_-]{8,}={0,2}")
_HEX_RE = re.compile(r"(?:0x)?((?:[0-9a-fA-F]{2}){4,})")
_DROPPED_CATEGORIES = {"Cf", "Mn", "Me"}  # invisible/format chars, combining marks

# Lookalike letters NFKD does not fold: Cyrillic, Greek, Latin small capitals.
_CONFUSABLE_SRC = (
    "АВЕКМНОРСТХІЈЅУаеорсхуіјѕԁӏ"  # Cyrillic
    "ΑΒΕΖΗΙΚΜΝΟΡΤΥΧοινκρ"  # Greek
    "ᴀʙᴄᴅᴇꜰɢʜɪᴊᴋʟᴍɴᴏᴘʀꜱᴛᴜᴠᴡʏᴢ"  # small capitals
)
_CONFUSABLE_DST = "ABEKMHOPCTXIJSYaeopcxyijsdl" "ABEZHIKMNOPTYXoivkp" "abcdefghijklmnoprstuvwyz"
assert len(_CONFUSABLE_SRC) == len(_CONFUSABLE_DST)
_CONFUSABLES = str.maketrans(_CONFUSABLE_SRC, _CONFUSABLE_DST)


def _fold(text: str) -> str:
    """Collapse cheap Unicode obfuscation to plain ASCII-ish text."""
    if text.isascii():
        return text
    text = unicodedata.normalize("NFKD", text)  # fullwidth, ligatures, accents -> base letters + marks
    text = "".join(ch for ch in text if unicodedata.category(ch) not in _DROPPED_CATEGORIES)
    return text.translate(_CONFUSABLES)


def _printable(text: str) -> bool:
    return all(ch.isprintable() or ch in "\t\r\n" for ch in text)


def _decode_escapes(text: str) -> str:
    return _ESCAPE_RE.sub(lambda m: chr(int(m.group(1) or m.group(2), 16)), text)


def _decode_base64_tokens(text: str) -> Iterator[str]:
    for token in _B64_RE.findall(text):
        body = token.rstrip("=").replace("-", "+").replace("_", "/")
        try:
            decoded = base64.b64decode(body + "=" * (-len(body) % 4), validate=True).decode("utf-8")
        except ValueError:  # binascii.Error and UnicodeDecodeError are both ValueErrors
            continue
        if _printable(decoded):
            yield decoded


def _decode_hex_tokens(text: str) -> Iterator[str]:
    for match in _HEX_RE.finditer(text):
        try:
            decoded = bytes.fromhex(match.group(1)).decode("utf-8")
        except ValueError:
            continue
        if _printable(decoded):
            yield decoded


def _decoded_forms(text: str) -> Iterator[str]:
    yield unquote(text)
    yield html.unescape(text)
    yield _decode_escapes(text)
    yield from _decode_base64_tokens(text)
    yield from _decode_hex_tokens(text)


class _Budget:
    """Per-request resource accounting shared by everything that inspects the arguments."""

    def __init__(self) -> None:
        self.nodes = 0
        self.source_chars = 0
        self.expanded_chars = 0

    def node(self) -> None:
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise InspectionLimitError("too many argument values")

    def source(self, size: int) -> None:
        self.source_chars += size
        if self.source_chars > MAX_SOURCE_CHARS:
            raise InspectionLimitError("arguments too large")

    def expanded(self, size: int) -> None:
        self.expanded_chars += size
        if self.expanded_chars > MAX_EXPANDED_CHARS:
            raise InspectionLimitError("decoded arguments too large")


def _variants(text: str, budget: _Budget) -> list[str]:
    """Every form of `text` that a downstream tool might end up interpreting."""
    results: dict[str, None] = {}
    frontier = [text]
    depth = 0
    while frontier:
        if depth > MAX_DECODE_ROUNDS:
            raise InspectionLimitError("too many nested encodings")
        next_frontier: dict[str, None] = {}
        for item in frontier:
            folded = _fold(item)
            for form in (folded, _SQL_COMMENT_RE.sub(" ", folded), _COMMENT_DELIMS_RE.sub(" ", folded)):
                if form not in results:
                    budget.expanded(len(form))
                    results[form] = None
            if len(results) > MAX_VARIANTS_PER_STRING:
                raise InspectionLimitError("too many encoded variants")
            for decoded in _decoded_forms(folded):
                if decoded != folded:
                    next_frontier[decoded] = None
        frontier = list(next_frontier)
        depth += 1
    return list(results)


@dataclass(frozen=True)
class _Inspectable:
    """All matchable text for one request, computed once and shared by every rule."""

    all_texts: tuple[str, ...]
    by_argument: dict[str, tuple[str, ...]]


def _walk(value: object, out: list[str], budget: _Budget, depth: int) -> None:
    if depth > MAX_ARGUMENT_DEPTH:
        raise InspectionLimitError("arguments nested too deeply")
    budget.node()
    if isinstance(value, str):
        if len(value) > MAX_STRING_CHARS:
            raise InspectionLimitError("argument string too long")
        budget.source(len(value))
        out.extend(_variants(value, budget))
        if value.lstrip()[:1] in ("{", "[", '"'):  # JSON hidden inside a string: parse and walk it
            try:
                parsed = json.loads(value)
            except ValueError:
                return
            _walk(parsed, out, budget, depth + 1)  # RecursionError propagates -> blocked
    elif isinstance(value, list):
        for item in value:
            _walk(item, out, budget, depth + 1)
    elif isinstance(value, dict):
        for key, item in value.items():
            _walk(key, out, budget, depth + 1)
            _walk(item, out, budget, depth + 1)


def _inspect(arguments: dict) -> _Inspectable:
    budget = _Budget()
    by_argument: dict[str, tuple[str, ...]] = {}
    for key, value in arguments.items():
        texts: list[str] = []
        _walk(key, texts, budget, 1)
        _walk(value, texts, budget, 1)
        by_argument[key] = tuple(texts)
    return _Inspectable(tuple(t for texts in by_argument.values() for t in texts), by_argument)


# --------------------------------------------------------------------------- #
# Matching helpers (small, single-purpose)
# --------------------------------------------------------------------------- #


def _texts_for(found: _Inspectable, argument: str | None) -> tuple[str, ...]:
    return found.all_texts if argument is None else found.by_argument.get(argument, ())


def _regex_matches(matcher: RegexMatcher, found: _Inspectable) -> bool:
    pattern = re.compile(matcher.pattern, re.IGNORECASE if matcher.ignore_case else 0)
    return any(pattern.search(text) for text in _texts_for(found, matcher.argument))


def _sql_keyword_matches(matcher: SqlKeywordMatcher, found: _Inspectable) -> bool:
    """Whole-word, case-insensitive. 'DROP TABLE' tolerates any whitespace between words."""
    patterns = [
        re.compile(r"\b" + r"\s+".join(re.escape(w) for w in kw.split()) + r"\b", re.IGNORECASE)
        for kw in matcher.keywords
    ]
    return any(p.search(text) for text in _texts_for(found, matcher.argument) for p in patterns)


def _domain_matches(patterns: list[str], host: str) -> bool:
    """'example.com' matches exactly; '*.example.com' matches subdomains only."""
    for pattern in patterns:
        if pattern.startswith("*."):
            if host.endswith(pattern[1:]):  # pattern[1:] == ".example.com"
                return True
        elif host == pattern:
            return True
    return False


def _target_host(request: ToolCallRequest) -> str:
    host = request.target_url.host
    if not host:
        raise ValueError("target_url has no host")
    return host.lower().rstrip(".")


def _rule_matches(rule: PolicyRule, request: ToolCallRequest, found: _Inspectable) -> bool:
    """Does this rule's tool list AND conditions match the request?"""
    if "*" not in rule.tool_names and request.tool_name not in rule.tool_names:
        return False

    cond = rule.conditions
    results: list[bool] = []
    if cond.regex:
        results.append(any(_regex_matches(m, found) for m in cond.regex))
    if cond.sql_keywords:
        results.append(any(_sql_keyword_matches(m, found) for m in cond.sql_keywords))
    if cond.domains:
        results.append(_domain_matches(cond.domains, _target_host(request)))

    if not results:  # no conditions: the rule applies to the tool by name alone
        return True
    return all(results) if cond.mode == "all" else any(results)


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #


class PolicyEngine:
    """Evaluates tool calls against a policy. `evaluate` never raises."""

    def __init__(self, policy: PolicyFile | None) -> None:
        self._policy = policy
        self._known_tools: set[str] = (
            {tool for rule in policy.rules for tool in rule.tool_names if tool != "*"} if policy else set()
        )

    @property
    def policy_loaded(self) -> bool:
        return self._policy is not None

    @classmethod
    def from_yaml(cls, path: str | Path = "policy.yaml") -> "PolicyEngine":
        """Load a policy. If loading fails, return an engine that blocks everything."""
        try:
            return cls(load_policy(path))
        except PolicyLoadError:
            logger.exception("policy failed to load; engine will block all requests")
            return cls(None)

    def evaluate(self, request: ToolCallRequest) -> GuardrailDecision:
        try:
            return self._evaluate(request)
        except InspectionLimitError as exc:
            logger.warning("arguments exceeded inspection limits: %s", exc)
            return self._decision(request, Action.BLOCK, f"arguments exceed inspection limits: {exc}", fail_closed=True)
        except Exception:  # noqa: BLE001 - fail-closed on ANY error
            logger.exception("unexpected error evaluating request; blocking")
            return self._decision(request, Action.BLOCK, "internal error during evaluation", fail_closed=True)

    # -- internals ---------------------------------------------------------- #

    def _evaluate(self, request: ToolCallRequest) -> GuardrailDecision:
        policy = self._policy
        if policy is None:
            return self._decision(request, Action.BLOCK, "no valid policy loaded", fail_closed=True)

        if request.tool_name not in self._known_tools:
            return self._decision(
                request, Action.BLOCK, f"unknown tool {request.tool_name!r}", fail_closed=True
            )

        if not _domain_matches(policy.allowed_domains, _target_host(request)):
            return self._decision(request, Action.BLOCK, "target host is not in allowed_domains")

        found = _inspect(request.arguments)
        matched = [rule for rule in policy.rules if _rule_matches(rule, request, found)]
        if not matched:
            return self._decision(
                request, policy.default_action, "no rule matched; default action applied"
            )

        action = max((rule.action for rule in matched), key=ACTION_SEVERITY.__getitem__)
        deciding = [rule.id for rule in matched if rule.action is action]
        return self._decision(
            request,
            action,
            f"{action.value} by rule(s): {', '.join(deciding)}",
            matched_rule_ids=[rule.id for rule in matched],
        )

    @staticmethod
    def _decision(
        request: ToolCallRequest,
        action: Action,
        reason: str,
        matched_rule_ids: list[str] | None = None,
        fail_closed: bool = False,
    ) -> GuardrailDecision:
        return GuardrailDecision(
            decision=action,
            reason=reason[:1000],
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            matched_rule_ids=matched_rule_ids or [],
            fail_closed=fail_closed,
            approval_id=uuid4() if action is Action.REQUIRE_APPROVAL else None,
        )
