#!/usr/bin/env python3
"""Validate the sprut-contracts repository.

Python 3 standard library only. Run from any directory:

    python3 tools/validate.py              # validate the repository
    python3 tools/validate.py --self-test  # prove the checks catch known-bad changes

Checks:
  * every JSON file in the repo is strict UTF-8 JSON without duplicate keys;
  * JSON Schemas use only the keyword subset this validator implements and
    every local $ref resolves;
  * registries (reason codes, exit codes, state machines) against their
    schemas and cross-file rules (uniqueness, exit-code mapping and
    resolution rules, platforms, coverage of the spec lists);
  * state-machine integrity (states exist, initial/terminal valid,
    reachability, no dead ends) and structural safety invariants taken from
    the spec (READY only after SMOKE_TEST, INSTALLING only after consent,
    re-verification after restart, ...);
  * canonical JSON test vectors (RFC 8785 / JCS subset, see
    docs/canonical-json.md), recomputed from scratch;
  * state-transition, exit-code resolution and OperationEvent test vectors.

Exits 0 when everything passes, 1 otherwise. Every failure is printed as
"FAIL <file>: <message>".
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import math
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

UPPER_SNAKE = re.compile(r"^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$")
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$")
PLATFORMS = ("windows", "linux")
DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"

P_STATE_MACHINES = "registry/state-machines.json"
P_REASON_CODES = "registry/reason-codes.json"
P_EXIT_CODES = "registry/exit-codes.json"
P_EVENT_SCHEMA = "schemas/operation-event.schema.json"
P_EVENT_VECTORS = "test-vectors/operation-events/events.json"
P_EXIT_VECTORS = "test-vectors/exit-codes/resolution.json"
D_CANONICAL = "test-vectors/canonical-json/"
D_CANONICAL_INVALID = "test-vectors/canonical-json-invalid/"
D_TRANSITIONS = "test-vectors/state-transitions/"
D_GUARDS = "test-vectors/guards/"

# Lists copied from the specification; the registry must contain all of them.
# SPRUT-CLIENT-SPECIFICATION.md v1.1, section 8.3.
SPEC_CLIENT_REASON_CODES = [
    "UNSUPPORTED_PROFILE", "ENGINE_CLI_MISSING", "ENGINE_DAEMON_STOPPED",
    "ENGINE_PERMISSION_DENIED", "ENGINE_REMOTE_CONTEXT", "ENGINE_WRONG_MODE",
    "VIRTUALIZATION_DISABLED", "WSL_MISSING", "WSL_OUTDATED", "WSL_POLICY_BLOCKED",
    "WSL_DISTRO_BROKEN", "WSL_RESTART_REQUIRED", "WSL_CONFIG_CONFLICT",
    "WSL_RESOURCES_INSUFFICIENT", "INSUFFICIENT_DISK", "SOURCE_UNAVAILABLE",
    "INTEGRITY_MISMATCH", "CONSENT_REQUIRED", "PRIVILEGE_REQUIRED", "REBOOT_REQUIRED",
    "RELOGIN_REQUIRED", "PLAN_STALE", "IMAGE_NOT_ALLOWED", "MANIFEST_POLICY_VIOLATION",
    "SMOKE_TEST_FAILED", "CUDA_UNAVAILABLE", "DEVICE_UNAVAILABLE", "MEMORY_BUDGET",
    "MODEL_INTEGRITY_FAILED", "MODEL_IN_USE", "MODEL_FORMAT_UNSUPPORTED",
    "MODEL_ARCH_UNSUPPORTED", "MODEL_REMOTE_CODE_REQUIRED", "MODEL_TEMPLATE_MISSING",
    "MODEL_SOURCE_AUTH_REQUIRED", "MODEL_NOT_ALLOWED_IN_MODE", "PROFILE_LOCKED",
    "DRAIN_TIMEOUT", "AUTH_REJECTED", "VERSION_MISMATCH", "COORDINATOR_UNREACHABLE",
]
# technical-plan/03-CONTRACTS.md, section 7.
SPEC_CONTRACT_REASON_CODES = [
    "AUTH_REJECTED", "VERSION_MISMATCH", "DATA_HASH_MISMATCH", "MEMORY_BUDGET",
    "PEER_UNREACHABLE", "PROFILE_EXPIRED", "PLAN_CONFLICT", "COUNT_MISMATCH",
    "NONFINITE_GRADIENT", "COLLECTIVE_TIMEOUT", "CHECKPOINT_INCOMPLETE", "STALE_ATTEMPT",
]

# Structural rules derived from the specification. Rule kinds:
#   required_edges: transitions that must exist;
#   preds_equal / preds_subset: allowed predecessors of a state;
#   succ_subset: allowed successors of a state ("terminal" = every terminal state);
#   must_pass: (start, target, via) - every path start -> target goes through via;
#   must_pass_guarded: the same on the graph without transitions whose guards need consent
#       (consent only exists after WAITING_FOR_CONSENT and is cleared on entering PROBING,
#       so a path that avoids WAITING_FOR_CONSENT can never satisfy such a guard);
#   restart_to: every other state has a transition to this state (resume re-verifies);
#   required_guards: transition -> predicates its guard must contain;
#   required_effects: (state, action) pairs that must be declared.
SPEC_MACHINES = {
    "bootstrap": {
        "states": {
            "NEW", "PROBING", "PLAN_READY", "WAITING_FOR_CONSENT", "WAITING_FOR_PRIVILEGE",
            "INSTALLING", "REBOOT_REQUIRED", "ENGINE_CHECK", "IMAGE_PULL", "SMOKE_TEST",
            "READY", "ACTION_REQUIRED", "FAILED", "CANCELLED",
        },
        "required_edges": [
            # CF17 main chain.
            ("NEW", "PROBING"), ("PROBING", "PLAN_READY"), ("PLAN_READY", "WAITING_FOR_CONSENT"),
            ("WAITING_FOR_CONSENT", "INSTALLING"), ("INSTALLING", "REBOOT_REQUIRED"),
            ("INSTALLING", "ENGINE_CHECK"), ("ENGINE_CHECK", "IMAGE_PULL"),
            ("IMAGE_PULL", "SMOKE_TEST"), ("SMOKE_TEST", "READY"),
            # CF15: resume after reboot re-verifies; CF17: config change returns to probing.
            ("REBOOT_REQUIRED", "PROBING"), ("READY", "PROBING"),
            # CF15/CF18: a process or computer restart in any in-flight state re-verifies.
            ("INSTALLING", "PROBING"), ("WAITING_FOR_PRIVILEGE", "PROBING"),
            ("ENGINE_CHECK", "PROBING"), ("IMAGE_PULL", "PROBING"), ("SMOKE_TEST", "PROBING"),
            # SEC-M3: the journal is never trusted to continue, also in PLAN_READY / WAITING_FOR_CONSENT.
            ("PLAN_READY", "PROBING"), ("WAITING_FOR_CONSENT", "PROBING"),
        ],
        "restart_to": "PROBING",
        "preds_equal": {"READY": {"SMOKE_TEST"}},  # CF16
        "preds_subset": {
            "INSTALLING": {"WAITING_FOR_CONSENT", "WAITING_FOR_PRIVILEGE"},  # CF13
            "WAITING_FOR_PRIVILEGE": {"INSTALLING"},
            "ENGINE_CHECK": {"PLAN_READY", "INSTALLING"},  # SEC-M1: consented plans run through INSTALLING
            "IMAGE_PULL": {"ENGINE_CHECK"},
            "SMOKE_TEST": {"ENGINE_CHECK", "IMAGE_PULL"},
        },
        "must_pass_guarded": [
            ("NEW", "IMAGE_PULL", "WAITING_FOR_CONSENT"),      # SEC-M1: the image pull is an action
            ("PROBING", "IMAGE_PULL", "WAITING_FOR_CONSENT"),
            ("NEW", "INSTALLING", "WAITING_FOR_CONSENT"),
            ("PROBING", "INSTALLING", "WAITING_FOR_CONSENT"),
        ],
        "required_guards": {
            ("PLAN_READY", "ENGINE_CHECK"): {"plan_has_no_actions"},
            ("WAITING_FOR_CONSENT", "INSTALLING"): {"consent_matches_plan"},
            ("INSTALLING", "WAITING_FOR_PRIVILEGE"): {"consent_matches_plan", "step_is_privileged_plan_step"},
            ("WAITING_FOR_PRIVILEGE", "INSTALLING"): {"consent_matches_plan", "step_is_privileged_plan_step",
                                                      "privilege_granted"},
            ("ENGINE_CHECK", "IMAGE_PULL"): {"consent_matches_plan", "image_allowlisted", "image_in_consented_plan"},
            ("ENGINE_CHECK", "SMOKE_TEST"): {"image_allowlisted", "image_present_by_digest"},  # N1
            ("IMAGE_PULL", "SMOKE_TEST"): {"image_allowlisted", "image_present_by_digest"},
        },
        # CR-17: orchestrator decision on what follows a rejected guard ("stay" = remain in `from`).
        "required_on_reject": {
            ("PLAN_READY", "ENGINE_CHECK"): {"CONSENT_REQUIRED": ("WAITING_FOR_CONSENT", "state")},
            ("WAITING_FOR_CONSENT", "INSTALLING"): {"CONSENT_REQUIRED": ("stay", "state"),
                                                    "PLAN_STALE": ("PROBING", "state")},
            ("INSTALLING", "WAITING_FOR_PRIVILEGE"): {"CONSENT_REQUIRED": ("FAILED", "error"),
                                                      "PLAN_STALE": ("FAILED", "error")},
            ("WAITING_FOR_PRIVILEGE", "INSTALLING"): {"CONSENT_REQUIRED": ("FAILED", "error"),
                                                      "PLAN_STALE": ("FAILED", "error"),
                                                      "PRIVILEGE_REQUIRED": ("stay", "state")},
            ("ENGINE_CHECK", "IMAGE_PULL"): {"CONSENT_REQUIRED": ("PROBING", "state"),
                                             "PLAN_STALE": ("FAILED", "error"),
                                             "IMAGE_NOT_ALLOWED": ("FAILED", "error")},
            ("ENGINE_CHECK", "SMOKE_TEST"): {"IMAGE_NOT_ALLOWED": ("FAILED", "error"),
                                             "PLAN_STALE": ("PROBING", "state")},
            ("IMAGE_PULL", "SMOKE_TEST"): {"IMAGE_NOT_ALLOWED": ("FAILED", "error"),
                                           "PLAN_STALE": ("PROBING", "state")},
        },
        "required_effects": [("enter_state", "PROBING", "clear_consent"),
                             ("user_consent", "WAITING_FOR_CONSENT", "set_consented_plan_id")],
        "succ_subset": {
            "REBOOT_REQUIRED": {"PROBING", "CANCELLED"},  # CF15
            "ACTION_REQUIRED": {"PROBING", "CANCELLED"},  # resume re-verifies
            "terminal": {"PROBING"},  # leaving READY/FAILED/CANCELLED starts with a probe
        },
        "must_pass": [
            ("NEW", "INSTALLING", "WAITING_FOR_CONSENT"),      # CF13
            ("PROBING", "INSTALLING", "WAITING_FOR_CONSENT"),  # CR-13: fresh consent after any resume
            ("NEW", "READY", "SMOKE_TEST"),                    # CF16
            ("PROBING", "READY", "SMOKE_TEST"),
        ],
    },
    "node_status": {
        "states": {"OFFLINE", "CONNECTING", "REGISTERED", "READY", "BUSY", "DRAINING"},
        "required_edges": [
            ("OFFLINE", "CONNECTING"), ("CONNECTING", "REGISTERED"), ("REGISTERED", "READY"),
            ("READY", "BUSY"), ("BUSY", "DRAINING"), ("DRAINING", "OFFLINE"),
        ],
        "preds_equal": {"BUSY": {"READY"}},                    # jobs only when READY
        "preds_subset": {"READY": {"REGISTERED", "BUSY"}},     # CF05/CF42: explicit join
        "succ_subset": {"DRAINING": {"OFFLINE"}},              # CF43: no jobs while draining
        "must_pass": [("OFFLINE", "BUSY", "REGISTERED")],
    },
    "wsl_availability": {
        "states": {"WSL2_READY", "WSL_OUTDATED", "WSL_MISSING", "VIRTUALIZATION_DISABLED",
                   "UNSUPPORTED_PROFILE"},
        "required_edges": [("WSL_MISSING", "WSL2_READY"), ("WSL_OUTDATED", "WSL2_READY")],
        "preds_equal": {},
        "preds_subset": {},
        "succ_subset": {"WSL2_READY": set()},  # CW02: a ready WSL2 is never changed
        "must_pass": [],
    },
    "task": {
        "states": {"RUNNING", "SUCCEEDED", "FAILED", "CANCELLED"},
        "required_edges": [("RUNNING", "SUCCEEDED"), ("RUNNING", "FAILED"), ("RUNNING", "CANCELLED")],
        "preds_equal": {},
        "preds_subset": {},
        "succ_subset": {"terminal": set()},  # CR-18: no restart edge; a resumed task is a new operation
        "must_pass": [],
    },
}

# CR-18: operation kinds and the machine each one uses.
SPEC_OPERATION_KINDS = {
    "bootstrap": "bootstrap", "node_status": "node_status", "model_pull": "task", "model_import": "task",
    "model_load": "task", "image_update": "task", "diag_export": "task", "train_run": "task",
    "mode_switch": "task",
}


def _p_consent_matches_plan(c: dict):
    consented = c.get("consented_plan_id")
    if not isinstance(consented, str):
        return "CONSENT_REQUIRED"
    plan_id = c.get("plan_id")
    if not isinstance(plan_id, str) or plan_id != consented:
        return "PLAN_STALE"
    return None


def _p_plan_has_no_actions(c: dict):
    n = c.get("plan_action_count")
    return None if isinstance(n, int) and not isinstance(n, bool) and n == 0 else "CONSENT_REQUIRED"


def _p_step_is_privileged_plan_step(c: dict):
    step = c.get("step")
    ok = isinstance(step, dict) and step.get("in_consented_plan") is True and step.get("privileged") is True
    return None if ok else "CONSENT_REQUIRED"


def _p_privilege_granted(c: dict):
    return None if c.get("privilege_granted") is True else "PRIVILEGE_REQUIRED"


def _p_image_allowlisted(c: dict):
    digest, allow = c.get("image_digest"), c.get("allowlist")
    ok = isinstance(digest, str) and isinstance(allow, list) and digest in allow
    return None if ok else "IMAGE_NOT_ALLOWED"


def _p_image_in_consented_plan(c: dict):
    digest, listed = c.get("image_digest"), c.get("consented_image_digests")
    ok = (isinstance(c.get("consented_plan_id"), str) and isinstance(digest, str)
          and isinstance(listed, list) and digest in listed)
    return None if ok else "CONSENT_REQUIRED"


def _p_image_present_by_digest(c: dict):
    return None if c.get("image_present") is True else "PLAN_STALE"


# Reference implementation of the guard predicates of registry/state-machines.json.
# Each returns None when the predicate holds, otherwise the reason code. Missing inputs fail.
PREDICATES = {
    "consent_matches_plan": (_p_consent_matches_plan, True),
    "plan_has_no_actions": (_p_plan_has_no_actions, False),
    "step_is_privileged_plan_step": (_p_step_is_privileged_plan_step, True),
    "privilege_granted": (_p_privilege_granted, False),
    "image_allowlisted": (_p_image_allowlisted, False),
    "image_in_consented_plan": (_p_image_in_consented_plan, True),
    "image_present_by_digest": (_p_image_present_by_digest, False),
}


def evaluate_guard(checks: list, context: dict):
    """(allowed, reason_code, failing_predicate) for the ordered checks of one transition."""
    for pid in checks:
        reason = PREDICATES[pid][0](context)
        if reason is not None:
            return False, reason, pid
    return True, None, None


def consent_edges(machine_def: dict) -> set:
    """Transitions whose guard contains a predicate that needs consent."""
    out = set()
    for g in machine_def.get("guards", []):
        if any(PREDICATES.get(p, (None, False))[1] for p in g["checks"]):
            out.add((g["from"], g["to"]))
    return out


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.checks = 0

    def error(self, where: str, msg: str) -> None:
        self.errors.append(f"{where}: {msg}")

    def ok(self) -> None:
        self.checks += 1


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


# --------------------------------------------------------------------------
# Canonical JSON (RFC 8785 / JCS, restricted value set; docs/canonical-json.md)
# --------------------------------------------------------------------------

MAX_SAFE_INTEGER = 2 ** 53 - 1
MAX_DEPTH = 64             # nesting of arrays/objects; the top-level container is depth 1
MAX_SIZE = 1024 * 1024     # bytes of the received document (spec 9: control payload <= 1 MiB)
KIND_RE = re.compile(r"[a-z][a-z0-9]*(_[a-z0-9]+)*")
HASH_RE = re.compile(r"[0-9a-f]{64}")


class CanonicalJsonError(Exception):
    """kind is one of the error categories listed in docs/canonical-json.md."""

    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(f"{kind}: {detail}")
        self.kind = kind


def _strict_int(token: str) -> int:
    if token == "-0":
        raise CanonicalJsonError("NEGATIVE_ZERO", "-0 is not allowed")
    if len(token.lstrip("-")) > 16:  # 2^53-1 has 16 digits; never convert huge tokens
        raise CanonicalJsonError("INTEGER_OUT_OF_RANGE", f"integer with {len(token.lstrip('-'))} digits")
    value = int(token)
    if abs(value) > MAX_SAFE_INTEGER:
        raise CanonicalJsonError("INTEGER_OUT_OF_RANGE", f"{token} is outside +/-(2^53-1)")
    return value


def _strict_float(token: str):
    raise CanonicalJsonError("NON_INTEGER_NUMBER", f"{token} has a fraction or exponent")


def _strict_constant(token: str):
    # NaN / Infinity are not RFC 8259 JSON tokens.
    raise CanonicalJsonError("INVALID_JSON", f"{token} is not a JSON token")


def _strict_pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise CanonicalJsonError("DUPLICATE_KEY", f"duplicate key {key!r}")
        obj[key] = value
    return obj


def _check_unicode(value) -> None:
    if isinstance(value, str):
        for ch in value:
            if 0xD800 <= ord(ch) <= 0xDFFF:
                raise CanonicalJsonError("INVALID_UNICODE", f"lone surrogate U+{ord(ch):04X}")
    elif isinstance(value, list):
        for item in value:
            _check_unicode(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _check_unicode(key)
            _check_unicode(item)


def parse_hashable_json(text: str):
    """Parse JSON text intended for hashing, enforcing the restricted value set."""
    try:
        value = json.loads(text, object_pairs_hook=_strict_pairs, parse_int=_strict_int,
                           parse_float=_strict_float, parse_constant=_strict_constant)
    except CanonicalJsonError:
        raise
    except ValueError as exc:
        raise CanonicalJsonError("INVALID_JSON", str(exc)) from exc
    _check_unicode(value)
    return value


def max_text_depth(text: str) -> int:
    """Nesting depth of [ and { outside strings, scanned before parsing."""
    depth = deepest = 0
    in_string = escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif ch in "]}":
            depth -= 1
    return deepest


def parse_hashable_bytes(raw: bytes):
    """Received document -> value: size limit, strict UTF-8, depth limit, then strict parsing."""
    if len(raw) > MAX_SIZE:
        raise CanonicalJsonError("SIZE_LIMIT", f"{len(raw)} bytes > {MAX_SIZE}")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CanonicalJsonError("INVALID_UNICODE", f"malformed UTF-8: {exc}") from exc
    if max_text_depth(text) > MAX_DEPTH:
        raise CanonicalJsonError("DEPTH_LIMIT", f"nesting deeper than {MAX_DEPTH}")
    return parse_hashable_json(text)


_SHORT_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n",
                  "\r": "\\r", "\t": "\\t"}


def _canonical_string(s: str) -> str:
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if ch in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[ch])
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        elif 0xD800 <= cp <= 0xDFFF:
            raise CanonicalJsonError("INVALID_UNICODE", f"lone surrogate U+{cp:04X}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def utf16_key(s: str) -> bytes:
    # Big-endian UTF-16 bytes compare exactly like UTF-16 code units (RFC 8785 3.2.3).
    return s.encode("utf-16-be")


# Indirection so that --self-test can swap in a wrong sort key and prove the vectors catch it.
SORT_KEY = utf16_key


def canonicalize(value, depth: int = 0) -> str:
    if isinstance(value, (list, dict)) and depth + 1 > MAX_DEPTH:
        raise CanonicalJsonError("DEPTH_LIMIT", f"nesting deeper than {MAX_DEPTH}")
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalJsonError("INTEGER_OUT_OF_RANGE", f"{value} is outside +/-(2^53-1)")
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalJsonError("NON_FINITE_NUMBER", f"{value!r} cannot be serialized")
        raise CanonicalJsonError("NON_INTEGER_NUMBER", f"{value!r} is not an integer")
    if isinstance(value, str):
        return _canonical_string(value)
    if isinstance(value, list):
        return "[" + ",".join(canonicalize(v, depth + 1) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value.keys(), key=SORT_KEY)
        return "{" + ",".join(_canonical_string(k) + ":" + canonicalize(value[k], depth + 1) for k in keys) + "}"
    raise CanonicalJsonError("INVALID_JSON", f"unsupported type {type(value).__name__}")


def object_hash_input(value, expected_kind: str | None = None) -> dict:
    """The object with its own top-level "hash" member removed (CF03), after the
    domain-separation and stored-hash checks of docs/canonical-json.md."""
    if not isinstance(value, dict):
        raise CanonicalJsonError("INVALID_JSON", "object_hash requires a JSON object")
    kind = value.get("kind")
    if not isinstance(kind, str) or not KIND_RE.fullmatch(kind):
        raise CanonicalJsonError("INVALID_KIND", f"top-level kind {kind!r} is missing or not lower_snake_case")
    if expected_kind is not None and kind != expected_kind:
        raise CanonicalJsonError("INVALID_KIND", f"kind {kind!r} where {expected_kind!r} is expected")
    if "hash" in value:
        stored = value["hash"]
        if not isinstance(stored, str) or not HASH_RE.fullmatch(stored):
            raise CanonicalJsonError("INVALID_HASH_MEMBER", f"stored hash {stored!r} is not 64 lowercase hex digits")
    return {k: v for k, v in value.items() if k != "hash"}


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Minimal JSON Schema (draft 2020-12 subset)
# --------------------------------------------------------------------------

SCHEMA_KEYWORDS = {
    "$schema", "$id", "$ref", "$defs", "$comment", "title", "description", "examples",
    "type", "properties", "required", "additionalProperties", "items", "enum", "const",
    "pattern", "minLength", "maxLength", "minimum", "maximum", "minItems", "uniqueItems",
    "allOf", "anyOf", "oneOf", "not", "if", "then", "else",
}


class SchemaRefError(Exception):
    pass


_PATTERN_CACHE: dict = {}


def pattern_matches(pattern: str, text: str) -> bool:
    """ECMA-262 semantics for the anchored patterns used here: `$` matches only at the very
    end of the string. Python's `$` also matches before a trailing newline, so it is replaced
    by `\\Z` (Java: Pattern.matches()/`\\z`; Go RE2 and JavaScript already behave correctly)."""
    compiled = _PATTERN_CACHE.get(pattern)
    if compiled is None:
        py = pattern[:-1] + r"\Z" if pattern.endswith("$") and not pattern.endswith("\\$") else pattern
        compiled = _PATTERN_CACHE[pattern] = re.compile(py)
    return compiled.search(text) is not None


def resolve_ref(root, ref: str):
    if not isinstance(ref, str) or not ref.startswith("#/"):
        raise SchemaRefError(f"unsupported $ref {ref!r} (only local '#/...' refs)")
    target = root
    for part in ref[2:].split("/"):
        if not isinstance(target, dict) or part not in target:
            raise SchemaRefError(f"$ref {ref!r} does not resolve")
        target = target[part]
    return target


def check_schema_keywords(schema, root, where: str, report: Report) -> None:
    if isinstance(schema, bool):
        return
    if not isinstance(schema, dict):
        report.error(where, "schema must be an object or boolean")
        return
    for key, value in schema.items():
        if key not in SCHEMA_KEYWORDS:
            report.error(where, f"unsupported JSON Schema keyword {key!r} "
                                "(extend tools/validate.py before using it)")
            continue
        if key == "$ref":
            try:
                resolve_ref(root, value)
            except SchemaRefError as exc:
                report.error(where, str(exc))
        elif key in ("properties", "$defs"):
            for name, sub in value.items():
                check_schema_keywords(sub, root, f"{where}/{key}/{name}", report)
        elif key in ("items", "additionalProperties", "not", "if", "then", "else"):
            check_schema_keywords(value, root, f"{where}/{key}", report)
        elif key in ("allOf", "anyOf", "oneOf"):
            for i, sub in enumerate(value):
                check_schema_keywords(sub, root, f"{where}/{key}/{i}", report)
        elif key == "pattern":
            if not (isinstance(value, str) and value.startswith("^") and value.endswith("$")
                    and not value.endswith("\\$")):
                report.error(where, f"pattern {value!r} must be anchored with ^...$ (whole-string match)")
                continue
            try:
                re.compile(value)
            except re.error as exc:
                report.error(where, f"bad pattern {value!r}: {exc}")


def _type_ok(instance, name: str) -> bool:
    if name == "object":
        return isinstance(instance, dict)
    if name == "array":
        return isinstance(instance, list)
    if name == "string":
        return isinstance(instance, str)
    if name == "integer":
        return isinstance(instance, int) and not isinstance(instance, bool)
    if name == "number":
        return isinstance(instance, (int, float)) and not isinstance(instance, bool)
    if name == "boolean":
        return isinstance(instance, bool)
    if name == "null":
        return instance is None
    return False


def _json_equal(a, b) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    return a == b


def schema_errors(instance, schema, root, path: str = "$") -> list[str]:
    if schema is True:
        return []
    if schema is False:
        return [f"{path}: not allowed"]
    errs: list[str] = []
    if "$ref" in schema:
        try:
            target = resolve_ref(root, schema["$ref"])
        except SchemaRefError as exc:
            return [f"{path}: {exc}"]
        errs += schema_errors(instance, target, root, path)
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_type_ok(instance, t) for t in types):
            return errs + [f"{path}: expected type {'|'.join(types)}"]
    if "const" in schema and not _json_equal(instance, schema["const"]):
        errs.append(f"{path}: must equal {schema['const']!r}")
    if "enum" in schema and not any(_json_equal(instance, e) for e in schema["enum"]):
        errs.append(f"{path}: {instance!r} not in {schema['enum']!r}")
    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errs.append(f"{path}: shorter than {schema['minLength']}")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errs.append(f"{path}: longer than {schema['maxLength']}")
        if "pattern" in schema and not pattern_matches(schema["pattern"], instance):
            errs.append(f"{path}: {instance!r} does not match {schema['pattern']!r}")
    if _type_ok(instance, "number"):
        if "minimum" in schema and instance < schema["minimum"]:
            errs.append(f"{path}: less than {schema['minimum']}")
        if "maximum" in schema and instance > schema["maximum"]:
            errs.append(f"{path}: greater than {schema['maximum']}")
    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errs.append(f"{path}: fewer than {schema['minItems']} items")
        if schema.get("uniqueItems"):
            seen = [json.dumps(i, sort_keys=True) for i in instance]
            if len(seen) != len(set(seen)):
                errs.append(f"{path}: items are not unique")
        if "items" in schema:
            for i, item in enumerate(instance):
                errs += schema_errors(item, schema["items"], root, f"{path}[{i}]")
    if isinstance(instance, dict):
        for name in schema.get("required", []):
            if name not in instance:
                errs.append(f"{path}: missing required property {name!r}")
        props = schema.get("properties", {})
        for name, value in instance.items():
            if name in props:
                errs += schema_errors(value, props[name], root, f"{path}.{name}")
            elif "additionalProperties" in schema:
                errs += schema_errors(value, schema["additionalProperties"], root, f"{path}.{name}")
    for sub in schema.get("allOf", []):
        errs += schema_errors(instance, sub, root, path)
    if "anyOf" in schema and not any(not schema_errors(instance, s, root, path) for s in schema["anyOf"]):
        errs.append(f"{path}: matches none of anyOf")
    if "oneOf" in schema:
        n = sum(1 for s in schema["oneOf"] if not schema_errors(instance, s, root, path))
        if n != 1:
            errs.append(f"{path}: matches {n} of oneOf, expected exactly 1")
    if "not" in schema and not schema_errors(instance, schema["not"], root, path):
        errs.append(f"{path}: must not match 'not' schema")
    if "if" in schema:
        if not schema_errors(instance, schema["if"], root, path):
            if "then" in schema:
                errs += schema_errors(instance, schema["then"], root, path)
        elif "else" in schema:
            errs += schema_errors(instance, schema["else"], root, path)
    return errs


def validate_against(instance, schema_name: str, where: str, ctx: dict, report: Report) -> bool:
    schema = ctx["schemas"].get(schema_name)
    if schema is None:
        report.error(where, f"schema {schema_name} is not available")
        return False
    errs = schema_errors(instance, schema, schema)
    for e in errs:
        report.error(where, e)
    if not errs:
        report.ok()
    return not errs


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------

def _no_duplicates(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate key {key!r}")
        obj[key] = value
    return obj


def _reject_constant(name):
    raise ValueError(f"non-standard JSON constant {name}")


def load_repo(report: Report) -> dict:
    """Read every repository file once. The returned context is mutated only by --self-test."""
    ctx: dict = {"files": {}, "canonical": {}, "schemas": {}}
    for path in sorted(ROOT.rglob("*.json")):
        if ".git" in path.parts:
            continue
        name = rel(path)
        raw = path.read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            report.error(name, "file starts with a UTF-8 BOM")
            continue
        try:
            text = raw.decode("utf-8")
            ctx["files"][name] = json.loads(text, object_pairs_hook=_no_duplicates,
                                            parse_constant=_reject_constant)
        except (UnicodeDecodeError, ValueError) as exc:
            report.error(name, f"invalid JSON: {exc}")
            continue
        report.ok()
        if name.startswith(D_CANONICAL):
            # Vector inputs are parsed under the hashing restrictions, so that e.g. -0 or 1.0
            # in an "input" cannot be silently normalised by the generic parser.
            try:
                ctx["canonical"][name] = parse_hashable_json(text)
            except CanonicalJsonError as exc:
                report.error(name, f"vector file violates hashing restrictions: {exc}")
    version = ROOT / "VERSION"
    ctx["version"] = version.read_text(encoding="utf-8").strip() if version.exists() else None
    return ctx


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------

def check_version(ctx: dict, report: Report) -> None:
    if ctx["version"] is None:
        report.error("VERSION", "file is missing")
    elif not SEMVER.fullmatch(ctx["version"]):
        report.error("VERSION", f"{ctx['version']!r} is not a semantic version")
    else:
        report.ok()


def check_schemas(ctx: dict, report: Report) -> None:
    for name, data in ctx["files"].items():
        if name.startswith("schemas/"):
            if not isinstance(data, dict) or data.get("$schema") != DRAFT_2020_12:
                report.error(name, "$schema must be draft 2020-12")
                continue
            check_schema_keywords(data, data, name, report)
            ctx["schemas"][name] = data
            report.ok()


def check_localized(entry: dict, field: str, where: str, report: Report) -> None:
    value = entry.get(field)
    if not isinstance(value, dict):
        return
    for lang in ("ru", "en"):
        text = value.get(lang)
        if isinstance(text, str) and text != text.strip():
            report.error(where, f"{field}.{lang} has leading/trailing whitespace")


def check_exit_codes(ctx: dict, report: Report) -> dict:
    name = P_EXIT_CODES
    data = ctx["files"].get(name)
    if data is None:
        report.error(name, "missing")
        return {}
    if not validate_against(data, "schemas/exit-code-registry.schema.json", name, ctx, report):
        return {}
    by_code = {}
    names = set()
    fallbacks = []
    for i, entry in enumerate(data["exit_codes"]):
        where = f"{name}: exit_codes[{i}]"
        if entry["code"] in by_code:
            report.error(where, f"duplicate exit code {entry['code']}")
        if entry["name"] in names:
            report.error(where, f"duplicate exit code name {entry['name']}")
        by_code[entry["code"]] = entry
        names.add(entry["name"])
        check_localized(entry, "description", where, report)
        if entry.get("reason_code_fallback"):
            fallbacks.append(entry["code"])
    if len(fallbacks) != 1:
        report.error(name, f"exactly one exit code must set reason_code_fallback, found {fallbacks}")
    expected = {0, 1, 2, 3, 4, 5, 6, 7, 8, 130}  # spec 7.3
    if set(by_code) != expected:
        report.error(name, f"exit codes {sorted(by_code)} differ from spec 7.3 {sorted(expected)}")
    rules = data["resolution"]["rules"]
    ids = [r["id"] for r in rules]
    if len(ids) != len(set(ids)):
        report.error(name, "resolution rule ids are not unique")
    for r in rules:
        check_localized(r, "description", f"{name}: resolution rule {r['id']}", report)
        ec = r["exit_code"]
        if isinstance(ec, int) and ec not in by_code:
            report.error(name, f"resolution rule {r['id']}: exit code {ec} is not defined")
    if not rules or rules[-1]["match"] != {} or rules[-1]["exit_code"] not in fallbacks:
        report.error(name, "the last resolution rule must be a catch-all (empty match) "
                           "returning the reason_code_fallback exit code")
    for r in rules[:-1]:
        if r["match"] == {}:
            report.error(name, f"resolution rule {r['id']}: only the last rule may have an empty match")
    report.ok()
    ctx["exit_codes"] = by_code
    ctx["exit_rules"] = rules
    ctx["succeeded_final_states"] = data["resolution"]["succeeded_final_states"]
    ctx["exit_fallback"] = fallbacks[0] if len(fallbacks) == 1 else 1
    return by_code


def check_reason_codes(ctx: dict, report: Report) -> dict:
    name = P_REASON_CODES
    exit_codes = ctx.get("exit_codes", {})
    data = ctx["files"].get(name)
    if data is None:
        report.error(name, "missing")
        return {}
    if not validate_against(data, "schemas/reason-code-registry.schema.json", name, ctx, report):
        return {}
    by_code: dict = {}
    for i, entry in enumerate(data["reason_codes"]):
        code = entry["code"]
        where = f"{name}: reason_codes[{i}] {code}"
        if code in by_code:
            report.error(where, "duplicate code")
        by_code[code] = entry
        if not UPPER_SNAKE.fullmatch(code):
            report.error(where, "code is not UPPER_SNAKE_CASE")
        for field in ("description", "next_action"):
            check_localized(entry, field, where, report)
        if entry["cli_exit_code"] not in exit_codes:
            report.error(where, f"cli_exit_code {entry['cli_exit_code']} is not in exit-codes.json")
        if code.startswith("WSL_") and entry["platforms"] != ["windows"]:
            report.error(where, 'WSL_* codes must have platforms ["windows"] (spec 8.3)')
        if sorted(entry["platforms"], key=PLATFORMS.index) != entry["platforms"]:
            report.error(where, f"platforms must be listed in the order {list(PLATFORMS)}")
    for code_num, ec in exit_codes.items():
        for rc in ec.get("reason_codes", []):
            if rc not in by_code:
                report.error(P_EXIT_CODES, f"exit code {code_num} lists unknown reason code {rc}")
            elif by_code[rc]["cli_exit_code"] != code_num:
                report.error(P_EXIT_CODES,
                             f"exit code {code_num} lists {rc}, but {rc} maps to {by_code[rc]['cli_exit_code']}")
    for rc, entry in by_code.items():
        ec = exit_codes.get(entry["cli_exit_code"])
        if ec and not ec.get("reason_code_fallback") and rc not in ec.get("reason_codes", []):
            report.error(name, f"{rc} maps to exit code {entry['cli_exit_code']}, "
                               "which does not list it in reason_codes")
    for source, codes in (("SPRUT-CLIENT-SPECIFICATION 8.3", SPEC_CLIENT_REASON_CODES),
                          ("03-CONTRACTS 7", SPEC_CONTRACT_REASON_CODES)):
        for rc in codes:
            if rc not in by_code:
                report.error(name, f"{rc} from {source} is missing")
    report.ok()
    ctx["reason_codes"] = by_code
    return by_code


def _reachable(start: list, edges: dict, avoid: str | None = None) -> set:
    seen = set(s for s in start if s != avoid)
    stack = list(seen)
    while stack:
        cur = stack.pop()
        for nxt in edges.get(cur, ()):
            if nxt != avoid and nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def check_structural_rules(mid: str, pairs: set, terminal: list, machine_def: dict, where: str,
                           report: Report) -> None:
    spec = SPEC_MACHINES[mid]
    edges: dict = {}
    preds: dict = {}
    for f, t in pairs:
        edges.setdefault(f, set()).add(t)
        preds.setdefault(t, set()).add(f)
    for e in spec["required_edges"]:
        if e not in pairs:
            report.error(where, f"spec transition {e[0]}->{e[1]} is missing")
    for state, allowed in spec["preds_equal"].items():
        if preds.get(state, set()) != allowed:
            report.error(where, f"predecessors of {state} must be exactly {sorted(allowed)}, "
                                f"found {sorted(preds.get(state, set()))}")
    for state, allowed in spec["preds_subset"].items():
        extra = preds.get(state, set()) - allowed
        if extra:
            report.error(where, f"{state} may only be entered from {sorted(allowed)}, "
                                f"also entered from {sorted(extra)}")
    for state, allowed in spec["succ_subset"].items():
        targets = terminal if state == "terminal" else [state]
        for s in targets:
            extra = edges.get(s, set()) - allowed
            if extra:
                report.error(where, f"{s} may only lead to {sorted(allowed)}, also leads to {sorted(extra)}")
    for start, target, via in spec["must_pass"]:
        if target in _reachable([start], edges, avoid=via):
            report.error(where, f"{target} is reachable from {start} without passing {via}")
    restart = spec.get("restart_to")
    if restart:
        for s in sorted({f for f, _ in pairs} | {t for _, t in pairs}):
            if s != restart and (s, restart) not in pairs:
                report.error(where, f"{s} has no transition to {restart} (resume after restart re-verifies)")
    guards = {(g["from"], g["to"]): g["checks"] for g in machine_def.get("guards", [])}
    for (f, t), needed in spec.get("required_guards", {}).items():
        missing = needed - set(guards.get((f, t), []))
        if missing:
            report.error(where, f"guard of {f}->{t} must contain {sorted(missing)}")
    effects = {(e["on"], e["state"], e["action"]) for e in machine_def.get("effects", [])}
    for eff in spec.get("required_effects", []):
        if eff not in effects:
            report.error(where, f"effect {eff[2]} on {eff[0]} in {eff[1]} is missing")
    for (f, t), expected in spec.get("required_on_reject", {}).items():
        declared = {}
        for g in machine_def.get("guards", []):
            if (g["from"], g["to"]) == (f, t):
                declared = g.get("on_reject", {})
        for rc, (target, event) in expected.items():
            entry = declared.get(rc, {})
            got = ("stay" if entry.get("stay") else entry.get("to"), entry.get("event"))
            if got != (target, event):
                report.error(where, f"on_reject of {f}->{t} for {rc} must be {target}/{event}, found {got[0]}/{got[1]}")
    if spec.get("must_pass_guarded"):
        needs_consent = consent_edges(machine_def)
        unconsented: dict = {}
        for f, t in pairs - needs_consent:
            unconsented.setdefault(f, set()).add(t)
        for start, target, via in spec["must_pass_guarded"]:
            if target in _reachable([start], unconsented, avoid=via):
                report.error(where, f"{target} is reachable from {start} without passing {via} "
                                    "(no consent-requiring guard on the way)")


def check_guard_definitions(mid: str, m: dict, pairs: set, reason_codes: dict, where: str, report: Report) -> None:
    context_names = {c["name"] for c in m.get("guard_context", [])}
    catalog = {p["id"]: p for p in m.get("guard_predicates", [])}
    if m.get("guards") and not catalog:
        report.error(where, "guards are used but guard_predicates is empty")
    for pid, p in catalog.items():
        if pid not in PREDICATES:
            report.error(where, f"predicate {pid} has no reference implementation in tools/validate.py")
            continue
        if p["requires_consent"] != PREDICATES[pid][1]:
            report.error(where, f"predicate {pid}: requires_consent must be {PREDICATES[pid][1]}")
        for rc in p["fails_with"]:
            if rc not in reason_codes:
                report.error(where, f"predicate {pid} fails with unknown reason code {rc}")
        for name in p["reads"]:
            if name not in context_names:
                report.error(where, f"predicate {pid} reads {name}, which is not in guard_context")
    seen = set()
    for g in m.get("guards", []):
        key = (g["from"], g["to"])
        if key in seen:
            report.error(where, f"duplicate guard for {key[0]}->{key[1]}")
        seen.add(key)
        if key not in pairs:
            report.error(where, f"guard for {key[0]}->{key[1]}, which is not a transition")
        for pid in g["checks"]:
            if pid not in catalog:
                report.error(where, f"guard of {key[0]}->{key[1]} uses undeclared predicate {pid}")
    state_names = {s["name"] for s in m["states"]}
    waiting = set(m.get("waiting", []))
    for e in m.get("effects", []):
        if e["state"] not in state_names:
            report.error(where, f"effect on unknown state {e['state']}")
        if e["on"] == "user_consent" and e["state"] not in waiting:
            report.error(where, f"user_consent effect in {e['state']}, which is not a waiting state")
    for g in m.get("guards", []):
        f, t = g["from"], g["to"]
        on_reject = g.get("on_reject", {})
        needed = set()
        for pid in g["checks"]:
            needed |= set(catalog.get(pid, {}).get("fails_with", []))
        for rc in sorted(needed - set(on_reject)):
            report.error(where, f"guard of {f}->{t}: on_reject does not cover {rc}")
        for rc, entry in on_reject.items():
            if rc not in needed:
                report.error(where, f"guard of {f}->{t}: on_reject lists {rc}, which no check can return")
            if entry.get("stay"):
                if f not in waiting:
                    report.error(where, f"guard of {f}->{t}: on_reject {rc} stays in {f}, which is not a waiting state")
            elif (f, entry["to"]) not in pairs:
                report.error(where, f"guard of {f}->{t}: on_reject {rc} goes to {entry['to']}, "
                                    f"but {f}->{entry['to']} is not a transition")


def check_state_machines(ctx: dict, report: Report) -> dict:
    name = P_STATE_MACHINES
    data = ctx["files"].get(name)
    if data is None:
        report.error(name, "missing")
        return {}
    if not validate_against(data, "schemas/state-machines.schema.json", name, ctx, report):
        return {}
    reason_codes = ctx.get("reason_codes", {})
    machines = {}
    for m in data["machines"]:
        mid = m["id"]
        where = f"{name}: {mid}"
        if mid in machines:
            report.error(where, "duplicate machine id")
        states = [s["name"] for s in m["states"]]
        state_set = set(states)
        if len(states) != len(state_set):
            report.error(where, "duplicate state names")
        for s in m["states"]:
            check_localized(s, "description", f"{where}.{s['name']}", report)
            rc = s.get("reason_code")
            if rc is not None and rc not in reason_codes:
                report.error(where, f"state {s['name']} references unknown reason code {rc}")
        edges: dict = {}
        pairs = set()
        for t in m["transitions"]:
            f, to = t["from"], t["to"]
            for s in (f, to):
                if s not in state_set:
                    report.error(where, f"transition {f}->{to} references unknown state {s}")
            if f == to:
                report.error(where, f"self-transition {f}->{to} is not allowed")
            if (f, to) in pairs:
                report.error(where, f"duplicate transition {f}->{to}")
            pairs.add((f, to))
            edges.setdefault(f, []).append(to)
        initial = m["initial"]
        terminal = m["terminal"]
        waiting = m.get("waiting", [])
        for s in terminal + waiting:
            if s not in state_set:
                report.error(where, f"terminal/waiting state {s} is not a declared state")
        if set(terminal) & set(waiting):
            report.error(where, "a state cannot be both terminal and waiting")
        if m["kind"] == "lifecycle":
            if initial not in state_set:
                report.error(where, f"initial state {initial!r} is not declared")
                continue
            unreachable = state_set - _reachable([initial], edges)
            if unreachable:
                report.error(where, f"unreachable from {initial}: {sorted(unreachable)}")
            for s in states:
                if s not in terminal and not set(terminal) & _reachable([s], edges):
                    report.error(where, f"no terminal state reachable from {s} (dead end)")
        else:  # probe_result: every state is a possible probe output
            if initial is not None:
                report.error(where, "probe_result machines must have initial = null")
            for s in states:
                has_out = bool(edges.get(s))
                if s in terminal and has_out:
                    report.error(where, f"terminal state {s} has client-driven transitions")
                if s not in terminal and not has_out:
                    report.error(where, f"non-terminal state {s} has no client-driven transition")
        if mid not in SPEC_MACHINES:
            report.error(where, "machine is not known to the validator (add its spec rules)")
        else:
            spec_states = SPEC_MACHINES[mid]["states"]
            if state_set != spec_states:
                report.error(where, f"states differ from spec: extra {sorted(state_set - spec_states)}, "
                                    f"missing {sorted(spec_states - state_set)}")
            check_structural_rules(mid, pairs, terminal, m, where, report)
        check_guard_definitions(mid, m, pairs, reason_codes, where, report)
        machines[mid] = {"states": state_set, "pairs": pairs, "def": m}
        report.ok()
    for mid in SPEC_MACHINES:
        if mid not in machines:
            report.error(name, f"machine {mid} is missing")
    kinds = {}
    for k in data["operation_kinds"]:
        if k["kind"] in kinds:
            report.error(name, f"duplicate operation kind {k['kind']}")
        kinds[k["kind"]] = k["machine"]
        check_localized(k, "description", f"{name}: operation kind {k['kind']}", report)
        mdata = machines.get(k["machine"])
        if mdata is None or mdata["def"]["kind"] != "lifecycle":
            report.error(name, f"operation kind {k['kind']} maps to {k['machine']}, which is not a lifecycle machine")
    if kinds != SPEC_OPERATION_KINDS:
        report.error(name, f"operation_kinds differ from the agreed mapping {SPEC_OPERATION_KINDS}")
    ctx["machines"] = machines
    ctx["operation_kinds"] = kinds
    return machines


def check_canonical_vectors(ctx: dict, report: Report) -> None:
    valid = dict(ctx["canonical"])
    invalid = {k: v for k, v in ctx["files"].items() if k.startswith(D_CANONICAL_INVALID)}
    if not valid:
        report.error(D_CANONICAL, "no vectors found")
    if not invalid:
        report.error(D_CANONICAL_INVALID, "no vectors found")
    names = set()
    for path, vec in sorted(valid.items()):
        if not validate_against(vec, "schemas/canonical-json-vector.schema.json", path, ctx, report):
            continue
        if vec["name"] in names:
            report.error(path, f"duplicate vector name {vec['name']}")
        names.add(vec["name"])
        if Path(path).stem != vec["name"]:
            report.error(path, f"file name must equal vector name {vec['name']!r}")
        try:
            value = vec["input"]
            if vec["operation"] == "object_hash":
                value = object_hash_input(value, vec.get("expected_kind"))
            canonical = canonicalize(value)
        except CanonicalJsonError as exc:
            report.error(path, f"input cannot be canonicalized: {exc}")
            continue
        if canonical != vec["canonical"]:
            report.error(path, f"canonical mismatch:\n  expected {vec['canonical']!r}\n  computed {canonical!r}")
        digest = sha256_hex(vec["canonical"])
        if digest != vec["sha256"]:
            report.error(path, f"sha256 mismatch: expected {vec['sha256']}, computed {digest}")
        try:
            if canonicalize(parse_hashable_json(vec["canonical"])) != vec["canonical"]:
                report.error(path, "canonical text is not a fixed point of canonicalization")
        except CanonicalJsonError as exc:
            report.error(path, f"canonical text does not parse: {exc}")
        report.ok()
    for path, vec in sorted(invalid.items()):
        if not validate_against(vec, "schemas/canonical-json-invalid-vector.schema.json", path, ctx, report):
            continue
        if vec["name"] in names:
            report.error(path, f"duplicate vector name {vec['name']}")
        names.add(vec["name"])
        if Path(path).stem != vec["name"]:
            report.error(path, f"file name must equal vector name {vec['name']!r}")
        try:
            if "input_base64" in vec:
                raw = base64.b64decode(vec["input_base64"], validate=True)
            elif "input_generated" in vec:
                g = vec["input_generated"]
                raw = (g["prefix"] + g["repeat"] * g["count"] + g["suffix"]).encode("utf-8")
            else:
                raw = vec["input_text"].encode("utf-8")
        except (ValueError, UnicodeEncodeError) as exc:
            report.error(path, f"vector input cannot be decoded: {exc}")
            continue
        try:
            value = parse_hashable_bytes(raw)
            if vec["operation"] == "object_hash":
                value = object_hash_input(value, vec.get("expected_kind"))
            canonicalize(value)
        except CanonicalJsonError as exc:
            if exc.kind != vec["expected_error"]:
                report.error(path, f"expected {vec['expected_error']}, got {exc.kind}")
            else:
                report.ok()
            continue
        report.error(path, f"input was accepted, expected {vec['expected_error']}")


def check_transition_vectors(ctx: dict, report: Report) -> None:
    machines = ctx.get("machines", {})
    vecs = {k: v for k, v in ctx["files"].items() if k.startswith(D_TRANSITIONS)}
    covered: dict = {mid: set() for mid in machines}
    seen_machines = set()
    for path, vec in sorted(vecs.items()):
        if not validate_against(vec, "schemas/state-transition-vector.schema.json", path, ctx, report):
            continue
        mid = vec["machine"]
        if mid not in machines:
            report.error(path, f"unknown machine {mid}")
            continue
        seen_machines.add(mid)
        pairs = machines[mid]["pairs"]
        has_allowed = has_rejected = False
        for i, case in enumerate(vec.get("cases", [])):
            allowed = (case["from"], case["to"]) in pairs
            want = case["expected"] == "allowed"
            has_allowed |= want
            has_rejected |= not want
            if allowed != want:
                report.error(path, f"cases[{i}] {case['from']}->{case['to']}: expected "
                                   f"{case['expected']}, registry says {'allowed' if allowed else 'rejected'}")
            elif allowed:
                covered[mid].add((case["from"], case["to"]))
            report.ok()
        mdef = machines[mid]["def"]
        needs_consent = consent_edges(mdef)
        clears = {e["state"] for e in mdef.get("effects", [])
                  if e["on"] == "enter_state" and e["action"] == "clear_consent"}
        grants = {e["state"] for e in mdef.get("effects", []) if e["on"] == "user_consent"}
        for i, seq in enumerate(vec.get("sequences", [])):
            steps = list(zip(seq["path"], seq["path"][1:]))
            bad = [s for s in steps if s not in pairs]
            # Consent abstraction of the guards: consent can be given only in a state with a
            # user_consent effect and is cleared by clear_consent effects; a fragment starts without consent.
            consent = False
            for s in steps:
                if s in needs_consent and not consent and s not in bad:
                    bad.append(s)
                if s[1] in grants:
                    consent = True
                if s[1] in clears:
                    consent = False
            want = seq["expected"] == "allowed"
            has_allowed |= want
            has_rejected |= not want
            if want and bad:
                report.error(path, f"sequences[{i}] {seq['name']}: rejected steps {bad}")
            elif not want and not bad:
                report.error(path, f"sequences[{i}] {seq['name']}: expected rejected, all steps allowed")
            elif want:
                covered[mid].update(steps)
            initial = machines[mid]["def"]["initial"]
            if initial and want and seq["path"][0] != initial and seq.get("starts_at_initial", True):
                report.error(path, f"sequences[{i}] {seq['name']}: must start at the initial state "
                                   "or set starts_at_initial=false")
            report.ok()
        if not has_allowed or not has_rejected:
            report.error(path, "vectors must contain both allowed and rejected cases")
    for mid, data in machines.items():
        if mid not in seen_machines:
            report.error(D_TRANSITIONS, f"no vectors for machine {mid}")
            continue
        missing = data["pairs"] - covered[mid]
        if missing:
            report.error(D_TRANSITIONS, f"{mid}: transitions not covered by any allowed vector: "
                                        + ", ".join(f"{a}->{b}" for a, b in sorted(missing)))


def check_guard_vectors(ctx: dict, report: Report) -> None:
    machines = ctx.get("machines", {})
    vecs = {k: v for k, v in ctx["files"].items() if k.startswith(D_GUARDS)}
    guarded_machines = {mid for mid, d in machines.items() if d["def"].get("guards")}
    seen = set()
    for path, vec in sorted(vecs.items()):
        if not validate_against(vec, "schemas/guard-vector.schema.json", path, ctx, report):
            continue
        mid = vec["machine"]
        if mid not in machines:
            report.error(path, f"unknown machine {mid}")
            continue
        seen.add(mid)
        mdef = machines[mid]["def"]
        guards = {(g["from"], g["to"]): g["checks"] for g in mdef.get("guards", [])}
        guard_reject = {(g["from"], g["to"]): g.get("on_reject", {}) for g in mdef.get("guards", [])}
        context_names = {c["name"] for c in mdef.get("guard_context", [])}
        outcomes: dict = {}
        failing_predicates = set()
        rejections_seen = set()
        for i, case in enumerate(vec["cases"]):
            where = f"cases[{i}] {case['name']}"
            key = (case["from"], case["to"])
            if key not in machines[mid]["pairs"]:
                report.error(path, f"{where}: {key[0]}->{key[1]} is not a transition of {mid}")
                continue
            for name in case["context"]:
                if name not in context_names:
                    report.error(path, f"{where}: context member {name} is not in guard_context")
            allowed, reason, pid = evaluate_guard(guards.get(key, []), case["context"])
            outcomes.setdefault(key, set()).add(allowed)
            if pid:
                failing_predicates.add(pid)
                rejections_seen.add((key, reason))
            want = case["expected"] == "allowed"
            if allowed != want or (not allowed and reason != case.get("reason_code")):
                got = "allowed" if allowed else f"rejected with {reason} by {pid}"
                report.error(path, f"{where}: expected {case['expected']} {case.get('reason_code', '')}".rstrip()
                             + f", guards give {got}")
                continue
            if not allowed:
                entry = guard_reject.get(key, {}).get(reason, {})
                next_state = key[0] if entry.get("stay") else entry.get("to")
                if (next_state, entry.get("event")) != (case.get("expected_next_state"), case.get("expected_event")):
                    report.error(path, f"{where}: expected next state {case.get('expected_next_state')} with a "
                                       f"{case.get('expected_event')} event, on_reject gives "
                                       f"{next_state}/{entry.get('event')}")
                    continue
            report.ok()
        for key in guards:
            if outcomes.get(key) != {True, False}:
                report.error(path, f"guarded transition {key[0]}->{key[1]} needs an allowed and a rejected case")
        used = {p for checks in guards.values() for p in checks}
        for pid in sorted(used - failing_predicates):
            report.error(path, f"no case where predicate {pid} is the one that fails")
        for key, on_reject in sorted(guard_reject.items()):
            for rc in sorted(on_reject):
                if (key, rc) not in rejections_seen:
                    report.error(path, f"no case rejects {key[0]}->{key[1]} with {rc} (on_reject entry untested)")
    for mid in sorted(guarded_machines - seen):
        report.error(D_GUARDS, f"no guard vectors for machine {mid}")


def resolve_exit_code(inp: dict, ctx: dict) -> int:
    """Interpret the resolution rules of registry/exit-codes.json (first match wins)."""
    for rule in ctx["exit_rules"]:
        m = rule["match"]
        if "usage_error" in m and inp.get("usage_error", False) != m["usage_error"]:
            continue
        if "interrupted" in m and inp.get("interrupted", False) != m["interrupted"]:
            continue
        if "incomplete" in m and inp.get("incomplete", False) != m["incomplete"]:
            continue
        if "succeeded" in m and inp.get("succeeded", False) != m["succeeded"]:
            continue
        if "machine" in m and ctx.get("operation_kinds", {}).get(inp.get("operation")) not in m["machine"]:
            continue
        if "final_state" in m and inp.get("final_state") not in m["final_state"]:
            continue
        if "interactive" in m and inp.get("interactive") != m["interactive"]:
            continue
        if "has_reason_code" in m and ("reason_code" in inp) != m["has_reason_code"]:
            continue
        if rule["exit_code"] == "from_reason_code":
            entry = ctx.get("reason_codes", {}).get(inp.get("reason_code"))
            return entry["cli_exit_code"] if entry else ctx["exit_fallback"]
        return rule["exit_code"]
    return ctx["exit_fallback"]


def check_exit_vectors(ctx: dict, report: Report) -> None:
    data = ctx["files"].get(P_EXIT_VECTORS)
    if data is None:
        report.error(P_EXIT_VECTORS, "missing")
        return
    if "exit_rules" not in ctx:
        report.error(P_EXIT_VECTORS, "exit-code registry is invalid; cannot check vectors")
        return
    if not validate_against(data, "schemas/exit-code-vector.schema.json", P_EXIT_VECTORS, ctx, report):
        return
    machines = ctx.get("machines", {})

    def lifecycle(mid):
        mdata = machines.get(mid)
        return mdata if mdata and mdata["def"]["kind"] == "lifecycle" else None

    # Rules: states are keyed by machine (SEC-M4, CR-18).
    for r in ctx["exit_rules"]:
        m = r["match"]
        if "final_state" in m and "machine" not in m:
            report.error(P_EXIT_CODES, f"resolution rule {r['id']}: final_state requires machine")
        for mid in m.get("machine", []):
            mdata = lifecycle(mid)
            if mdata is None:
                report.error(P_EXIT_CODES, f"resolution rule {r['id']}: {mid} is not a lifecycle machine")
                continue
            for s in m.get("final_state", []):
                if s not in mdata["states"]:
                    report.error(P_EXIT_CODES, f"resolution rule {r['id']}: {s} is not a state of {mid}")
    succ_states = ctx.get("succeeded_final_states", {})
    for mid, states in succ_states.items():
        mdata = lifecycle(mid)
        if mdata is None:
            report.error(P_EXIT_CODES, f"succeeded_final_states: {mid} is not a lifecycle machine")
            continue
        for s in states:
            if s not in mdata["states"]:
                report.error(P_EXIT_CODES, f"succeeded_final_states: {s} is not a state of {mid}")
            if s in ("FAILED", "CANCELLED"):
                report.error(P_EXIT_CODES, f"succeeded_final_states: {mid}/{s} can never be a success")
    hit_codes = set()
    kinds = ctx.get("operation_kinds", {})
    for i, case in enumerate(data["cases"]):
        inp = case["input"]
        where = f"cases[{i}] {case['name']}"
        op, fs = inp.get("operation"), inp.get("final_state")
        mid = kinds.get(op)
        mdata = lifecycle(mid) if mid else None
        if fs is not None and op is None:
            report.error(P_EXIT_VECTORS, f"{where}: final_state requires operation")
        if fs is not None and mdata is not None and fs not in mdata["states"]:
            report.error(P_EXIT_VECTORS, f"{where}: {fs} is not a state of {op} (machine {mid})")
        if inp.get("succeeded"):
            if fs is not None and fs not in succ_states.get(mid, []):
                report.error(P_EXIT_VECTORS, f"{where}: succeeded=true is inconsistent with {op}/{fs} "
                                             "(see resolution.succeeded_final_states)")
        if inp.get("incomplete"):
            if inp.get("succeeded"):
                report.error(P_EXIT_VECTORS, f"{where}: incomplete and succeeded are exclusive")
            if fs is not None and mdata is not None and (
                    fs in mdata["def"]["terminal"] or fs in mdata["def"].get("waiting", [])):
                report.error(P_EXIT_VECTORS, f"{where}: incomplete with a terminal or waiting state {fs}")
        got = resolve_exit_code(inp, ctx)
        hit_codes.add(got)
        if got != case["exit_code"]:
            report.error(P_EXIT_VECTORS, f"cases[{i}] {case['name']}: expected exit {case['exit_code']}, "
                                         f"rules give {got}")
        else:
            report.ok()
    missing = set(ctx["exit_codes"]) - hit_codes
    if missing:
        report.error(P_EXIT_VECTORS, f"no vector produces exit codes {sorted(missing)}")


def _event_semantic_errors(event, ctx: dict, producer: bool) -> list[str]:
    errs = []
    if not isinstance(event, dict):
        return errs
    prog = event.get("progress")
    if isinstance(prog, dict) and isinstance(prog.get("current"), int) and isinstance(prog.get("total"), int):
        if prog["current"] > prog["total"]:
            errs.append("progress.current is greater than progress.total")
    if producer:
        rc = event.get("reason_code")
        if isinstance(rc, str) and rc not in ctx.get("reason_codes", {}):
            errs.append(f"reason_code {rc} is not in {P_REASON_CODES}")
        op = event.get("operation")
        if isinstance(op, str):
            mid = ctx.get("operation_kinds", {}).get(op)
            machine = ctx.get("machines", {}).get(mid) if mid else None
            if machine is None or machine["def"]["kind"] != "lifecycle":
                errs.append(f"operation {op} is not an operation kind in {P_STATE_MACHINES}")
            elif event.get("state") not in machine["states"]:
                errs.append(f"state {event.get('state')} is not a state of {op} (machine {mid})")
    return errs


def consumer_view(event, schema):
    """Consumer rule: drop members unknown to this schema version, top level and inside progress."""
    if not isinstance(event, dict):
        return event
    props = schema["properties"]
    view = {k: v for k, v in event.items() if k in props}
    prog = view.get("progress")
    if isinstance(prog, dict):
        view["progress"] = {k: v for k, v in prog.items() if k in props["progress"]["properties"]}
    return view


def check_event_vectors(ctx: dict, report: Report) -> None:
    data = ctx["files"].get(P_EVENT_VECTORS)
    if data is None:
        report.error(P_EVENT_VECTORS, "missing")
        return
    if not validate_against(data, "schemas/operation-event-vector.schema.json", P_EVENT_VECTORS, ctx, report):
        return
    schema = ctx["schemas"].get(P_EVENT_SCHEMA)
    if schema is None:
        report.error(P_EVENT_VECTORS, "operation-event schema missing")
        return
    seen = {("producer", True): False, ("producer", False): False,
            ("consumer", True): False, ("consumer", False): False}
    for i, case in enumerate(data["cases"]):
        event = case["event"]
        p_errs = schema_errors(event, schema, schema) + _event_semantic_errors(event, ctx, producer=True)
        view = consumer_view(event, schema)
        c_errs = schema_errors(view, schema, schema) + _event_semantic_errors(view, ctx, producer=False)
        for role, errs in (("producer", p_errs), ("consumer", c_errs)):
            want = case[role]
            seen[(role, want)] = True
            if (not errs) != want:
                detail = "; ".join(errs) if errs else "accepted"
                report.error(P_EVENT_VECTORS, f"cases[{i}] {case['name']}: expected {role}={want}, got {detail}")
            else:
                report.ok()
        if case["producer"] and not case["consumer"]:
            report.error(P_EVENT_VECTORS, f"cases[{i}] {case['name']}: an event valid for producers "
                                          "must be accepted by consumers")
    for key, present in seen.items():
        if not present:
            report.error(P_EVENT_VECTORS, f"no case with {key[0]}={key[1]}")


def run_checks(ctx: dict, report: Report) -> None:
    check_version(ctx, report)
    check_schemas(ctx, report)
    check_exit_codes(ctx, report)
    check_reason_codes(ctx, report)
    check_state_machines(ctx, report)
    check_canonical_vectors(ctx, report)
    check_transition_vectors(ctx, report)
    check_guard_vectors(ctx, report)
    check_exit_vectors(ctx, report)
    check_event_vectors(ctx, report)


# --------------------------------------------------------------------------
# Self-test: every known-bad change must be detected
# --------------------------------------------------------------------------

def _machine(ctx: dict, mid: str) -> dict:
    return next(m for m in ctx["files"][P_STATE_MACHINES]["machines"] if m["id"] == mid)


def _add_edge(mid, f, t):
    return (f"{mid}: add {f}->{t}",
            lambda ctx: _machine(ctx, mid)["transitions"].append({"from": f, "to": t}), "machines")


def _remove_edge(mid, f, t):
    def apply(ctx):
        m = _machine(ctx, mid)
        m["transitions"] = [x for x in m["transitions"] if (x["from"], x["to"]) != (f, t)]
    return (f"{mid}: remove {f}->{t}", apply, "machines")


def _add_node_failed(ctx):
    m = _machine(ctx, "node_status")
    m["states"].append({"name": "FAILED", "description": {"ru": "x", "en": "x"}})
    m["transitions"].append({"from": "DRAINING", "to": "FAILED"})
    m["terminal"].append("FAILED")


def _tamper_canonical(ctx):
    vec = ctx["canonical"][D_CANONICAL + "key-ordering-flat.json"]
    vec["canonical"] = vec["canonical"].replace('"a":1', '"a":9')


def _swap_rule(ctx):
    for r in ctx["files"][P_EXIT_CODES]["resolution"]["rules"]:
        if r["id"] == "action_required":
            r["exit_code"] = 1


def _drop_error_rule(ctx):
    schema = ctx["files"][P_EVENT_SCHEMA]
    schema.pop("if", None)
    schema.pop("then", None)


def _dangling_ref(ctx):
    schema = ctx["files"]["schemas/reason-code-registry.schema.json"]
    schema["properties"]["reason_codes"]["items"]["$ref"] = "#/$defs/missing"


def _codepoint_sort(ctx):
    global SORT_KEY
    SORT_KEY = lambda s: s  # noqa: E731 - code point order instead of UTF-16 code units


def _drop_guard(mid, f, t):
    def apply(ctx):
        m = _machine(ctx, mid)
        m["guards"] = [g for g in m["guards"] if (g["from"], g["to"]) != (f, t)]
    return (f"{mid}: drop guard of {f}->{t}", apply, "machines")


def _drop_check(mid, f, t, pid):
    def apply(ctx):
        for g in _machine(ctx, mid)["guards"]:
            if (g["from"], g["to"]) == (f, t):
                g["checks"] = [c for c in g["checks"] if c != pid]
    return (f"{mid}: drop {pid} from guard of {f}->{t}", apply, "machines")


def _drop_clear_consent(ctx):
    _machine(ctx, "bootstrap")["effects"] = []


def _flip_requires_consent(ctx):
    for p in _machine(ctx, "bootstrap")["guard_predicates"]:
        if p["id"] == "image_in_consented_plan":
            p["requires_consent"] = False


def _unkey_ready_rule(ctx):
    for r in ctx["files"][P_EXIT_CODES]["resolution"]["rules"]:
        if r["id"] == "ready":
            r["match"].pop("machine")


def _succeed_on_failed(ctx):
    ctx["files"][P_EXIT_CODES]["resolution"]["succeeded_final_states"]["bootstrap"].append("FAILED")


def _operation_optional(ctx):
    ctx["files"][P_EVENT_SCHEMA]["required"].remove("operation")


def _message_any_text(ctx):
    ctx["files"][P_EVENT_SCHEMA]["properties"]["message"].pop("pattern")


def _unanchored_pattern(ctx):
    ctx["files"][P_EVENT_SCHEMA]["properties"]["state"]["pattern"] = "^[A-Z][A-Z0-9_]*"


def _guard(ctx, f, t):
    return next(g for g in _machine(ctx, "bootstrap")["guards"] if (g["from"], g["to"]) == (f, t))


def _reject_uncovered(ctx):
    _guard(ctx, "WAITING_FOR_CONSENT", "INSTALLING")["on_reject"].pop("PLAN_STALE")


def _reject_stay_outside_waiting(ctx):
    _guard(ctx, "INSTALLING", "WAITING_FOR_PRIVILEGE")["on_reject"]["CONSENT_REQUIRED"] = {"stay": True, "event": "state"}


def _reject_to_non_edge(ctx):
    _guard(ctx, "ENGINE_CHECK", "IMAGE_PULL")["on_reject"]["CONSENT_REQUIRED"] = {"to": "READY", "event": "state"}


def _reject_wrong_target(ctx):
    _guard(ctx, "PLAN_READY", "ENGINE_CHECK")["on_reject"]["CONSENT_REQUIRED"] = {"to": "PROBING", "event": "state"}


def _reject_wrong_event(ctx):
    _guard(ctx, "ENGINE_CHECK", "IMAGE_PULL")["on_reject"]["IMAGE_NOT_ALLOWED"]["event"] = "state"


def _drop_set_consent(ctx):
    m = _machine(ctx, "bootstrap")
    m["effects"] = [e for e in m["effects"] if e["action"] != "set_consented_plan_id"]


def _task_restart(ctx):
    _machine(ctx, "task")["transitions"].append({"from": "FAILED", "to": "RUNNING"})


def _kind_remapped(ctx):
    for k in ctx["files"][P_STATE_MACHINES]["operation_kinds"]:
        if k["kind"] == "model_pull":
            k["machine"] = "bootstrap"


def _task_succeeded_not_zero(ctx):
    for r in ctx["files"][P_EXIT_CODES]["resolution"]["rules"]:
        if r["id"] == "task_succeeded":
            r["exit_code"] = 1


def _hash_vector_without_kind(ctx):
    vec = ctx["canonical"][D_CANONICAL + "object-hash-without-hash-member.json"]
    vec["input"].pop("kind")


SELF_TEST_MUTATIONS = [
    # bootstrap: READY only after SMOKE_TEST (CF16)
    _add_edge("bootstrap", "PLAN_READY", "READY"),
    _add_edge("bootstrap", "WAITING_FOR_PRIVILEGE", "READY"),
    _add_edge("bootstrap", "ENGINE_CHECK", "READY"),
    _add_edge("bootstrap", "IMAGE_PULL", "READY"),
    _add_edge("bootstrap", "NEW", "READY"),
    _add_edge("bootstrap", "FAILED", "READY"),
    # bootstrap: INSTALLING only after consent (CF13, CR-13)
    _add_edge("bootstrap", "ACTION_REQUIRED", "INSTALLING"),
    _add_edge("bootstrap", "PROBING", "INSTALLING"),
    _add_edge("bootstrap", "PLAN_READY", "INSTALLING"),
    _add_edge("bootstrap", "READY", "INSTALLING"),
    _add_edge("bootstrap", "PROBING", "WAITING_FOR_PRIVILEGE"),
    # bootstrap: re-verification (CF15, CF18)
    _add_edge("bootstrap", "REBOOT_REQUIRED", "INSTALLING"),
    _add_edge("bootstrap", "REBOOT_REQUIRED", "ENGINE_CHECK"),
    _add_edge("bootstrap", "ACTION_REQUIRED", "ENGINE_CHECK"),
    _add_edge("bootstrap", "CANCELLED", "SMOKE_TEST"),
    _add_edge("bootstrap", "READY", "IMAGE_PULL"),
    _remove_edge("bootstrap", "SMOKE_TEST", "READY"),
    _remove_edge("bootstrap", "REBOOT_REQUIRED", "PROBING"),
    _remove_edge("bootstrap", "INSTALLING", "PROBING"),
    _remove_edge("bootstrap", "WAITING_FOR_PRIVILEGE", "PROBING"),
    _remove_edge("bootstrap", "SMOKE_TEST", "PROBING"),
    _remove_edge("bootstrap", "READY", "PROBING"),
    # bootstrap: SEC-M1 (image pull is an action), SEC-M2 (guards), SEC-M3 (restart in any state)
    _add_edge("bootstrap", "WAITING_FOR_CONSENT", "ENGINE_CHECK"),
    _add_edge("bootstrap", "PLAN_READY", "IMAGE_PULL"),
    _remove_edge("bootstrap", "PLAN_READY", "PROBING"),
    _remove_edge("bootstrap", "WAITING_FOR_CONSENT", "PROBING"),
    _drop_guard("bootstrap", "ENGINE_CHECK", "IMAGE_PULL"),
    _drop_guard("bootstrap", "PLAN_READY", "ENGINE_CHECK"),
    _drop_check("bootstrap", "WAITING_FOR_CONSENT", "INSTALLING", "consent_matches_plan"),
    _drop_check("bootstrap", "WAITING_FOR_PRIVILEGE", "INSTALLING", "privilege_granted"),
    _drop_check("bootstrap", "INSTALLING", "WAITING_FOR_PRIVILEGE", "step_is_privileged_plan_step"),
    _drop_check("bootstrap", "ENGINE_CHECK", "IMAGE_PULL", "image_allowlisted"),
    ("bootstrap: PROBING no longer clears consent", _drop_clear_consent, "machines"),
    ("bootstrap: image_in_consented_plan marked as not needing consent", _flip_requires_consent, "machines"),
    # node_status (CF42, CF43, CR-14)
    _add_edge("node_status", "DRAINING", "BUSY"),
    _add_edge("node_status", "DRAINING", "READY"),
    _add_edge("node_status", "OFFLINE", "BUSY"),
    _add_edge("node_status", "OFFLINE", "READY"),
    _add_edge("node_status", "REGISTERED", "BUSY"),
    _add_edge("node_status", "CONNECTING", "BUSY"),
    ("node_status: add FAILED status", _add_node_failed, "machines"),
    # wsl_availability (CW02)
    _add_edge("wsl_availability", "WSL2_READY", "WSL_MISSING"),
    _add_edge("wsl_availability", "VIRTUALIZATION_DISABLED", "WSL2_READY"),
    _add_edge("wsl_availability", "UNSUPPORTED_PROFILE", "WSL2_READY"),
    # data and vectors
    ("canonical vector with tampered canonical text", _tamper_canonical, "all"),
    ("code point key order instead of UTF-16 code units", _codepoint_sort, "all"),
    ("exit resolution: ACTION_REQUIRED no longer gives 3", _swap_rule, "all"),
    ("event schema: error without reason_code accepted", _drop_error_rule, "all"),
    ("schema with a dangling $ref", _dangling_ref, "all"),
    ("exit resolution: READY not keyed by operation", _unkey_ready_rule, "all"),
    ("exit resolution: succeeded allowed with FAILED", _succeed_on_failed, "all"),
    ("event schema: operation optional", _operation_optional, "all"),
    ("event schema: message accepts control characters", _message_any_text, "all"),
    ("schema pattern without $ anchor", _unanchored_pattern, "all"),
    ("object_hash vector without kind", _hash_vector_without_kind, "all"),
    # CR-17: what follows a rejected guard
    ("on_reject misses a reason code", _reject_uncovered, "machines"),
    ("on_reject stays in a non-waiting state", _reject_stay_outside_waiting, "machines"),
    ("on_reject targets a state without a transition", _reject_to_non_edge, "machines"),
    ("on_reject deviates from the agreed mapping", _reject_wrong_target, "machines"),
    ("on_reject emits the wrong event type", _reject_wrong_event, "machines"),
    # N1, N3
    _drop_check("bootstrap", "ENGINE_CHECK", "SMOKE_TEST", "image_present_by_digest"),
    _drop_check("bootstrap", "IMAGE_PULL", "SMOKE_TEST", "image_present_by_digest"),
    ("bootstrap: user consent no longer sets consented_plan_id", _drop_set_consent, "machines"),
    # CR-18
    ("task: FAILED restarted in place", _task_restart, "machines"),
    ("operation_kinds: model_pull mapped to bootstrap", _kind_remapped, "machines"),
    ("exit resolution: task SUCCEEDED no longer gives 0", _task_succeeded_not_zero, "all"),
]


def self_test(base: dict) -> int:
    global SORT_KEY
    report = Report()
    run_checks(copy.deepcopy(base), report)
    if report.errors:
        for e in report.errors:
            print(f"FAIL {e}", file=sys.stderr)
        print("self-test: the unmodified repository does not validate", file=sys.stderr)
        return 1
    failures = 0
    for label, mutate, scope in SELF_TEST_MUTATIONS:
        ctx = copy.deepcopy(base)
        r = Report()
        try:
            mutate(ctx)
            if scope == "machines":
                # Registry checks only: the mutation must be caught structurally,
                # not merely by missing vector coverage.
                check_schemas(ctx, r)
                check_exit_codes(ctx, r)
                check_reason_codes(ctx, r)
                check_state_machines(ctx, r)
            else:
                run_checks(ctx, r)
        finally:
            SORT_KEY = utf16_key
        if r.errors:
            print(f"ok    {label}  ->  {r.errors[0].splitlines()[0]}")
        else:
            print(f"MISS  {label}: not detected", file=sys.stderr)
            failures += 1
    if failures:
        print(f"self-test: {failures} of {len(SELF_TEST_MUTATIONS)} mutation(s) not detected", file=sys.stderr)
        return 1
    print(f"self-test: OK ({len(SELF_TEST_MUTATIONS)} mutations detected)")
    return 0


def main(argv: list) -> int:
    args = argv[1:]
    if args not in ([], ["--self-test"]):
        print("usage: validate.py [--self-test]", file=sys.stderr)
        return 2
    report = Report()
    ctx = load_repo(report)
    if report.errors:
        for e in report.errors:
            print(f"FAIL {e}", file=sys.stderr)
        print(f"validate: {len(report.errors)} error(s) while loading", file=sys.stderr)
        return 1
    if args == ["--self-test"]:
        return self_test(ctx)
    run_checks(ctx, report)
    if report.errors:
        for e in report.errors:
            print(f"FAIL {e}", file=sys.stderr)
        print(f"validate: {len(report.errors)} error(s), {report.checks} check(s) passed", file=sys.stderr)
        return 1
    print(f"validate: OK ({report.checks} checks, {len(ctx.get('reason_codes', {}))} reason codes, "
          f"{len(ctx.get('machines', {}))} state machines)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
