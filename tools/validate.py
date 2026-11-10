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
  * state-transition, exit-code resolution and OperationEvent test vectors;
  * the InstallationPlan step-kind registry (closed vocabulary, privilege per
    platform, elevated-helper operations) and InstallationPlan vectors with
    their derived guard inputs (docs/installation-plan.md);
  * image allowlist, ownership labels and WSL resources registries, schemas and
    vectors; schema definitions copied between files are identical;
  * the step-failure registry (failure class -> reason code and next state, per
    step kind and platform) and its vectors; the download redirect rule
    (redirect_hosts) and the container run profiles with their vectors;
  * guard predicate `reads` equal the inputs of the reference predicates.

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
from urllib.parse import urlsplit

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
P_STEP_KINDS = "registry/plan-step-kinds.json"
P_ALLOWLIST = "registry/image-allowlist.json"
P_OWNERSHIP = "registry/ownership.json"
P_PLAN_SCHEMA = "schemas/installation-plan.schema.json"
P_ALLOWLIST_SCHEMA = "schemas/image-allowlist.schema.json"
P_IMAGE_SCHEMA = "schemas/image-reference.schema.json"
P_WSL_SCHEMA = "schemas/wsl-resources.schema.json"
D_PLANS = "test-vectors/installation-plans/"
D_EFFECTS = "test-vectors/effects/"
P_PRECONDITION_VECTORS = "test-vectors/step-preconditions/cases.json"
P_ALLOWLIST_VECTORS = "test-vectors/image-allowlist/cases.json"
P_OWNERSHIP_VECTORS = "test-vectors/ownership/cases.json"
P_WSL_VECTORS = "test-vectors/wsl-resources/cases.json"
P_STEP_FAILURES = "registry/step-failures.json"
P_STEP_FAILURE_VECTORS = "test-vectors/step-failures/cases.json"
P_REDIRECT_VECTORS = "test-vectors/download-redirects/cases.json"
P_RUN_PROFILES = "registry/run-profiles.json"
P_RUN_PROFILE_VECTORS = "test-vectors/run-profiles/cases.json"
# Files parsed under the hashing restrictions of docs/canonical-json.md section 3 (hashed or
# hash-parsed documents and the vectors that carry them).
HASHABLE_PREFIXES = (D_CANONICAL, D_PLANS, P_ALLOWLIST, P_ALLOWLIST_VECTORS)

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
# Codes introduced by this repository (sprut-contracts 0.2.0, issue #3): touching a resource that
# is not Sprut's, and a plan document that violates docs/installation-plan.md.
CONTRACT_REASON_CODES = ["FOREIGN_RESOURCE", "PLAN_INVALID", "ENGINE_TCP_EXPOSED"]
# sprut-contracts 0.3.0 (CR-45): a failure is reported with a code of its own, never with a code
# that describes another condition.
CONTRACT_REASON_CODES_0_3 = ["STEP_FAILED", "WSL_COMMAND_FAILED", "ENGINE_COMMAND_FAILED", "ELEVATED_STEP_FAILED",
                             "ELEVATION_UNAVAILABLE", "SECRET_STORE_FAILED", "PACKAGE_INSTALL_FAILED", "PROBE_FAILED",
                             "LOCAL_STORAGE_FAILED", "ENGINE_DOCKER_DESKTOP"]
RAW_INVISIBLE = re.compile("[\u0000-\u001f\u007f-\u009f​-‏ -‮⁦-⁩﻿]")
# Plan and ownership rules that --self-test switches off to prove the vectors notice.
RULE_SWITCHES = {"unregister_pairing": True, "docker_access": True, "wslconfig_replaced": True,
                 "licence_required": True, "adoption_needs_journal": True,
                 "redirect_host_check": True, "redirect_every_hop": True, "redirect_https_hops": True,
                 "redirect_prefix_on_requested_only": True, "requested_url_strict": True, "download_size_cap": True,
                 "run_profile_closed": True, "run_profile_exactly_once": True, "run_profile_nothing_after_image": True,
                 "wsl_exit_range": True, "probe_failure_is_not_evidence": True, "docker_desktop_wins": True}
_RULE_SWITCHES_DEFAULT = dict(RULE_SWITCHES)

# InstallationPlan step kinds (docs/installation-plan.md, registry/plan-step-kinds.json): the closed
# vocabulary and its privilege per platform. True = host elevation (UAC / sudo). Windows steps run
# as root inside the Sprut distribution are not host elevation (CW04, CW05); Linux root steps use
# sudo (spec 7.4 item 1).
SPEC_STEP_KINDS = {
    "enable_wsl_features": {"windows": True},
    "enable_vm_platform": {"windows": True},
    "install_wsl": {"windows": True},
    "update_wsl": {"windows": True},
    "unregister_distro": {"windows": False},
    "import_distro": {"windows": False},
    "configure_distro": {"windows": False},
    "apt_add_docker_repo": {"windows": False, "linux": True},
    "install_docker_engine": {"windows": False, "linux": True},
    "add_user_to_docker_group": {"linux": True},
    "install_nvidia_toolkit": {"windows": False, "linux": True},
    "start_engine": {"windows": False, "linux": True},
    "write_wslconfig": {"windows": False},
    "resize_distro_disk": {"windows": False},
    "restart_wsl": {"windows": False},
    "image_pull": {"windows": False, "linux": False},
}
# The Windows elevated-helper vocabulary (Java ElevatedStep), issue #3 item 7.
SPEC_WINDOWS_ELEVATED = {"enable_wsl_features": "ENABLE_WSL_FEATURES", "enable_vm_platform": "ENABLE_VM_PLATFORM",
                         "install_wsl": "INSTALL_WSL", "update_wsl": "UPDATE_WSL"}
SPEC_SOURCE_REQUIRED = {"import_distro", "apt_add_docker_repo", "install_nvidia_toolkit"}  # CW04, CW05, 7.4
SPEC_FLAG_ALWAYS = {("add_user_to_docker_group", "requires_relogin"),  # spec 7.4 item 3
                    ("write_wslconfig", "requires_wsl_restart")}     # CR04
SPEC_REBOOT_MAY = set(SPEC_WINDOWS_ELEVATED)                            # CW03: only WSL/feature steps
STEP_MEMBERS = ("image", "source", "wslconfig", "wslconfig_file", "distro_disk_size", "distro", "target_user")
# CR-72: on a Linux host the engine restart of install_nvidia_toolkit stops containers that are not Sprut's.
SPEC_PLATFORM_ACKNOWLEDGEMENTS = {("install_nvidia_toolkit", "linux"): "engine_restart"}
# CR-71: by default apt-get update exits 0 when an index cannot be fetched.
APT_UPDATE_ARGV = ["/usr/bin/apt-get", "update", "-o", "APT::Update::Error-Mode=any"]
# CR-77: per-kind download limits (max_bytes, timeout_seconds). Provisional, confirmed at S-1.
SPEC_DOWNLOAD_LIMITS = {
    "install_wsl": (536870912, 1800), "update_wsl": (536870912, 1800), "import_distro": (1073741824, 3600),
    "apt_add_docker_repo": (65536, 60), "install_nvidia_toolkit": (65536, 60),
}
SPEC_ACKNOWLEDGEMENTS = {"add_user_to_docker_group": "docker_group",  # spec 7.4 item 3, SEC-C1
                         "unregister_distro": "distro_removal"}        # CW04, SEC-C2
SPEC_LICENCE_REQUIRED = {"import_distro"}                              # Ubuntu rootfs (Q10), SEC-m2
SPEC_STEP_PRECONDITIONS = {
    # SEC-5: installing or updating WSL can stop every distribution; confirmed like restart_wsl, before the hash.
    "install_wsl": ["wsl_restart_confirmed", "source_verified"],
    "update_wsl": ["wsl_restart_confirmed", "source_verified"],
    "import_distro": ["source_verified"],
    "apt_add_docker_repo": ["ubuntu_supported", "source_verified"],
    "install_nvidia_toolkit": ["ubuntu_supported", "sprut_drained", "source_verified"],  # CR-72: restarts the engine
    "install_docker_engine": ["ubuntu_supported"],
    "add_user_to_docker_group": ["target_user_current"],
    # SEC-1: nothing is removed before the replacement rootfs is downloaded and verified; CR-49: drain first.
    "unregister_distro": ["distro_owned", "sprut_drained", "replacement_source_verified"],
    "configure_distro": ["sprut_drained"],    # CR-49: it terminates the Sprut distribution
    "resize_distro_disk": ["sprut_drained"],  # CR-49
    "write_wslconfig": ["wslconfig_unchanged"],
    "restart_wsl": ["wsl_restart_confirmed"],  # CR04: a separate confirmed action
}
# CR-58 / SEC-11: hosts a download may end on besides the requested host. Provisional (S-1): the
# GitHub release-asset CDN hosts for the WSL package. Any other entry needs a change here.
SPEC_REDIRECT_HOSTS = {
    "install_wsl": ["objects.githubusercontent.com", "release-assets.githubusercontent.com"],
    "update_wsl": ["objects.githubusercontent.com", "release-assets.githubusercontent.com"],
}
HOST_NAME = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,63}")
MAX_REDIRECTS = 5
# CR-49: wsl.exe arguments (and the WSL package installer) that stop the Sprut distribution.
DISTRO_STOPPING_ARGS = {"--terminate", "--unregister", "--shutdown", "--install", "--update"}
# CR-72, CR-83: systemctl verbs that stop the engine (disable/mask only with --now) and its units.
ENGINE_STOPPING_VERBS = {"stop", "restart", "try-restart", "reload-or-restart", "try-reload-or-restart", "kill"}
ENGINE_UNITS = {"docker", "docker.service", "docker.socket"}
# CR-45: failure class -> (reason code, next state, event). The order is the registry order.
SPEC_FAILURE_CLASSES = {
    "source_unavailable": ("SOURCE_UNAVAILABLE", "FAILED", "error"),
    # The client's own files of a step: a full disk when positively known, any other write failure otherwise.
    "insufficient_disk": ("INSUFFICIENT_DISK", "ACTION_REQUIRED", "error"),
    "local_storage_failed": ("LOCAL_STORAGE_FAILED", "ACTION_REQUIRED", "error"),
    "package_install_failed": ("PACKAGE_INSTALL_FAILED", "FAILED", "error"),
    "wsl_command_failed": ("WSL_COMMAND_FAILED", "FAILED", "error"),
    "command_failed": ("STEP_FAILED", "FAILED", "error"),
    "plan_refused": ("PLAN_INVALID", "FAILED", "error"),  # CR-73: the elevated helper refused the plan
    "elevation_unavailable": ("ELEVATION_UNAVAILABLE", "ACTION_REQUIRED", "error"),
    "elevated_step_failed": ("ELEVATED_STEP_FAILED", "FAILED", "error"),
    "smoke_test_failed": ("SMOKE_TEST_FAILED", "FAILED", "error"),
    "engine_docker_desktop": ("ENGINE_DOCKER_DESKTOP", "ACTION_REQUIRED", "error"),  # CW06
    "engine_command_failed": ("ENGINE_COMMAND_FAILED", "FAILED", "error"),
    "probe_failed": ("PROBE_FAILED", "FAILED", "error"),  # CR-74: the catch-all of checks outside plan steps
}
DOCKER_DESKTOP = "Docker Desktop"
# Bootstrap states whose work is not a plan step, and the failure classes of their checks.
SPEC_STATE_FAILURES = {
    "PROBING": {"windows": ["wsl_command_failed", "engine_docker_desktop", "engine_command_failed", "probe_failed"],
                "linux": ["engine_docker_desktop", "engine_command_failed", "probe_failed"]},
    "ENGINE_CHECK": {"windows": ["wsl_command_failed", "engine_docker_desktop", "engine_command_failed", "probe_failed"],
                     "linux": ["engine_docker_desktop", "engine_command_failed", "probe_failed"]},
    "SMOKE_TEST": {"windows": ["wsl_command_failed", "smoke_test_failed", "engine_docker_desktop",
                               "engine_command_failed", "probe_failed"],
                   "linux": ["smoke_test_failed", "engine_docker_desktop", "engine_command_failed", "probe_failed"]},
}
# SEC-15: the diagnostic (smoke-test) container; other profiles need their own security review.
SPEC_DIAGNOSTIC_OPTIONS = [["--pull=never"], ["--network", "none"], ["--cap-drop", "ALL"],
                           ["--security-opt", "no-new-privileges"], ["--read-only"],
                           ["--pids-limit", "{pids_limit}"], ["--memory", "{memory_limit}"]]
SPEC_DIAGNOSTIC_OTHER_OPTIONS = [["--detach"], ["--name", "{container_name}"], ["--label", "{label}"]]
SPEC_RUN_PROFILES = {"diagnostic": "normative", "worker": "to_be_defined", "inference": "to_be_defined"}
SPEC_PLACEHOLDERS = {"system32", "distro_name", "distro_base_path", "verified_file", "target_user", "codename",
                     "distro_disk_size"}
# Placeholder -> step member it needs (a kind may use the placeholder only if it has that member).
PLACEHOLDER_MEMBER = {"verified_file": "source", "target_user": "target_user", "distro_disk_size": "distro_disk_size"}
FORBIDDEN_PROGRAMS = {"sh", "bash", "dash", "zsh", "ksh", "fish", "cmd.exe", "powershell.exe", "pwsh", "pwsh.exe",
                      "python", "python3", "perl", "curl", "wget", "sudo", "su", "wscript.exe", "cscript.exe",
                      "env", "xargs", "nohup", "timeout"}  # SEC-N4: no program launchers either
ALLOWED_ENVIRONMENT = {"DEBIAN_FRONTEND": "noninteractive"}
PREFIX_SHAPE = re.compile(r"^https://[a-z0-9.-]+/(.*/)?$")  # CR-26
STEP_FLAGS = ("requires_reboot", "requires_relogin", "requires_wsl_restart")
STATE_COMPONENT_PLATFORMS = {"wsl": "windows", "sprut_distro": "windows", "docker_group": "linux"}
SPEC_LABEL_NAMESPACE = "io.github.alexindacomp.sprut"
SPEC_LABELLED_RESOURCES = {"container", "volume", "network"}  # CF22
# Definitions copied verbatim between schemas (only local $refs are supported): (copy, source).
SHARED_DEFS = [
    ((P_ALLOWLIST_SCHEMA, "image_digest"), (P_IMAGE_SCHEMA, "image_digest")),
    ((P_ALLOWLIST_SCHEMA, "repository"), (P_IMAGE_SCHEMA, "repository")),
    ((P_PLAN_SCHEMA, "image_reference"), (P_IMAGE_SCHEMA, "image_reference")),
    ((P_PLAN_SCHEMA, "wslconfig_wsl2"), (P_WSL_SCHEMA, "wslconfig_wsl2")),
    ((P_PLAN_SCHEMA, "disk_size"), (P_WSL_SCHEMA, "disk_size")),
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
            ("ENGINE_CHECK", "IMAGE_PULL"): {"engine_endpoint_local", "consent_matches_plan", "image_allowlisted",
                                             "image_in_consented_plan"},
            ("ENGINE_CHECK", "SMOKE_TEST"): {"engine_endpoint_local", "image_allowlisted",
                                             "image_present_by_digest"},  # N1, SEC-B1
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
                                             "IMAGE_NOT_ALLOWED": ("FAILED", "error"),
                                             "ENGINE_REMOTE_CONTEXT": ("ACTION_REQUIRED", "error"),
                                             "ENGINE_TCP_EXPOSED": ("ACTION_REQUIRED", "error")},
            ("ENGINE_CHECK", "SMOKE_TEST"): {"IMAGE_NOT_ALLOWED": ("FAILED", "error"),
                                             "PLAN_STALE": ("PROBING", "state"),
                                             "ENGINE_REMOTE_CONTEXT": ("ACTION_REQUIRED", "error"),
                                             "ENGINE_TCP_EXPOSED": ("ACTION_REQUIRED", "error")},
            ("IMAGE_PULL", "SMOKE_TEST"): {"IMAGE_NOT_ALLOWED": ("FAILED", "error"),
                                           "PLAN_STALE": ("PROBING", "state")},
        },
        "required_effects": [("enter_state", "PROBING", "clear_consent"),
                             ("user_consent", "WAITING_FOR_CONSENT", "set_consented_plan_id")],
        # CR-20: consent is set only after every licence and acknowledgement; otherwise it stays unset.
        "required_effect_checks": {("user_consent", "WAITING_FOR_CONSENT", "set_consented_plan_id"): "terms_accepted"},
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
                   "WSL_POLICY_BLOCKED", "UNSUPPORTED_PROFILE"},
        "required_edges": [("WSL_MISSING", "WSL2_READY"), ("WSL_OUTDATED", "WSL2_READY")],
        "preds_equal": {},
        "preds_subset": {"WSL2_READY": {"WSL_MISSING", "WSL_OUTDATED"}},  # only what a plan step can fix
        "succ_subset": {"WSL2_READY": set(),            # CW02: a ready WSL2 is never changed
                        "WSL_POLICY_BLOCKED": set()},   # CR-45: a policy is never changed by the client
        "must_pass": [],
        # CR-45: states the client cannot leave by itself, and the reason code each state carries.
        "required_terminal": {"WSL2_READY", "VIRTUALIZATION_DISABLED", "WSL_POLICY_BLOCKED", "UNSUPPORTED_PROFILE"},
        "state_reason_codes": {"WSL2_READY": None, "WSL_OUTDATED": "WSL_OUTDATED", "WSL_MISSING": "WSL_MISSING",
                               "VIRTUALIZATION_DISABLED": "VIRTUALIZATION_DISABLED",
                               "WSL_POLICY_BLOCKED": "WSL_POLICY_BLOCKED",
                               "UNSUPPORTED_PROFILE": "UNSUPPORTED_PROFILE"},
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
    # CR-12: the step is looked up in the plan whose object_hash is consented_plan_id, so the
    # predicate needs consent as well as the step flags.
    step = c.get("step")
    ok = (isinstance(c.get("consented_plan_id"), str) and isinstance(step, dict)
          and step.get("in_consented_plan") is True and step.get("privileged") is True)
    return None if ok else "CONSENT_REQUIRED"


def _p_privilege_granted(c: dict):
    return None if c.get("privilege_granted") is True else "PRIVILEGE_REQUIRED"


def _p_image_allowlisted(c: dict):
    # SEC-m3: (repository, digest) pairs, i.e. whole ImageReferences, are compared.
    ref, allow = c.get("image_reference"), c.get("allowlist")
    ok = isinstance(ref, str) and isinstance(allow, list) and ref in allow
    return None if ok else "IMAGE_NOT_ALLOWED"


def _p_engine_endpoint_local(c: dict):
    # SEC-B1: only a local unix socket; tcp:// is refused even on loopback; no TCP listener at all.
    endpoint = c.get("engine_endpoint")
    if not isinstance(endpoint, str) or not endpoint.startswith("unix:///"):
        return "ENGINE_REMOTE_CONTEXT"
    return None if c.get("engine_tcp_listener") is False else "ENGINE_TCP_EXPOSED"


def _p_terms_accepted(c: dict):
    # CR-20: consent is set only when every licence and every acknowledgement was given explicitly.
    for need, have in (("required_licence_ids", "accepted_licence_ids"),
                       ("required_acknowledgements", "given_acknowledgements")):
        n, h = c.get(need), c.get(have)
        if not isinstance(n, list) or not isinstance(h, list) or not set(n) <= set(h):
            return "CONSENT_REQUIRED"
    return None


def _p_image_in_consented_plan(c: dict):
    # CR-30: whole ImageReferences are compared; a digest alone is never used.
    digest, listed = c.get("image_reference"), c.get("consented_image_references")
    ok = (isinstance(c.get("consented_plan_id"), str) and isinstance(digest, str)
          and isinstance(listed, list) and digest in listed)
    return None if ok else "CONSENT_REQUIRED"


def _p_image_present_by_digest(c: dict):
    return None if c.get("image_present") is True else "PLAN_STALE"


# Reference implementation of the guard predicates of registry/state-machines.json.
# Each returns None when the predicate holds, otherwise the reason code. Missing inputs fail.
# (function, requires_consent, guard_context members the function reads; `reads` in the registry
# must equal the last set, CR-12).
PREDICATES = {
    "consent_matches_plan": (_p_consent_matches_plan, True, {"consented_plan_id", "plan_id"}),
    "plan_has_no_actions": (_p_plan_has_no_actions, False, {"plan_action_count"}),
    "step_is_privileged_plan_step": (_p_step_is_privileged_plan_step, True, {"consented_plan_id", "step"}),
    "privilege_granted": (_p_privilege_granted, False, {"privilege_granted"}),
    "image_allowlisted": (_p_image_allowlisted, False, {"image_reference", "allowlist"}),
    "engine_endpoint_local": (_p_engine_endpoint_local, False, {"engine_endpoint", "engine_tcp_listener"}),
    "terms_accepted": (_p_terms_accepted, False, {"required_licence_ids", "accepted_licence_ids",
                                                  "required_acknowledgements", "given_acknowledgements"}),
    "image_in_consented_plan": (_p_image_in_consented_plan, True,
                                {"consented_plan_id", "image_reference", "consented_image_references"}),
    "image_present_by_digest": (_p_image_present_by_digest, False, {"image_present"}),
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
        if any(PREDICATES.get(p, (None, False, set()))[1] for p in g["checks"]):
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
    # SEC-m6: a numeric const/enum always comes with "type": "integer", so 1.0 is rejected by type.
    numeric = [v for v in ([schema["const"]] if "const" in schema else []) + list(schema.get("enum", []))
               if isinstance(v, (int, float)) and not isinstance(v, bool)]
    if numeric and schema.get("type") != "integer":
        report.error(where, f"numeric const/enum {numeric} needs \"type\": \"integer\" (docs/canonical-json.md 3.3)")
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


# Schema semantics fixed for parity (docs/canonical-json.md section 3.3, issue #2). They differ
# from generic draft 2020-12 validators; --self-test flips them and proves the vectors notice.
SCHEMA_SEMANTICS = {
    # "type": "integer" accepts only number tokens without fraction or exponent: 1.0 is rejected,
    # although draft 2020-12 calls it an integer.
    "integer_accepts_integral_fraction": False,
    # const / enum compare numbers by mathematical value: 1.0 equals 1.
    "numbers_equal_by_value": True,
}
_SCHEMA_SEMANTICS_DEFAULT = dict(SCHEMA_SEMANTICS)


def _type_ok(instance, name: str) -> bool:
    if name == "object":
        return isinstance(instance, dict)
    if name == "array":
        return isinstance(instance, list)
    if name == "string":
        return isinstance(instance, str)
    if name == "integer":
        if (SCHEMA_SEMANTICS["integer_accepts_integral_fraction"] and isinstance(instance, float)
                and instance.is_integer()):
            return True
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
    if not SCHEMA_SEMANTICS["numbers_equal_by_value"] and isinstance(a, (int, float)) and isinstance(b, (int, float)):
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
        if name.startswith(("schemas/", "registry/")) and RAW_INVISIBLE.search(text.replace("\n", "")):
            report.error(name, "contains a raw control or invisible character; write it as a \\uXXXX escape (CR-27)")
        if name.startswith(HASHABLE_PREFIXES):
            # Hashed documents and vector inputs are parsed under the hashing restrictions, so that
            # e.g. -0 or 1.0 in an "input" cannot be silently normalised by the generic parser.
            try:
                parsed = parse_hashable_json(text)
            except CanonicalJsonError as exc:
                report.error(name, f"file violates hashing restrictions: {exc}")
                continue
            if name.startswith(D_CANONICAL):
                ctx["canonical"][name] = parsed
    # SEC-N3: CODEOWNERS must exist before the allowlist may contain entries.
    ctx["codeowners"] = any((ROOT / p).is_file() for p in ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"))
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
                          ("03-CONTRACTS 7", SPEC_CONTRACT_REASON_CODES),
                          ("sprut-contracts 0.2.0", CONTRACT_REASON_CODES),
                          ("sprut-contracts 0.3.0", CONTRACT_REASON_CODES_0_3)):
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
    for state in sorted(spec.get("required_terminal", set()) - set(terminal)):
        report.error(where, f"{state} must be terminal (the client cannot leave it by itself)")
    declared_codes = {s["name"]: s.get("reason_code") for s in machine_def["states"]}
    for state, rc in spec.get("state_reason_codes", {}).items():
        if state in declared_codes and declared_codes[state] != rc:
            report.error(where, f"state {state} must carry reason_code {rc}, found {declared_codes[state]}")
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
    for eff, pid in spec.get("required_effect_checks", {}).items():
        declared = [e for e in machine_def.get("effects", []) if (e["on"], e["state"], e["action"]) == eff]
        if not declared or pid not in declared[0].get("checks", []):
            report.error(where, f"effect {eff[2]} on {eff[0]} in {eff[1]} must check {pid}")
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
        if set(p["reads"]) != PREDICATES[pid][2]:
            report.error(where, f"predicate {pid}: reads {sorted(p['reads'])} differ from the inputs of the "
                                f"reference implementation {sorted(PREDICATES[pid][2])}")
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
        needed = set()
        for pid in e.get("checks", []):
            if pid not in catalog:
                report.error(where, f"effect {e['action']} uses undeclared predicate {pid}")
            needed |= set(catalog.get(pid, {}).get("fails_with", []))
        on_reject = e.get("on_reject", {})
        if set(on_reject) != needed:
            report.error(where, f"effect {e['action']}: on_reject {sorted(on_reject)} must cover exactly {sorted(needed)}")
        if on_reject and e["state"] not in waiting:
            report.error(where, f"effect {e['action']}: on_reject stays in {e['state']}, which is not a waiting state")
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


def check_effect_vectors(ctx: dict, report: Report) -> None:
    machines = ctx.get("machines", {})
    vecs = {k: v for k, v in ctx["files"].items() if k.startswith(D_EFFECTS)}
    checked_effects = {(mid, (e["on"], e["state"], e["action"]))
                       for mid, d in machines.items() for e in d["def"].get("effects", []) if e.get("checks")}
    outcomes: dict = {}
    for path, vec in sorted(vecs.items()):
        if not validate_against(vec, "schemas/effect-vector.schema.json", path, ctx, report):
            continue
        mid = vec["machine"]
        if mid not in machines:
            report.error(path, f"unknown machine {mid}")
            continue
        mdef = machines[mid]["def"]
        context_names = {c["name"] for c in mdef.get("guard_context", [])}
        effects = {(e["on"], e["state"], e["action"]): e for e in mdef.get("effects", [])}
        for i, case in enumerate(vec["cases"]):
            where = f"cases[{i}] {case['name']}"
            key = (case["on"], case["state"], case["action"])
            effect = effects.get(key)
            if effect is None:
                report.error(path, f"{where}: no effect {key}")
                continue
            for name in case["context"]:
                if name not in context_names:
                    report.error(path, f"{where}: context member {name} is not in guard_context")
            allowed, reason, _ = evaluate_guard(effect.get("checks", []), case["context"])
            outcomes.setdefault((mid, key), set()).add(allowed)
            want = case["expected"] == "applied"
            event = None if allowed else effect.get("on_reject", {}).get(reason, {}).get("event")
            if allowed != want or (not allowed and (reason, event) != (case.get("reason_code"), case.get("expected_event"))):
                report.error(path, f"{where}: expected {case['expected']} {case.get('reason_code', '')}".rstrip()
                             + f", effect checks give {'applied' if allowed else f'{reason}/{event}'}")
            else:
                report.ok()
    for key in sorted(checked_effects):
        if outcomes.get(key) != {True, False}:
            report.error(D_EFFECTS, f"effect {key[1]} of {key[0]} needs an applied and a rejected case")


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


# --------------------------------------------------------------------------
# Shared definitions, plan step kinds, InstallationPlan, allowlist, ownership, WSL resources
# --------------------------------------------------------------------------

def check_shared_defs(ctx: dict, report: Report) -> None:
    files = ctx["files"]
    for (copy_file, copy_def), (src_file, src_def) in SHARED_DEFS:
        try:
            copied = files[copy_file]["$defs"][copy_def]
            source = files[src_file]["$defs"][src_def]
        except (KeyError, TypeError):
            report.error(copy_file, f"$defs/{copy_def} or its source {src_file} $defs/{src_def} is missing")
            continue
        if copied != source:
            report.error(copy_file, f"$defs/{copy_def} differs from {src_file} $defs/{src_def} (copies must be identical)")
        else:
            report.ok()
    try:
        d = files[P_IMAGE_SCHEMA]["$defs"]
        expected = d["repository"]["pattern"][:-1] + "@" + d["image_digest"]["pattern"][1:]
        if d["image_reference"]["pattern"] != expected:
            report.error(P_IMAGE_SCHEMA, "image_reference pattern must be the repository pattern, '@' and the "
                                         "image_digest pattern")
    except (KeyError, TypeError):
        report.error(P_IMAGE_SCHEMA, "image_digest, repository or image_reference definition is missing")


_PLACEHOLDER = re.compile(r"\{([^{}]*)\}")


def render_title(template: str, step: dict) -> str:
    """Title rendering: the only placeholder is {repository}, the repository part of step.image."""
    image = step.get("image", "")
    return template.replace("{repository}", image.split("@", 1)[0] if isinstance(image, str) else "")


def verified_in_distro(rule: dict, platform: str) -> bool:
    """SEC-12: the verified copy is made and hashed by root inside the Sprut distribution, i.e. on
    Windows `{verified_file}` is an argument of a Linux program."""
    return platform == "windows" and any(
        "argv" in op and op["argv"][0].startswith("/") and "{verified_file}" in op["argv"]
        for op in rule["commands"].get("windows", []))


def _pc_source_verified(step, rule, o, env):
    if "source" not in step:
        return None if "source" in rule["optional_members"] else "INTEGRITY_MISMATCH"
    want = step["source"]["sha256"]
    if o.get("downloaded_sha256") != want:
        return "INTEGRITY_MISMATCH"
    # SEC-12: the answer of the distribution is not enough; the client's own hash must match too.
    if verified_in_distro(rule, env["platform"]) and o.get("staged_sha256") != want:
        return "INTEGRITY_MISMATCH"
    return None


def _pc_ubuntu_supported(step, rule, o, env):
    sup = env["registry"]["supported_ubuntu"]
    ok = o.get("ubuntu_codename") in sup["codenames"] and o.get("architecture") == sup["architecture"]
    return None if ok else "UNSUPPORTED_PROFILE"


def _pc_target_user_current(step, rule, o, env):
    user = o.get("process_user")
    return None if "target_user" in step and user == step["target_user"] else "PLAN_STALE"


def _pc_distro_owned(step, rule, o, env):
    reg_d = o.get("registered_distro")
    if not isinstance(reg_d, dict):
        return "PLAN_STALE"
    want = step.get("distro", {})
    ok = reg_d.get("name") == want.get("name") and reg_d.get("base_path") == want.get("base_path")
    return None if ok else "FOREIGN_RESOURCE"


def _pc_wslconfig_unchanged(step, rule, o, env):
    current = o.get("wslconfig_sha256")
    return None if isinstance(current, str) and current == step.get("wslconfig_file", {}).get("sha256") else "PLAN_STALE"


def _name_list(value) -> bool:
    """A list of distribution names that was actually read; anything else means "could not be read"."""
    return isinstance(value, list) and all(isinstance(n, str) for n in value)


def _pc_wsl_restart_confirmed(step, rule, o, env):
    if rule["kind"] == "restart_wsl":
        # CR04: the dialog lists the running distributions; without the list the step fails closed.
        if not _name_list(o.get("running_distributions")):
            return "WSL_RESTART_REQUIRED"
    else:
        # SEC-5 (install_wsl, update_wsl): needed when at least one distribution is registered.
        registered = o.get("registered_distributions")
        if not _name_list(registered):
            return "WSL_RESTART_REQUIRED"
        if not registered:
            return None
    ok = o.get("sprut_drained") is True and o.get("wsl_restart_confirmed") is True
    return None if ok else "WSL_RESTART_REQUIRED"


def _pc_sprut_drained(step, rule, o, env):
    return None if o.get("sprut_drained") is True else "DRAIN_TIMEOUT"


def _pc_replacement_source_verified(step, rule, o, env):
    # SEC-1: the source of the paired import_distro (the next step of the consented plan).
    nxt = env.get("next_step")
    want = None
    if isinstance(nxt, dict) and nxt.get("kind") == "import_distro" and isinstance(nxt.get("source"), dict):
        want = nxt["source"].get("sha256")
    got = o.get("replacement_downloaded_sha256")
    if not isinstance(want, str) or not isinstance(got, str):
        return "SOURCE_UNAVAILABLE"
    return None if got == want else "INTEGRITY_MISMATCH"


# Reference implementation of the execution preconditions of registry/plan-step-kinds.json:
# id -> (function(step, kind rule, observed facts, env), observed facts it reads). env carries the
# step-kind registry, the platform and the step that follows in the consented plan (next_step).
STEP_PRECONDITIONS = {
    "source_verified": (_pc_source_verified, {"downloaded_sha256", "staged_sha256"}),
    "ubuntu_supported": (_pc_ubuntu_supported, {"ubuntu_codename", "architecture"}),
    "target_user_current": (_pc_target_user_current, {"process_user"}),
    "distro_owned": (_pc_distro_owned, {"registered_distro"}),
    "wslconfig_unchanged": (_pc_wslconfig_unchanged, {"wslconfig_sha256"}),
    "wsl_restart_confirmed": (_pc_wsl_restart_confirmed, {"sprut_drained", "wsl_restart_confirmed",
                                                          "registered_distributions", "running_distributions"}),
    "sprut_drained": (_pc_sprut_drained, {"sprut_drained"}),
    "replacement_source_verified": (_pc_replacement_source_verified, {"replacement_downloaded_sha256"}),
}


def check_commands(kind: str, platform: str, ops: list, members: set, prule: dict, where: str, report: Report) -> None:
    """SEC-m1: fixed argv templates, absolute programs, no shells, only declared placeholders."""
    where = f"{where} commands.{platform}"
    downloaded, verified = set(), set()
    for i, op in enumerate(ops):
        w = f"{where}[{i}]"
        when = op.get("when")
        if when is not None and "source" not in members:
            report.error(w, "`when` is only for kinds with a source")
        if "argv" in op:
            prog = op["argv"][0]
            host = prog.startswith("{system32}\\")
            if platform == "linux" and not prog.startswith("/"):
                report.error(w, f"program {prog!r} must be an absolute Linux path")
            if platform == "windows" and not (host or prog.startswith("/")):
                report.error(w, f"program {prog!r} must start with {{system32}}\\ or be a Linux path in the Sprut distribution")
            if platform == "windows" and prule.get("privileged") and not host:
                report.error(w, "an elevated step runs only Windows system programs")
            base = prog.replace("\\", "/").rsplit("/", 1)[-1].lower()
            if base in FORBIDDEN_PROGRAMS:
                report.error(w, f"program {base} is not allowed (no shell, interpreter, downloader or sudo in templates)")
            for j, arg in enumerate(op["argv"]):
                names = _PLACEHOLDER.findall(arg)
                if j == 0:
                    if names not in ([], ["system32"]) or (names and not host):
                        report.error(w, "argv[0] may only use {system32} as its prefix")
                    continue
                for n in names:
                    if arg != "{" + n + "}":
                        report.error(w, f"placeholder {{{n}}} must be a whole argument")
                    if n not in SPEC_PLACEHOLDERS - {"system32"}:
                        report.error(w, f"unknown placeholder {{{n}}}")
                    if n in PLACEHOLDER_MEMBER and PLACEHOLDER_MEMBER[n] not in members:
                        report.error(w, f"{{{n}}} needs step member {PLACEHOLDER_MEMBER[n]}")
                    if n == "verified_file" and when not in verified:
                        report.error(w, "{verified_file} is used without a preceding verify_source (SEC-N1)")
        elif "install_file" in op:
            names = set(_PLACEHOLDER.findall(op["install_file"]["content"]))
            if names - {"codename"}:
                report.error(w, f"install_file content may only use {{codename}}, found {sorted(names)}")
        else:
            action = op["client_action"]
            need = {"download_source": "source", "verify_source": "source", "engine_pull": "image",
                    "edit_wslconfig": "wslconfig"}[action]
            if need not in members:
                report.error(w, f"{action} needs step member {need}")
            if action == "download_source":
                downloaded.add(when)
            if action == "verify_source":
                if when not in downloaded:
                    report.error(w, "verify_source needs a preceding download_source")
                verified.add(when)


def check_step_kinds(ctx: dict, report: Report) -> None:
    name = P_STEP_KINDS
    data = ctx["files"].get(name)
    if data is None:
        report.error(name, "missing")
        return
    if not validate_against(data, "schemas/plan-step-kinds.schema.json", name, ctx, report):
        return
    if {p["name"] for p in data["placeholders"]} != SPEC_PLACEHOLDERS:
        report.error(name, f"placeholders must be {sorted(SPEC_PLACEHOLDERS)}")
    catalog = {}
    bootstrap = ctx.get("machines", {}).get("bootstrap")
    for p in data["preconditions"]:
        where = f"{name}: precondition {p['id']}"
        catalog[p["id"]] = p
        check_localized(p, "description", where, report)
        ref = STEP_PRECONDITIONS.get(p["id"])
        if ref is None:
            report.error(where, "no reference implementation in tools/validate.py")
            continue
        if set(p["reads"]) != ref[1]:
            report.error(where, f"reads must be {sorted(ref[1])}")
        if set(p["fails_with"]) != set(p["on_reject"]):
            report.error(where, "on_reject must cover exactly fails_with")
        for rc, entry in p["on_reject"].items():
            if rc not in ctx.get("reason_codes", {}):
                report.error(where, f"unknown reason code {rc}")
            if bootstrap is not None and ("INSTALLING", entry["to"]) not in bootstrap["pairs"]:
                report.error(where, f"on_reject {rc} goes to {entry['to']}, but INSTALLING->{entry['to']} is not a transition")
    kinds: dict = {}
    for entry in data["step_kinds"]:
        kind = entry["kind"]
        where = f"{name}: {kind}"
        if kind in kinds:
            report.error(where, "duplicate kind")
        kinds[kind] = entry
        check_localized(entry, "title", where, report)
        privileged = {p: r["privileged"] for p, r in entry["platforms"].items()}
        if kind in SPEC_STEP_KINDS and privileged != SPEC_STEP_KINDS[kind]:
            report.error(where, f"platforms/privileged {privileged} differ from the agreed {SPEC_STEP_KINDS[kind]}")
        elevated = entry.get("windows_elevated_step")
        if privileged.get("windows"):
            if elevated != kind.upper() or elevated != SPEC_WINDOWS_ELEVATED.get(kind):
                report.error(where, f"windows_elevated_step must be {kind.upper()} and part of the elevated "
                                    f"vocabulary {sorted(SPEC_WINDOWS_ELEVATED.values())}")
        elif elevated is not None:
            report.error(where, "windows_elevated_step is only for kinds privileged on windows")
        required, optional = set(entry["required_members"]), set(entry["optional_members"])
        if required & optional:
            report.error(where, f"members both required and optional: {sorted(required & optional)}")
        members = required | optional
        if ("image" in members) != (kind == "image_pull") or ("image" in optional):
            report.error(where, "only image_pull has an image, and it is required there")
        if ("source" in required) != (kind in SPEC_SOURCE_REQUIRED):
            report.error(where, f"source must be required exactly for {sorted(SPEC_SOURCE_REQUIRED)}")
        if bool(entry["source_url_prefixes"]) != ("source" in members):
            report.error(where, "source_url_prefixes must be non-empty exactly when source is required or optional")
        for flag in STEP_FLAGS:
            rule = entry["flags"][flag]
            if (kind, flag) in SPEC_FLAG_ALWAYS and rule != "always":
                report.error(where, f"{flag} must be always")
            if flag == "requires_reboot" and rule != ("may" if kind in SPEC_REBOOT_MAY else "never"):
                report.error(where, f"requires_reboot must be {'may' if kind in SPEC_REBOOT_MAY else 'never'}")
            if flag != "requires_reboot" and (kind, flag) not in SPEC_FLAG_ALWAYS and rule != "never":
                report.error(where, f"{flag} must be never")
        for tkey in ("title", "title_without_source"):
            if tkey not in entry:
                continue
            check_localized(entry, tkey, where, report)
            holders = {lang: set(_PLACEHOLDER.findall(entry[tkey][lang])) for lang in ("ru", "en")}
            for lang, found in holders.items():
                allowed = {"repository"} if "image" in required else set()
                if found - allowed:
                    report.error(where, f"{tkey}.{lang} uses placeholders {sorted(found - allowed)} (allowed: {sorted(allowed)})")
            if holders["ru"] != holders["en"]:
                report.error(where, f"{tkey}.ru and {tkey}.en use different placeholders")
        if ("title_without_source" in entry) != ("source" in optional):
            report.error(where, "title_without_source must be present exactly when source is optional (SEC-A1)")
        if entry.get("acknowledgement") != SPEC_ACKNOWLEDGEMENTS.get(kind):
            report.error(where, f"acknowledgement must be {SPEC_ACKNOWLEDGEMENTS.get(kind)}")
        for platform, prule in entry["platforms"].items():
            want = SPEC_PLATFORM_ACKNOWLEDGEMENTS.get((kind, platform))
            if prule.get("acknowledgement") != want:
                report.error(where, f"acknowledgement on {platform} must be {want}")
            if "title" in prule:
                check_localized(prule, "title", f"{where} on {platform}", report)
                if any(_PLACEHOLDER.findall(prule["title"][lang]) for lang in ("ru", "en")):
                    report.error(where, f"the {platform} title uses placeholders")
                if "source" in optional:
                    report.error(where, "a kind with title_without_source has no platform titles")
            if want is not None and "title" not in prule:
                report.error(where, f"the {platform} title must name the effect acknowledged as {want}")
        if entry["licence_required"] != (kind in SPEC_LICENCE_REQUIRED):
            report.error(where, f"licence_required must be {kind in SPEC_LICENCE_REQUIRED}")
        if entry["preconditions"] != SPEC_STEP_PRECONDITIONS.get(kind, []):
            report.error(where, f"preconditions must be {SPEC_STEP_PRECONDITIONS.get(kind, [])}")
        for pid in entry["preconditions"]:
            if pid not in catalog:
                report.error(where, f"precondition {pid} is not declared")
        for prefix in entry["source_url_prefixes"]:
            if not PREFIX_SHAPE.fullmatch(prefix):
                report.error(where, f"source prefix {prefix!r} must match {PREFIX_SHAPE.pattern}")
        # CR-58 / SEC-11: bare host names, only for kinds with a source, only the agreed ones.
        redirect_hosts = entry.get("redirect_hosts")
        if redirect_hosts is None:
            report.error(where, "redirect_hosts is required (empty when a download must end on the requested host)")
            redirect_hosts = entry["redirect_hosts"] = []
        for host in redirect_hosts:
            if not HOST_NAME.fullmatch(host):
                report.error(where, f"redirect host {host!r} must be a bare lowercase host name "
                                    "(no scheme, port, path, wildcard or IP address)")
        if redirect_hosts and "source" not in members:
            report.error(where, "redirect_hosts is only for kinds with a source")
        if redirect_hosts != SPEC_REDIRECT_HOSTS.get(kind, []):
            report.error(where, f"redirect_hosts must be {SPEC_REDIRECT_HOSTS.get(kind, [])} "
                                "(a new host needs a security review and a change in tools/validate.py)")
        # CR-49: a kind that stops the Sprut distribution runs only after a drain of Sprut tasks.
        win_ops = [op["argv"] for op in entry["commands"].get("windows", []) if "argv" in op]
        all_ops = [op["argv"] for ops in entry["commands"].values() for op in ops if "argv" in op]
        stops = any((argv[0].lower().endswith("\\wsl.exe") and DISTRO_STOPPING_ARGS & set(argv[1:]))
                    or argv[0].lower().endswith("\\msiexec.exe") for argv in win_ops)
        # CR-72: stopping or restarting the engine stops every container, on either platform.
        stops_engine = any(argv[0].rsplit("/", 1)[-1] == "systemctl" and ENGINE_UNITS & set(argv[1:])
                           and (ENGINE_STOPPING_VERBS & set(argv[1:])
                                or ({"disable", "mask"} & set(argv[1:]) and "--now" in argv))
                           for argv in all_ops)
        drains = any("sprut_drained" in catalog.get(pid, {}).get("reads", []) for pid in entry["preconditions"])
        if stops and not drains:
            report.error(where, "a kind that stops the Sprut distribution needs a precondition that reads sprut_drained (CR-49)")
        if stops_engine and not drains:
            report.error(where, "a kind that stops or restarts docker.service needs a precondition that reads sprut_drained (CR-72)")
        if stops_engine and "linux" in entry["platforms"] and \
                entry["platforms"]["linux"].get("acknowledgement", entry.get("acknowledgement")) != "engine_restart":
            report.error(where, "a kind that stops or restarts docker.service on a Linux host needs the engine_restart "
                                "acknowledgement (CR-72)")
        # CR-71: apt-get update must report fetch failures through its exit status.
        for argv in all_ops:
            # CR-83: any apt-get call that updates, wherever `update` stands in it.
            if argv[0].rsplit("/", 1)[-1] == "apt-get" and "update" in argv[1:] and argv != APT_UPDATE_ARGV:
                report.error(where, f"apt-get update must be exactly {APT_UPDATE_ARGV} (CR-71)")
        # CR-77: download limits exactly for kinds with a source.
        limits = entry.get("download")
        if (limits is not None) != ("source" in members):
            report.error(where, "download limits must be present exactly when the kind requires or allows source")
        elif limits is not None and (limits["max_bytes"], limits["timeout_seconds"]) != SPEC_DOWNLOAD_LIMITS.get(kind):
            report.error(where, f"download limits must be {SPEC_DOWNLOAD_LIMITS.get(kind)} (max_bytes, timeout_seconds)")
        for i, argv in enumerate(win_ops):
            if "--resize" in argv and (i == 0 or win_ops[i - 1] != [argv[0], "--terminate", "{distro_name}"]):
                report.error(where, "wsl --manage --resize must be preceded by wsl --terminate {distro_name} (CR-49)")
        if set(entry["commands"]) != set(entry["platforms"]):
            report.error(where, "commands must be given for exactly the kind's platforms")
        for platform, ops in entry["commands"].items():
            check_commands(kind, platform, ops, members, entry["platforms"].get(platform, {}), where, report)
        env = entry.get("environment", {})
        if any(ALLOWED_ENVIRONMENT.get(k) != v for k, v in env.items()):
            report.error(where, f"environment may only set {ALLOWED_ENVIRONMENT}")
        uses_apt = any(op.get("argv", [""])[0] == "/usr/bin/apt-get" for ops in entry["commands"].values() for op in ops)
        if uses_apt != (env == ALLOWED_ENVIRONMENT):
            report.error(where, "kinds that run apt-get declare environment DEBIAN_FRONTEND=noninteractive, others none")
    if set(kinds) != set(SPEC_STEP_KINDS):
        report.error(name, f"step kinds differ from the agreed closed vocabulary: extra "
                           f"{sorted(set(kinds) - set(SPEC_STEP_KINDS))}, missing {sorted(set(SPEC_STEP_KINDS) - set(kinds))}")
    report.ok()
    ctx["step_kinds"] = kinds
    ctx["step_registry"] = data


class ContractError(Exception):
    """A document rejected by one of the documented categories (docs/installation-plan.md section 6)."""

    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(f"{kind}: {detail}")
        self.kind = kind


def validate_plan(value, ctx: dict) -> dict:
    """Reference InstallationPlan check. Returns the derived guard inputs or raises ContractError."""
    try:
        hashed = object_hash_input(value, "installation_plan")
    except CanonicalJsonError as exc:
        raise ContractError(exc.kind, str(exc)) from exc
    schema = ctx["schemas"].get(P_PLAN_SCHEMA)
    kinds = ctx.get("step_kinds")
    if schema is None or kinds is None:
        raise ContractError("SCHEMA_VIOLATION", "plan schema or step-kind registry unavailable")
    errs = schema_errors(value, schema, schema)
    if errs:
        raise ContractError("SCHEMA_VIOLATION", errs[0])
    try:
        plan_id = sha256_hex(canonicalize(hashed))
    except CanonicalJsonError as exc:
        raise ContractError(exc.kind, str(exc)) from exc
    if value.get("hash") != plan_id:
        raise ContractError("HASH_MISMATCH", f"stored {value.get('hash')}, recomputed {plan_id}")
    platform = value["platform"]
    for summary in ("current_state", "target_state"):
        for component in value[summary]:
            if STATE_COMPONENT_PLATFORMS.get(component, platform) != platform:
                raise ContractError("STATE_NOT_ON_PLATFORM", f"{summary}.{component} on {platform}")
    images: dict = {}
    for ref in value["images"]:
        digest = ref.split("@", 1)[1]
        if digest in images:
            raise ContractError("DUPLICATE_IMAGE", digest)
        images[digest] = ref
    licences = set()
    for lic in value["licences"]:
        if lic["id"] in licences:
            raise ContractError("DUPLICATE_LICENCE", lic["id"])
        licences.add(lic["id"])
    ids: set = set()
    pulls: list = []
    pulled_refs: list = []
    privileged: list = []
    elevated: list = []
    acknowledgements: list = []
    total = 0
    steps = value["steps"]
    for index, step in enumerate(steps):
        sid, kind = step["id"], step["kind"]
        if sid in ids:
            raise ContractError("DUPLICATE_STEP_ID", sid)
        ids.add(sid)
        rule = kinds.get(kind)
        if rule is None:
            raise ContractError("UNKNOWN_STEP_KIND", kind)
        prule = rule["platforms"].get(platform)
        if prule is None:
            raise ContractError("STEP_NOT_ON_PLATFORM", f"{kind} on {platform}")
        if step["privileged"] != prule["privileged"]:
            raise ContractError("PRIVILEGE_MISMATCH", f"{sid}: {kind} on {platform} has privileged={prule['privileged']}")
        for flag in STEP_FLAGS:
            want = rule["flags"][flag]
            if (want == "never" and step[flag]) or (want == "always" and not step[flag]):
                raise ContractError("FLAG_MISMATCH", f"{sid}: {flag} must be {want}")
        allowed = set(rule["required_members"]) | set(rule["optional_members"])
        for member in STEP_MEMBERS:
            if member in step and member not in allowed:
                raise ContractError("STEP_MEMBER_NOT_ALLOWED", f"{sid}: {kind} has no {member}")
            if member in rule["required_members"] and member not in step:
                raise ContractError("STEP_MEMBER_MISSING", f"{sid}: {kind} needs {member}")
        if "source" in step and not any(step["source"]["url"].startswith(p) for p in rule["source_url_prefixes"]):
            raise ContractError("SOURCE_NOT_OFFICIAL", f"{sid}: {step['source']['url']}")
        if "image" in step:
            digest = step["image"].split("@", 1)[1]
            if images.get(digest) != step["image"]:
                raise ContractError("IMAGE_NOT_LISTED", f"{sid}: {step['image']}")
            if digest in pulls:
                raise ContractError("DUPLICATE_PULL", f"{sid}: {digest}")
            pulls.append(digest)
            pulled_refs.append(step["image"])
        # SEC-A1: without its optional source the title states that the download is unverified.
        template = prule.get("title", rule["title"]) if "source" in step or "title_without_source" not in rule \
            else rule["title_without_source"]
        for lang in ("ru", "en"):
            if step["title"][lang] != render_title(template[lang], step):
                raise ContractError("TITLE_MISMATCH", f"{sid}: title.{lang} is not the template of {kind}")
        for lic in step.get("licence_ids", []):
            if lic not in licences:
                raise ContractError("LICENCE_UNKNOWN", f"{sid}: {lic}")
        if RULE_SWITCHES["licence_required"] and rule["licence_required"] and not step.get("licence_ids"):
            raise ContractError("LICENCE_MISSING", f"{sid}: {kind} needs a licence")
        if RULE_SWITCHES["unregister_pairing"] and kind == "unregister_distro" and (index + 1 >= len(steps) or steps[index + 1]["kind"] != "import_distro"):
            raise ContractError("UNPAIRED_UNREGISTER", f"{sid}: must be immediately followed by import_distro")
        if RULE_SWITCHES["wslconfig_replaced"] and "wslconfig_file" in step:
            replaced, written = step["wslconfig_file"]["replaced"], step["wslconfig"]
            if not set(replaced) <= set(written) or (step["wslconfig_file"]["sha256"] == "absent" and replaced):
                raise ContractError("WSLCONFIG_REPLACED_MISMATCH", f"{sid}: replaced values must be of written keys of an existing file")
        ack = prule.get("acknowledgement", rule.get("acknowledgement"))  # CR-72: per platform or per kind
        if ack is not None and ack not in acknowledgements:
            acknowledgements.append(ack)
        total += step["estimated_bytes"]
        if step["privileged"]:
            privileged.append(sid)
            if platform == "windows":
                elevated.append({"step_id": sid, "elevated_step": rule["windows_elevated_step"]})
    # SEC-C1: Linux plans state how the user reaches the engine; the group step matches that choice.
    access = value.get("docker_access")
    has_group_step = any(s["kind"] == "add_user_to_docker_group" for s in steps)
    if not RULE_SWITCHES["docker_access"]:
        pass
    elif platform == "windows":
        if access is not None:
            raise ContractError("DOCKER_ACCESS_MISMATCH", "docker_access is Linux only")
    elif access is None or (access == "none" and has_group_step) or \
            (access == "docker_group" and not has_group_step and value["current_state"].get("docker_group") != "member"):
        raise ContractError("DOCKER_ACCESS_MISMATCH", f"docker_access {access!r} does not match the steps")
    if total != value["disk_estimate_bytes"]:
        raise ContractError("DISK_ESTIMATE_MISMATCH", f"sum of estimated_bytes {total} != {value['disk_estimate_bytes']}")
    return {"plan_id": plan_id, "plan_action_count": len(steps), "consented_image_references": pulled_refs,
            "privileged_step_ids": privileged, "windows_elevated_steps": elevated,
            "required_licence_ids": [lic["id"] for lic in value["licences"]],
            "required_acknowledgements": acknowledgements}


def evaluate_preconditions(step: dict, platform: str, observed: dict, ctx: dict, next_step=None):
    """(allowed, reason_code, next_state, event, failing precondition) for the execution
    preconditions of a step; next_step is the step that follows it in the consented plan."""
    reg = ctx["step_registry"]
    rule = ctx["step_kinds"][step["kind"]]
    if platform not in rule["platforms"]:
        raise ContractError("STEP_NOT_ON_PLATFORM", f"{step['kind']} on {platform}")
    catalog = {p["id"]: p for p in reg["preconditions"]}
    env = {"registry": reg, "platform": platform, "next_step": next_step}
    for pid in rule["preconditions"]:
        reason = STEP_PRECONDITIONS[pid][0](step, rule, observed, env)
        if reason is not None:
            entry = catalog[pid]["on_reject"].get(reason, {})
            return False, reason, entry.get("to"), entry.get("event"), pid
    return True, None, None, None, None


def check_precondition_vectors(ctx: dict, report: Report) -> None:
    vec = ctx["files"].get(P_PRECONDITION_VECTORS)
    if vec is None or "step_kinds" not in ctx:
        report.error(P_PRECONDITION_VECTORS, "vectors or step-kind registry missing")
        return
    if not validate_against(vec, "schemas/step-precondition-vector.schema.json", P_PRECONDITION_VECTORS, ctx, report):
        return
    failed, rejections, passed = set(), set(), set()
    for i, case in enumerate(vec["cases"]):
        where = f"cases[{i}] {case['name']}"
        if case["step"].get("kind") not in ctx["step_kinds"]:
            report.error(P_PRECONDITION_VECTORS, f"{where}: unknown step kind")
            continue
        try:
            allowed, reason, nxt, event, pid = evaluate_preconditions(
                case["step"], case["platform"], case["observed"], ctx, case.get("next_step"))
        except (ContractError, KeyError, TypeError, AttributeError) as exc:
            report.error(P_PRECONDITION_VECTORS, f"{where}: {exc!r}")
            continue
        got = ("allowed",) if allowed else ("rejected", reason, nxt, event)
        want = ("allowed",) if case["expected"] == "allowed" else (
            "rejected", case.get("reason_code"), case.get("expected_next_state"), case.get("expected_event"))
        if got != want:
            report.error(P_PRECONDITION_VECTORS, f"{where}: expected {want}, preconditions give {got}")
            continue
        if not allowed:
            failed.add(pid)
            rejections.add((pid, reason))
        else:
            passed.update(ctx["step_kinds"][case["step"]["kind"]]["preconditions"])
        report.ok()
    for p in ctx["step_registry"]["preconditions"]:
        for rc in p["fails_with"]:
            if (p["id"], rc) not in rejections:
                report.error(P_PRECONDITION_VECTORS, f"no case where precondition {p['id']} fails with {rc}")
        if p["id"] not in passed:
            report.error(P_PRECONDITION_VECTORS, f"no allowed case for a step with precondition {p['id']}")


def check_plan_vectors(ctx: dict, report: Report) -> None:
    vecs = {k: v for k, v in ctx["files"].items() if k.startswith(D_PLANS)}
    if not vecs:
        report.error(D_PLANS, "no vectors found")
        return
    names = set()
    seen_errors = set()
    valid_platforms = set()
    for path, vec in sorted(vecs.items()):
        if not validate_against(vec, "schemas/installation-plan-vector.schema.json", path, ctx, report):
            continue
        if vec["name"] in names or Path(path).stem != vec["name"]:
            report.error(path, f"vector name {vec['name']!r} must be unique and equal the file name")
        names.add(vec["name"])
        try:
            derived = validate_plan(vec["document"], ctx)
        except (KeyError, TypeError, AttributeError, IndexError) as exc:
            # Only reachable when the schema no longer guarantees the shape the rules rely on.
            report.error(path, f"plan rules failed on a document the schema accepted: {exc!r}")
            continue
        except ContractError as exc:
            if vec["expected"] == "valid":
                report.error(path, f"expected valid, got {exc}")
            elif exc.kind != vec["expected_error"]:
                report.error(path, f"expected {vec['expected_error']}, got {exc}")
            else:
                seen_errors.add(exc.kind)
                report.ok()
            continue
        if vec["expected"] == "invalid":
            report.error(path, f"plan was accepted, expected {vec['expected_error']}")
        elif derived != vec["derived"]:
            report.error(path, f"derived guard inputs differ:\n  expected {vec['derived']}\n  computed {derived}")
        else:
            valid_platforms.add(vec["document"]["platform"])
            report.ok()
    for platform in PLATFORMS:
        if platform not in valid_platforms:
            report.error(D_PLANS, f"no valid {platform} plan vector")
    categories = set(ctx["schemas"].get("schemas/installation-plan-vector.schema.json", {})
                     .get("properties", {}).get("expected_error", {}).get("enum", []))
    missing = categories - seen_errors - {"INVALID_JSON", "INVALID_HASH_MEMBER"}  # covered by canonical vectors
    if missing:
        report.error(D_PLANS, f"no invalid vector for {sorted(missing)}")


def _semver(text: str) -> tuple:
    """CR-21: (MAJOR, MINOR, PATCH, 0 for a pre-release / 1 for a release). Pre-release identifiers are
    not compared further; a pre-release is lower than its release."""
    core, _, pre = text.partition("-")
    return tuple(int(p) for p in core.split(".")) + (0 if pre else 1,)


def allowlist_digests(value, ctx: dict, client_version: str) -> list:
    """Reference allowlist reader: the guard input `allowlist` for a client, or ContractError."""
    try:
        object_hash_input(value, "image_allowlist")
    except CanonicalJsonError as exc:
        raise ContractError(exc.kind, str(exc)) from exc
    schema = ctx["schemas"].get(P_ALLOWLIST_SCHEMA)
    if schema is None:
        raise ContractError("SCHEMA_VIOLATION", "allowlist schema unavailable")
    errs = schema_errors(value, schema, schema)
    if errs:
        raise ContractError("SCHEMA_VIOLATION", errs[0])
    seen = set()
    for entry in value["entries"]:
        if entry["digest"] in seen:
            raise ContractError("DUPLICATE_DIGEST", entry["digest"])
        seen.add(entry["digest"])
    client = _semver(client_version)
    return [e["repository"] + "@" + e["digest"] for e in value["entries"]
            if _semver(e["min_client_version"]) <= client
            and ("max_client_version" not in e or client <= _semver(e["max_client_version"]))]


def check_allowlist(ctx: dict, report: Report) -> None:
    data = ctx["files"].get(P_ALLOWLIST)
    if data is None:
        report.error(P_ALLOWLIST, "missing")
    else:
        try:
            allowlist_digests(data, ctx, "0.0.0")
            if data.get("entries") and not ctx.get("codeowners"):
                report.error(P_ALLOWLIST, "a non-empty allowlist requires CODEOWNERS, branch protection and signed tags "
                                          "(SECURITY.md); CODEOWNERS is missing")
            else:
                report.ok()
        except ContractError as exc:
            report.error(P_ALLOWLIST, f"bundled allowlist is invalid: {exc}")
    vec = ctx["files"].get(P_ALLOWLIST_VECTORS)
    if vec is None:
        report.error(P_ALLOWLIST_VECTORS, "missing")
        return
    if not validate_against(vec, "schemas/image-allowlist-vector.schema.json", P_ALLOWLIST_VECTORS, ctx, report):
        return
    for i, case in enumerate(vec["cases"]):
        where = f"cases[{i}] {case['name']}"
        try:
            got = allowlist_digests(case["document"], ctx, case["client_version"])
        except ContractError as exc:
            if case["expected"] != "invalid" or exc.kind != case["expected_error"]:
                report.error(P_ALLOWLIST_VECTORS, f"{where}: expected {case['expected']} "
                                                  f"{case.get('expected_error', '')}".rstrip() + f", got {exc}")
            else:
                report.ok()
            continue
        if case["expected"] == "invalid":
            report.error(P_ALLOWLIST_VECTORS, f"{where}: accepted, expected {case['expected_error']}")
        elif got != case["allowlisted_references"]:
            report.error(P_ALLOWLIST_VECTORS, f"{where}: allowlist {got}, expected {case['allowlisted_references']}")
        else:
            report.ok()


def is_owned(labels: dict, profile: str, reg: dict) -> bool:
    for label in reg["labels"]:
        rule = label["owned_when"]
        if rule == "not_checked":
            continue
        value = labels.get(label["key"])
        if value is None or (rule == "equals_value" and value != label["value"]) \
                or (rule == "equals_current_profile" and value != profile):
            return False
    return True


def is_adoptable(case: dict, profile: str, reg: dict) -> bool:
    """SEC-m5: reuse an existing labelled resource only if journaled and inspected clean."""
    inspect = case["inspect"]
    return (is_owned(case["labels"], profile, reg) and (case["in_journal"] is True or not RULE_SWITCHES["adoption_needs_journal"])
            and inspect.get("image_allowlisted") is True and inspect.get("host_bind_mounts") is False
            and inspect.get("privileged") is False and inspect.get("docker_socket_mounted") is False)


def caller_labels_accepted(labels: dict, reg: dict) -> bool:
    ns = reg["label_namespace"]
    for key, value in labels.items():
        if key == ns or key.startswith(ns + "."):
            return False
        if not pattern_matches(reg["label_charset_pattern"], key) or not pattern_matches(reg["label_charset_pattern"], value):
            return False
    return True


def check_ownership(ctx: dict, report: Report) -> None:
    reg = ctx["files"].get(P_OWNERSHIP)
    if reg is None:
        report.error(P_OWNERSHIP, "missing")
        return
    if not validate_against(reg, "schemas/ownership.schema.json", P_OWNERSHIP, ctx, report):
        return
    if reg["label_namespace"] != SPEC_LABEL_NAMESPACE:
        report.error(P_OWNERSHIP, f"label_namespace must be {SPEC_LABEL_NAMESPACE}")
    if set(reg["labelled_resources"]) != SPEC_LABELLED_RESOURCES:
        report.error(P_OWNERSHIP, f"labelled_resources must be {sorted(SPEC_LABELLED_RESOURCES)} (CF22)")
    charset = reg["label_charset_pattern"]
    patterns_ok = True
    for pat in [charset] + [l["value_pattern"] for l in reg["labels"]]:
        if not (pat.startswith("^") and pat.endswith("$") and not pat.endswith("\\$")):
            report.error(P_OWNERSHIP, f"pattern {pat!r} must be anchored with ^...$")
            patterns_ok = False
            continue
        try:
            re.compile(pat)
        except re.error as exc:
            report.error(P_OWNERSHIP, f"bad pattern {pat!r}: {exc}")
            patterns_ok = False
    if not patterns_ok:
        return
    names, keys = set(), set()
    checks = {}
    for label in reg["labels"]:
        where = f"{P_OWNERSHIP}: label {label['name']}"
        check_localized(label, "description", where, report)
        if label["key"] != f"{reg['label_namespace']}.{label['name']}":
            report.error(where, "key must be label_namespace + '.' + name")
        if label["name"] in names or label["key"] in keys:
            report.error(where, "duplicate label")
        names.add(label["name"])
        keys.add(label["key"])
        if not pattern_matches(charset, label["key"]):
            report.error(where, "key does not match label_charset_pattern")
        if "value" in label and not (pattern_matches(label["value_pattern"], label["value"])
                                     and pattern_matches(charset, label["value"])):
            report.error(where, "value does not match value_pattern / label_charset_pattern")
        if label["required"]:
            checks[label["name"]] = (label["owned_when"], label.get("value"))
    expected = {"managed": ("equals_value", "true"), "profile": ("equals_current_profile", None)}
    for lname, rule in expected.items():
        if checks.get(lname) != rule:
            report.error(P_OWNERSHIP, f"label {lname} must be required with owned_when {rule[0]}"
                                      + (f" and value {rule[1]}" if rule[1] else ""))
    for rule in reg["rules"]:
        check_localized(rule, "text", f"{P_OWNERSHIP}: rule {rule['id']}", report)
    report.ok()
    vec = ctx["files"].get(P_OWNERSHIP_VECTORS)
    if vec is None:
        report.error(P_OWNERSHIP_VECTORS, "missing")
        return
    if not validate_against(vec, "schemas/ownership-vector.schema.json", P_OWNERSHIP_VECTORS, ctx, report):
        return
    for i, case in enumerate(vec["ownership_cases"]):
        got = is_owned(case["labels"], vec["profile"], reg)
        if got != case["owned"]:
            report.error(P_OWNERSHIP_VECTORS, f"ownership_cases[{i}] {case['name']}: expected owned={case['owned']}")
        else:
            report.ok()
    for i, case in enumerate(vec["caller_label_cases"]):
        got = caller_labels_accepted(case["labels"], reg)
        if got != case["accepted"]:
            report.error(P_OWNERSHIP_VECTORS, f"caller_label_cases[{i}] {case['name']}: expected accepted={case['accepted']}")
        else:
            report.ok()
    for i, case in enumerate(vec["adoption_cases"]):
        if is_adoptable(case, vec["profile"], reg) != case["adoptable"]:
            report.error(P_OWNERSHIP_VECTORS, f"adoption_cases[{i}] {case['name']}: expected adoptable={case['adoptable']}")
        else:
            report.ok()
    if "adoption" not in {r["id"] for r in reg["rules"]}:
        report.error(P_OWNERSHIP, "rule adoption (SEC-m5) is missing")
    for field, key in (("ownership_cases", "owned"), ("caller_label_cases", "accepted"), ("adoption_cases", "adoptable")):
        if {c[key] for c in vec[field]} != {True, False}:
            report.error(P_OWNERSHIP_VECTORS, f"{field} needs both {key}=true and {key}=false cases")


def check_wsl_resources(ctx: dict, report: Report) -> None:
    vec = ctx["files"].get(P_WSL_VECTORS)
    schema = ctx["schemas"].get(P_WSL_SCHEMA)
    if vec is None or schema is None:
        report.error(P_WSL_VECTORS, "vectors or schema missing")
        return
    if not validate_against(vec, "schemas/wsl-resources-vector.schema.json", P_WSL_VECTORS, ctx, report):
        return
    for i, case in enumerate(vec["cases"]):
        errs = schema_errors(case["value"], schema, schema)
        if (not errs) != case["valid"]:
            report.error(P_WSL_VECTORS, f"cases[{i}] {case['name']}: expected valid={case['valid']}, got "
                                        + ("; ".join(errs) if errs else "accepted"))
        else:
            report.ok()
    if {c["valid"] for c in vec["cases"]} != {True, False}:
        report.error(P_WSL_VECTORS, "needs both valid and invalid cases")
    plan_schema = ctx["schemas"].get(P_PLAN_SCHEMA, {})
    display = plan_schema.get("$defs", {}).get("display_text")
    for i, case in enumerate(vec["current_value_cases"]):
        # CR-29: a current value is shown in wslconfig_file.replaced only if it is valid display text.
        got = "replaced" if display is not None and not schema_errors(case["current_text"], display, plan_schema) \
            else "WSL_CONFIG_CONFLICT"
        if got != case["outcome"]:
            report.error(P_WSL_VECTORS, f"current_value_cases[{i}] {case['name']}: expected {case['outcome']}, got {got}")
        else:
            report.ok()


# --------------------------------------------------------------------------
# Step failures (CR-45), download redirects (CR-58 / SEC-11), run profiles (SEC-15)
# --------------------------------------------------------------------------

def expected_step_failures(rule: dict, platform: str) -> list:
    """Reference: the failure classes of a step kind on a platform, derived from its command
    templates (docs/installation-plan.md section 8). The last class is the catch-all."""
    ops = rule["commands"][platform]
    actions = {op.get("client_action") for op in ops}
    apt = {op["argv"][1] for op in ops if "argv" in op and op["argv"][0] == "/usr/bin/apt-get" and len(op["argv"]) > 1}
    if "engine_pull" in actions:
        return ["source_unavailable", "engine_command_failed"]
    out = []
    if "download_source" in actions or "update" in apt:
        out.append("source_unavailable")
    if platform == "windows" and rule["platforms"]["windows"]["privileged"]:
        # The elevated helper runs the step; it can also refuse the plan document it read (CR-73).
        return out + ["plan_refused", "elevation_unavailable", "elevated_step_failed"]
    if "download_source" in actions:  # the client stages the download and its verified copy itself
        out += ["insufficient_disk", "local_storage_failed"]
    if "install" in apt:
        out.append("package_install_failed")
    # On Windows every program and install_file of an unprivileged step goes through wsl.exe.
    if platform == "windows" and any("argv" in op or "install_file" in op for op in ops):
        out.append("wsl_command_failed")
    return out + ["command_failed"]


def failure_outcome(reg: dict, platform: str, case: dict):
    """(reason_code, next_state, event) of a failure class for a step kind or a state, or None when
    the class cannot occur there. Raises KeyError for an unknown kind, state or platform."""
    table = reg["step_kinds"][case["step_kind"]] if "step_kind" in case else reg["states"][case["state"]]
    if case["failure"] not in table[platform]:
        return None
    cls = next(c for c in reg["failure_classes"] if c["id"] == case["failure"])
    return cls["reason_code"], cls["to"], cls["event"]


_PROCESS_OUTCOMES = {"not_started", "timed_out", "exited"}
# Command -> (where it occurs, the outcomes it can have).
CLASSIFY_COMMANDS = {
    "download_source": ("step", {"completed", "failed", "disk_full", "storage_failed"}),
    "client_file": ("step", {"completed", "disk_full", "storage_failed"}),
    "client_action": ("step", {"completed", "failed"}),
    "apt_update": ("step", _PROCESS_OUTCOMES),
    "apt_install": ("step", _PROCESS_OUTCOMES),
    "program": ("step", _PROCESS_OUTCOMES),
    "engine_pull": ("step", _PROCESS_OUTCOMES | {"request_error", "stream_error"}),
    "engine": ("both", _PROCESS_OUTCOMES | {"request_error"}),
    "engine_identity": ("state", _PROCESS_OUTCOMES | {"request_error", "completed"}),
    "diagnostic": ("state", _PROCESS_OUTCOMES | {"request_error", "container_exited", "wait_timed_out"}),
    "probe_output": ("state", _PROCESS_OUTCOMES),
    "probe_exit_status": ("state", _PROCESS_OUTCOMES),
    "host_query": ("state", {"completed", "failed"}),
}


def is_docker_desktop(engine: dict) -> bool:
    """CW06: the engine identifies itself as Docker Desktop (info OperatingSystem, version Platform.Name)."""
    return engine.get("operating_system") == DOCKER_DESKTOP or \
        str(engine.get("platform_name", "")).startswith(DOCKER_DESKTOP)



def classify_result(platform: str, in_state: bool, command: str, result: dict) -> str:
    """Reference for docs/installation-plan.md section 8.2: the failure class chosen from the kind
    of command and how it ended, or `ok`, `answer` (a probe that answers by its exit status) or
    `evidence` (a probe with a complete, well-formed answer that is not the expected one)."""
    outcome, status = result["outcome"], result.get("exit_status")
    if command in ("download_source", "client_file", "client_action", "host_query"):  # no process of their own
        if outcome == "completed":
            return "ok"
        if outcome in ("disk_full", "storage_failed"):  # the client's own files
            return "insufficient_disk" if outcome == "disk_full" else "local_storage_failed"
        return {"download_source": "source_unavailable", "client_action": "command_failed",
                "host_query": "probe_failed"}[command]
    if command == "engine_identity":
        # CR-82: the identity is read before the is-active answer is used; Docker Desktop wins whatever it is.
        inactive = result.get("service_active") is False
        if outcome == "completed":
            desktop = is_docker_desktop(result.get("engine", {}))
            if desktop and inactive and not RULE_SWITCHES["docker_desktop_wins"]:
                return "answer"
            return "engine_docker_desktop" if desktop else "ok"
        if inactive:
            return "answer"  # the daemon is stopped: positive evidence, not a failure
    exited = outcome == "exited"
    # A Linux exit status is 0..255; through wsl.exe anything else is an error of wsl.exe itself (CR-70).
    in_range = exited and (0 <= status <= 255 or not RULE_SWITCHES["wsl_exit_range"])
    if command in ("engine", "engine_pull", "engine_identity", "diagnostic"):  # engine commands, whatever starts them (CR-75)
        if command == "diagnostic" and outcome == "container_exited":
            return "ok" if status == 0 else "smoke_test_failed"
        if command == "diagnostic" and outcome == "wait_timed_out":
            return "smoke_test_failed" if result.get("container") == "running" else "engine_command_failed"
        if in_range and status == 0:
            return "ok"
        if command == "engine_pull" and (outcome == "stream_error" or (in_range and status != 0)):
            return "source_unavailable"
        return "engine_command_failed"
    probe = command in ("probe_output", "probe_exit_status")
    no_answer = ("wsl_command_failed" if platform == "windows" else "probe_failed") if probe else None
    if not in_range:  # not started, timed out, or (Windows) an exit status outside 0..255
        if platform == "windows":
            return "wsl_command_failed"
        return "probe_failed" if probe else "command_failed"
    if command == "probe_exit_status":
        return "answer"
    if command == "probe_output":
        if status == 0 and result.get("output") == "expected":
            return "ok"
        if status == 0 and result.get("output") == "unexpected":
            return "evidence"
        # A non-zero status or incomplete output is no answer and never evidence (CR-70).
        return no_answer if RULE_SWITCHES["probe_failure_is_not_evidence"] else "evidence"
    if status == 0:
        return "ok"
    return {"apt_update": "source_unavailable", "apt_install": "package_install_failed"}.get(command, "command_failed")


def check_classification_vectors(reg: dict, kinds: dict, vec: dict, report: Report) -> None:
    names, commands, verdicts = set(), set(), set()
    for i, case in enumerate(vec["classification_cases"]):
        where = f"classification_cases[{i}] {case['name']}"
        if case["name"] in names:
            report.error(P_STEP_FAILURE_VECTORS, f"{where}: duplicate case name")
        names.add(case["name"])
        platform, command, result = case["platform"], case["command"], case["result"]
        in_state = "state" in case
        try:
            listed = (reg["states"][case["state"]] if in_state else reg["step_kinds"][case["step_kind"]])[platform]
        except KeyError as exc:
            report.error(P_STEP_FAILURE_VECTORS, f"{where}: unknown step kind, state or platform {exc}")
            continue
        if not in_state and platform == "windows" and kinds[case["step_kind"]]["platforms"]["windows"]["privileged"]:
            report.error(P_STEP_FAILURE_VECTORS, f"{where}: an elevated step is run by the helper, which reports its own outcome")
            continue
        occurs, outcomes = CLASSIFY_COMMANDS[command]
        if occurs != "both" and (occurs == "state") != in_state:
            report.error(P_STEP_FAILURE_VECTORS, f"{where}: command {command} does not occur there")
            continue
        shape_ok = result["outcome"] in outcomes and \
            (("exit_status" in result) == (result["outcome"] in ("exited", "container_exited"))) and \
            (("engine" in result) == (command == "engine_identity" and result["outcome"] == "completed")) and \
            (("container" in result) == (result["outcome"] == "wait_timed_out")) and \
            ("output" not in result or (command == "probe_output" and result.get("exit_status") == 0)) and \
            ("service_active" not in result or command == "engine_identity")
        if not shape_ok:
            report.error(P_STEP_FAILURE_VECTORS, f"{where}: result {result} does not fit command {command}")
            continue
        got = classify_result(platform, in_state, command, result)
        commands.add(command)
        verdicts.add(got)
        if got != case["expected"]:
            report.error(P_STEP_FAILURE_VECTORS, f"{where}: expected {case['expected']}, section 8.2 gives {got}")
            continue
        if got not in ("ok", "answer", "evidence") and got not in listed:
            report.error(P_STEP_FAILURE_VECTORS, f"{where}: class {got} is not listed for it in {P_STEP_FAILURES}")
            continue
        report.ok()
    for command in sorted(set(CLASSIFY_COMMANDS) - commands):
        report.error(P_STEP_FAILURE_VECTORS, f"no classification case for command {command}")
    for verdict in ("ok", "answer", "evidence"):
        if verdict not in verdicts:
            report.error(P_STEP_FAILURE_VECTORS, f"no classification case with the result {verdict}")


def check_step_failures(ctx: dict, report: Report) -> None:
    name = P_STEP_FAILURES
    reg = ctx["files"].get(name)
    kinds = ctx.get("step_kinds")
    bootstrap = ctx.get("machines", {}).get("bootstrap")
    if reg is None or kinds is None or bootstrap is None:
        report.error(name, "registry, step kinds or the bootstrap machine missing")
        return
    if not validate_against(reg, "schemas/step-failures.schema.json", name, ctx, report):
        return
    reason_codes = ctx.get("reason_codes", {})
    classes = {}
    for c in reg["failure_classes"]:
        where = f"{name}: failure class {c['id']}"
        if c["id"] in classes:
            report.error(where, "duplicate failure class")
        classes[c["id"]] = c
        check_localized(c, "description", where, report)
        if c["reason_code"] not in reason_codes:
            report.error(where, f"unknown reason code {c['reason_code']}")
    declared = {cid: (c["reason_code"], c["to"], c["event"]) for cid, c in classes.items()}
    if declared != SPEC_FAILURE_CLASSES or list(classes) != list(SPEC_FAILURE_CLASSES):
        report.error(name, f"failure classes and their outcomes must be exactly {SPEC_FAILURE_CLASSES} (CR-45)")
        return
    pairs = bootstrap["pairs"]

    def check_list(where, platform, listed, from_states):
        for cid in listed:
            c = classes.get(cid)
            if c is None:
                report.error(where, f"unknown failure class {cid}")
                continue
            if platform not in reason_codes.get(c["reason_code"], {}).get("platforms", []):
                report.error(where, f"{cid} gives {c['reason_code']}, which is not a {platform} code")
            for f in from_states:
                if (f, c["to"]) not in pairs:
                    report.error(where, f"{cid} goes to {c['to']}, but {f}->{c['to']} is not a transition")

    if set(reg["step_kinds"]) != set(kinds):
        report.error(name, f"step_kinds must list exactly the step kinds: extra {sorted(set(reg['step_kinds']) - set(kinds))}, "
                           f"missing {sorted(set(kinds) - set(reg['step_kinds']))}")
    for kind, table in reg["step_kinds"].items():
        rule = kinds.get(kind)
        if rule is None:
            continue
        if set(table) != set(rule["platforms"]):
            report.error(f"{name}: {kind}", "failure classes must be given for exactly the kind's platforms")
            continue
        for platform, listed in table.items():
            where = f"{name}: {kind} on {platform}"
            want = expected_step_failures(rule, platform)
            if listed != want:
                report.error(where, f"failure classes must be {want} (derived from the command templates), found {listed}")
            if kind == "image_pull":
                from_states = ["IMAGE_PULL"]
            elif rule["platforms"][platform]["privileged"]:
                from_states = ["INSTALLING", "WAITING_FOR_PRIVILEGE"]
            else:
                from_states = ["INSTALLING"]
            check_list(where, platform, listed, from_states)
    if reg["states"] != SPEC_STATE_FAILURES:
        report.error(name, f"states must be exactly {SPEC_STATE_FAILURES}")
    for state, table in reg["states"].items():
        if state not in bootstrap["states"]:
            report.error(name, f"{state} is not a bootstrap state")
            continue
        for platform, listed in table.items():
            check_list(f"{name}: {state} on {platform}", platform, listed, [state])
    report.ok()

    vec = ctx["files"].get(P_STEP_FAILURE_VECTORS)
    if vec is None:
        report.error(P_STEP_FAILURE_VECTORS, "missing")
        return
    if not validate_against(vec, "schemas/step-failure-vector.schema.json", P_STEP_FAILURE_VECTORS, ctx, report):
        return
    covered, names, not_applicable = set(), set(), 0
    for i, case in enumerate(vec["cases"]):
        where = f"cases[{i}] {case['name']}"
        if case["name"] in names:
            report.error(P_STEP_FAILURE_VECTORS, f"{where}: duplicate case name")
        names.add(case["name"])
        if case["failure"] not in classes:
            report.error(P_STEP_FAILURE_VECTORS, f"{where}: unknown failure class {case['failure']}")
            continue
        try:
            got = failure_outcome(reg, case["platform"], case)
        except KeyError as exc:
            report.error(P_STEP_FAILURE_VECTORS, f"{where}: unknown step kind, state or platform {exc}")
            continue
        want = (case["reason_code"], case["expected_next_state"], case["expected_event"]) \
            if case["expected"] == "mapped" else None
        if got != want:
            report.error(P_STEP_FAILURE_VECTORS, f"{where}: expected {want or 'not_applicable'}, registry gives {got or 'not_applicable'}")
            continue
        if got is None:
            not_applicable += 1
        else:
            covered.add((case.get("step_kind") or case["state"], case["platform"], case["failure"]))
        report.ok()
    for section in ("step_kinds", "states"):
        for where_id, table in reg[section].items():
            for platform, listed in table.items():
                for cid in listed:
                    if (where_id, platform, cid) not in covered:
                        report.error(P_STEP_FAILURE_VECTORS, f"no mapped case for {cid} of {where_id} on {platform}")
    if not not_applicable:
        report.error(P_STEP_FAILURE_VECTORS, "needs a not_applicable case")
    check_classification_vectors(reg, kinds, vec, report)


def _hop_host(url: str):
    """Host of an acceptable hop (https, no userinfo, no explicit port), lowercased; else None."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    https = parts.scheme == "https" or not RULE_SWITCHES["redirect_https_hops"]
    if not https or "@" in parts.netloc or port is not None or not parts.hostname:
        return None
    return parts.hostname.lower()


def download_allowed(rule: dict, requested_url: str, redirects: list, url_schema: dict, root: dict,
                     response_bytes=None) -> bool:
    """Reference for docs/installation-plan.md rule 10 (CR-58 / SEC-11, CR-77). `redirects` are the
    Location targets in order, as absolute URLs; the last one is the final URL. response_bytes is
    the length of the final response body, when the case gives it."""
    prefixes = rule["source_url_prefixes"]
    # The requested URL is step.source.url: the strict https_url form of the plan schema, under a prefix.
    if RULE_SWITCHES["requested_url_strict"] and schema_errors(requested_url, url_schema, root):
        return False
    if not any(requested_url.startswith(p) for p in prefixes):
        return False
    requested_host = _hop_host(requested_url)
    if requested_host is None or len(redirects) > MAX_REDIRECTS:
        return False
    hosts = [_hop_host(url) for url in redirects]
    if None in hosts:
        return False
    final_url = redirects[-1] if redirects else requested_url
    if not RULE_SWITCHES["redirect_prefix_on_requested_only"] and not any(final_url.startswith(p) for p in prefixes):
        return False  # the 0.2.0 rule, kept only for --self-test
    if RULE_SWITCHES["redirect_host_check"]:
        # CR-77: every hop, not only the last one, stays on the requested host or a listed host.
        allowed = {requested_host} | set(rule.get("redirect_hosts", []))
        if any(host not in allowed for host in (hosts if RULE_SWITCHES["redirect_every_hop"] else hosts[-1:])):
            return False
    if response_bytes is not None and RULE_SWITCHES["download_size_cap"] \
            and response_bytes > rule["download"]["max_bytes"]:
        return False
    return True


def check_redirect_vectors(ctx: dict, report: Report) -> None:
    vec = ctx["files"].get(P_REDIRECT_VECTORS)
    kinds = ctx.get("step_kinds")
    plan_schema = ctx["schemas"].get(P_PLAN_SCHEMA, {})
    url_schema = plan_schema.get("$defs", {}).get("https_url")
    if vec is None or kinds is None or url_schema is None:
        report.error(P_REDIRECT_VECTORS, "vectors, step-kind registry or the https_url definition missing")
        return
    if not validate_against(vec, "schemas/download-redirect-vector.schema.json", P_REDIRECT_VECTORS, ctx, report):
        return
    names, verdicts, ended_on = set(), set(), set()
    for i, case in enumerate(vec["cases"]):
        where = f"cases[{i}] {case['name']}"
        if case["name"] in names:
            report.error(P_REDIRECT_VECTORS, f"{where}: duplicate case name")
        names.add(case["name"])
        rule = kinds.get(case["step_kind"])
        if rule is None or not rule["source_url_prefixes"]:
            report.error(P_REDIRECT_VECTORS, f"{where}: {case['step_kind']} is not a step kind with a source")
            continue
        got = download_allowed(rule, case["requested_url"], case["redirects"], url_schema, plan_schema,
                               case.get("response_bytes"))
        verdicts.add(got)
        if got != (case["expected"] == "allowed"):
            report.error(P_REDIRECT_VECTORS, f"{where}: expected {case['expected']}, the rule gives "
                                             f"{'allowed' if got else 'refused'}")
            continue
        if got and case["redirects"]:
            ended_on.add((case["step_kind"], _hop_host(case["redirects"][-1])))
        report.ok()
    if verdicts != {True, False}:
        report.error(P_REDIRECT_VECTORS, "needs both allowed and refused cases")
    sized = {c["expected"] for c in vec["cases"] if "response_bytes" in c}
    if sized != {"allowed", "refused"}:
        report.error(P_REDIRECT_VECTORS, "needs an allowed and a refused case with response_bytes (CR-77)")
    hosts = {h for rule in kinds.values() for h in rule["redirect_hosts"]}
    for host in sorted(hosts - {h for _, h in ended_on}):
        report.error(P_REDIRECT_VECTORS, f"no allowed case that ends on the listed redirect host {host}")


def _option_group_matches(group: list, options: list, at: int, params: dict, limits: dict) -> bool:
    if len(options) - at < len(group):
        return False
    for token, got in zip(group, options[at:at + len(group)]):
        placeholder = _PLACEHOLDER.fullmatch(token)
        if placeholder is None:
            if token != got:
                return False
        else:
            pname = placeholder.group(1)
            if pname in limits:
                if got != limits[pname]:
                    return False
            elif pname not in params or not pattern_matches(params[pname], got):
                return False
    return True


def run_conforms(reg: dict, profile_id: str, options: list, after_image=()) -> bool:
    """Reference for docs/images-and-ownership.md section 5: every option group of the profile
    exactly once, everything else from other_options, placeholders matching their parameters,
    and nothing after the image reference (CR-76)."""
    profile = next((p for p in reg["profiles"] if p["id"] == profile_id), None)
    if profile is None or profile["status"] != "normative":
        return False  # to_be_defined: no container of that purpose is run
    if after_image and RULE_SWITCHES["run_profile_nothing_after_image"]:
        return False
    params = {p["name"]: p["pattern"] for p in reg["parameters"]}
    limits = profile.get("limits", {})
    required, other = profile["docker_run_options"], profile["other_options"]
    seen = [0] * len(required)
    at = 0
    while at < len(options):
        for index, group in enumerate(required):
            if _option_group_matches(group, options, at, params, limits):
                seen[index] += 1
                at += len(group)
                break
        else:
            for group in other:
                if _option_group_matches(group, options, at, params, limits):
                    at += len(group)
                    break
            else:
                if RULE_SWITCHES["run_profile_closed"]:
                    return False
                at += 1
    return all(n == 1 or (n > 1 and not RULE_SWITCHES["run_profile_exactly_once"]) for n in seen)


def check_run_profiles(ctx: dict, report: Report) -> None:
    name = P_RUN_PROFILES
    reg = ctx["files"].get(name)
    if reg is None:
        report.error(name, "missing")
        return
    if not validate_against(reg, "schemas/run-profiles.schema.json", name, ctx, report):
        return
    params = {}
    for p in reg["parameters"]:
        pat = p["pattern"]
        if p["name"] in params:
            report.error(name, f"duplicate parameter {p['name']}")
        params[p["name"]] = pat
        if not (pat.startswith("^") and pat.endswith("$") and not pat.endswith("\\$")):
            report.error(name, f"parameter {p['name']}: pattern {pat!r} must be anchored with ^...$")
            return
        try:
            re.compile(pat)
        except re.error as exc:
            report.error(name, f"parameter {p['name']}: bad pattern {pat!r}: {exc}")
            return
    profiles = {}
    for profile in reg["profiles"]:
        where = f"{name}: profile {profile['id']}"
        if profile["id"] in profiles:
            report.error(where, "duplicate profile")
        profiles[profile["id"]] = profile
        check_localized(profile, "description", where, report)
        used = set()
        for group in profile.get("docker_run_options", []) + profile.get("other_options", []):
            for token in group:
                for pname in _PLACEHOLDER.findall(token):
                    used.add(pname)
                    if token != "{" + pname + "}" or pname not in params:
                        report.error(where, f"placeholder {{{pname}}} must be a whole token naming a declared parameter")
        limit_names = {t[1:-1] for g in profile.get("docker_run_options", []) for t in g if _PLACEHOLDER.fullmatch(t)}
        limits = profile.get("limits")
        if limits is not None:
            if set(limits) != limit_names:
                report.error(where, f"limits must fix exactly {sorted(limit_names)}")
            for pname, value in limits.items():
                if pname in params and not pattern_matches(params[pname], value):
                    report.error(where, f"limit {pname}={value!r} does not match its parameter pattern")
    if {pid: p["status"] for pid, p in profiles.items()} != SPEC_RUN_PROFILES:
        report.error(name, f"profiles and their status must be {SPEC_RUN_PROFILES}: a new normative profile "
                           "needs its own security review and a change in tools/validate.py (SEC-15)")
        return
    purposes = set(ctx["schemas"].get(P_ALLOWLIST_SCHEMA, {}).get("$defs", {}).get("entry", {})
                   .get("properties", {}).get("purpose", {}).get("enum", []))
    if purposes != set(profiles):
        report.error(name, f"profile ids must equal the allowlist purposes {sorted(purposes)}")
    diagnostic = profiles["diagnostic"]
    for group in SPEC_DIAGNOSTIC_OPTIONS:
        if group not in diagnostic["docker_run_options"]:
            report.error(name, f"the diagnostic profile must contain {' '.join(group)} (SEC-15)")
    if diagnostic["docker_run_options"] != SPEC_DIAGNOSTIC_OPTIONS:
        report.error(name, f"the diagnostic options must be exactly {SPEC_DIAGNOSTIC_OPTIONS}")
    if diagnostic["other_options"] != SPEC_DIAGNOSTIC_OTHER_OPTIONS:
        report.error(name, f"the other options of the diagnostic profile must be exactly {SPEC_DIAGNOSTIC_OTHER_OPTIONS}")
    if diagnostic["removal"] != "always":
        report.error(name, "the diagnostic container is always removed")
    # An image may be allowlisted only for a purpose whose run profile is defined, with fixed limits.
    for entry in (ctx["files"].get(P_ALLOWLIST) or {}).get("entries", []):
        profile = profiles.get(entry.get("purpose")) if isinstance(entry, dict) else None
        if profile is None or profile["status"] != "normative" or "limits" not in profile:
            report.error(P_ALLOWLIST, f"an image with purpose {entry.get('purpose') if isinstance(entry, dict) else entry!r} "
                                      f"needs a normative run profile with fixed limits in {name} (SEC-15)")
    report.ok()

    vec = ctx["files"].get(P_RUN_PROFILE_VECTORS)
    if vec is None:
        report.error(P_RUN_PROFILE_VECTORS, "missing")
        return
    if not validate_against(vec, "schemas/run-profile-vector.schema.json", P_RUN_PROFILE_VECTORS, ctx, report):
        return
    names, verdicts = set(), set()
    for i, case in enumerate(vec["cases"]):
        where = f"cases[{i}] {case['name']}"
        if case["name"] in names:
            report.error(P_RUN_PROFILE_VECTORS, f"{where}: duplicate case name")
        names.add(case["name"])
        got = run_conforms(reg, case["profile"], case["options"], case.get("after_image", ()))
        verdicts.add(got)
        if got != (case["expected"] == "conforming"):
            report.error(P_RUN_PROFILE_VECTORS, f"{where}: expected {case['expected']}, the profile gives "
                                                f"{'conforming' if got else 'non_conforming'}")
        else:
            report.ok()
    if verdicts != {True, False}:
        report.error(P_RUN_PROFILE_VECTORS, "needs both conforming and non_conforming cases")
    for pid, profile in profiles.items():
        cases = [c for c in vec["cases"] if c["profile"] == pid]
        if not cases:
            report.error(P_RUN_PROFILE_VECTORS, f"no case for profile {pid}")
        for group in profile.get("docker_run_options", []):
            if not any(c["expected"] == "non_conforming" and group[0] not in c["options"] for c in cases):
                report.error(P_RUN_PROFILE_VECTORS, f"no non_conforming case of {pid} without {group[0]}")
            if not any(c["expected"] == "non_conforming" and c["options"].count(group[0]) > 1 for c in cases):
                report.error(P_RUN_PROFILE_VECTORS, f"no non_conforming case of {pid} with {group[0]} repeated (CR-76)")
        if profile["status"] == "normative" and not any(c.get("after_image") for c in cases):
            report.error(P_RUN_PROFILE_VECTORS, f"no case of {pid} with arguments after the image reference (CR-76)")


def run_checks(ctx: dict, report: Report) -> None:
    check_version(ctx, report)
    check_schemas(ctx, report)
    check_shared_defs(ctx, report)
    check_exit_codes(ctx, report)
    check_reason_codes(ctx, report)
    check_state_machines(ctx, report)
    check_step_kinds(ctx, report)
    check_canonical_vectors(ctx, report)
    check_transition_vectors(ctx, report)
    check_guard_vectors(ctx, report)
    check_effect_vectors(ctx, report)
    check_exit_vectors(ctx, report)
    check_event_vectors(ctx, report)
    check_plan_vectors(ctx, report)
    check_precondition_vectors(ctx, report)
    check_allowlist(ctx, report)
    check_ownership(ctx, report)
    check_wsl_resources(ctx, report)
    check_step_failures(ctx, report)
    check_redirect_vectors(ctx, report)
    check_run_profiles(ctx, report)


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


def _step_kind(ctx, kind):
    return next(k for k in ctx["files"][P_STEP_KINDS]["step_kinds"] if k["kind"] == kind)


def _plan_vector(ctx, name):
    return ctx["files"][D_PLANS + name + ".json"]


def _reads_without_consent(ctx):
    for p in _machine(ctx, "bootstrap")["guard_predicates"]:
        if p["id"] == "step_is_privileged_plan_step":
            p["reads"] = ["step"]


def _uac_step_unprivileged(ctx):
    _step_kind(ctx, "enable_wsl_features")["platforms"]["windows"]["privileged"] = False
    _step_kind(ctx, "enable_wsl_features").pop("windows_elevated_step")


def _import_distro_privileged(ctx):
    _step_kind(ctx, "import_distro")["platforms"]["windows"]["privileged"] = True
    _step_kind(ctx, "import_distro")["windows_elevated_step"] = "IMPORT_DISTRO"


def _linux_apt_unprivileged(ctx):
    _step_kind(ctx, "apt_add_docker_repo")["platforms"]["linux"]["privileged"] = False


def _open_vocabulary(ctx):
    entry = copy.deepcopy(_step_kind(ctx, "start_engine"))
    entry["kind"] = "run_script"
    ctx["files"][P_STEP_KINDS]["step_kinds"].append(entry)


def _image_on_install_step(ctx):
    _step_kind(ctx, "install_docker_engine")["optional_members"].append("image")


def _rootfs_source_optional(ctx):
    k = _step_kind(ctx, "import_distro")
    k["required_members"].remove("source")
    k["optional_members"].append("source")


def _prefix_without_path(ctx):
    _step_kind(ctx, "apt_add_docker_repo")["source_url_prefixes"] = ["https://download.docker.com"]


def _relogin_may(ctx):
    _step_kind(ctx, "add_user_to_docker_group")["flags"]["requires_relogin"] = "may"


def _elevated_renamed(ctx):
    _step_kind(ctx, "update_wsl")["windows_elevated_step"] = "UPGRADE_WSL"


def _title_template_changed(ctx):
    _step_kind(ctx, "install_docker_engine")["title"]["en"] = "Install Docker"


def _free_placeholder(ctx):
    _step_kind(ctx, "install_docker_engine")["title"]["en"] = "Install {package}"


def _plan_allows_unknown_members(ctx):
    ctx["files"][P_PLAN_SCHEMA].pop("additionalProperties")


def _plan_hash_optional(ctx):
    ctx["files"][P_PLAN_SCHEMA]["required"].remove("hash")


def _plan_step_allows_unknown_members(ctx):
    ctx["files"][P_PLAN_SCHEMA]["$defs"]["step"].pop("additionalProperties")


def _consented_digests_all_images(ctx):
    vec = _plan_vector(ctx, "linux-zero-action")
    vec["derived"]["consented_image_references"] = list(vec["document"]["images"])


def _action_count_without_pulls(ctx):
    _plan_vector(ctx, "linux-pull-only")["derived"]["plan_action_count"] = 0


def _plan_document_tampered(ctx):
    _plan_vector(ctx, "linux-fresh-install")["document"]["steps"][1]["estimated_bytes"] += 1
    _plan_vector(ctx, "linux-fresh-install")["document"]["disk_estimate_bytes"] += 1


def _allowlist_digest_drift(ctx):
    ctx["files"][P_ALLOWLIST_SCHEMA]["$defs"]["image_digest"]["pattern"] = "^sha256:[0-9a-fA-F]{64}$"


def _bundled_allowlist_tag(ctx):
    ctx["files"][P_ALLOWLIST]["entries"].append(
        {"repository": "ghcr.io/alexindacomp/sprut-worker", "digest": "latest", "purpose": "worker",
         "platform": "linux/amd64", "min_client_version": "0.1.0"})


def _profile_label_optional(ctx):
    for label in ctx["files"][P_OWNERSHIP]["labels"]:
        if label["name"] == "profile":
            label["required"] = False


def _profile_not_checked(ctx):
    for label in ctx["files"][P_OWNERSHIP]["labels"]:
        if label["name"] == "profile":
            label["owned_when"] = "not_checked"


def _namespace_changed(ctx):
    reg = ctx["files"][P_OWNERSHIP]
    reg["label_namespace"] = "io.sprut"
    for label in reg["labels"]:
        label["key"] = "io.sprut." + label["name"]


def _wslconfig_any_key(ctx):
    ctx["files"][P_WSL_SCHEMA]["$defs"]["wslconfig_wsl2"].pop("additionalProperties")
    ctx["files"][P_PLAN_SCHEMA]["$defs"]["wslconfig_wsl2"].pop("additionalProperties")


def _integer_accepts_fraction(ctx):
    SCHEMA_SEMANTICS["integer_accepts_integral_fraction"] = True


def _drop_foreign_resource(ctx):
    reg = ctx["files"][P_REASON_CODES]
    reg["reason_codes"] = [c for c in reg["reason_codes"] if c["code"] != "FOREIGN_RESOURCE"]


def _event_schema_version_untyped(ctx):
    ctx["files"][P_EVENT_SCHEMA]["properties"]["schema_version"].pop("type")


def _engine_reject_to_failed(ctx):
    _guard(ctx, "ENGINE_CHECK", "IMAGE_PULL")["on_reject"]["ENGINE_TCP_EXPOSED"] = {"to": "FAILED", "event": "error"}


def _swap_predicate(pid, fn):
    def apply(ctx):
        PREDICATES[pid] = (fn,) + PREDICATES[pid][1:]
    return apply


def _consented_by_digest(c):
    ref, listed = c.get("image_reference", ""), c.get("consented_image_references") or []
    ok = isinstance(c.get("consented_plan_id"), str) and ref.split("@")[-1] in [r.split("@")[-1] for r in listed]
    return None if ok else "CONSENT_REQUIRED"


def _allowlist_by_digest(c):
    ref, allow = c.get("image_reference", ""), c.get("allowlist") or []
    return None if ref.split("@")[-1] in [a.split("@")[-1] for a in allow] else "IMAGE_NOT_ALLOWED"


def _engine_accepts_loopback_tcp(c):
    ep = c.get("engine_endpoint", "")
    if not (ep.startswith("unix:///") or ep.startswith("tcp://127.0.0.1")):
        return "ENGINE_REMOTE_CONTEXT"
    return None if c.get("engine_tcp_listener") is False else "ENGINE_TCP_EXPOSED"


def _terms_without_acknowledgements(c):
    n, h = c.get("required_licence_ids"), c.get("accepted_licence_ids")
    return None if isinstance(n, list) and isinstance(h, list) and set(n) <= set(h) else "CONSENT_REQUIRED"


def _drop_consent_effect_check(ctx):
    for e in _machine(ctx, "bootstrap")["effects"]:
        e.pop("checks", None)
        e.pop("on_reject", None)


def _swap_precondition(pid, fn):
    def apply(ctx):
        STEP_PRECONDITIONS[pid] = (fn,) + STEP_PRECONDITIONS[pid][1:]
    return apply


def _restart_without_drain(step, rule, o, env):
    lists = ("running_distributions",) if rule["kind"] == "restart_wsl" else ("registered_distributions",)
    if not all(_name_list(o.get(name)) for name in lists):
        return "WSL_RESTART_REQUIRED"
    return None if o.get("wsl_restart_confirmed") is True else "WSL_RESTART_REQUIRED"


def _restart_without_precondition(ctx):
    _step_kind(ctx, "restart_wsl")["preconditions"] = []


def _shell_command(ctx):
    _step_kind(ctx, "start_engine")["commands"]["linux"].append({"argv": ["/bin/sh", "-c", "systemctl start docker"]})


def _free_command_placeholder(ctx):
    _step_kind(ctx, "start_engine")["commands"]["linux"].append({"argv": ["/usr/bin/systemctl", "start", "{service}"]})


def _elevated_in_distro_program(ctx):
    _step_kind(ctx, "update_wsl")["commands"]["windows"].append({"argv": ["/usr/bin/apt-get", "update"]})


def _group_without_acknowledgement(ctx):
    _step_kind(ctx, "add_user_to_docker_group").pop("acknowledgement")


def _rootfs_without_licence(ctx):
    _step_kind(ctx, "import_distro")["licence_required"] = False


def _unverified_title_removed(ctx):
    _step_kind(ctx, "install_wsl").pop("title_without_source")


def _prefix_shape(ctx):
    ctx["files"]["schemas/plan-step-kinds.schema.json"]["$defs"]["step_kind"]["properties"]["source_url_prefixes"]["items"].pop("pattern")
    _step_kind(ctx, "apt_add_docker_repo")["source_url_prefixes"] = ["https://download.docker.com/linux/ubuntu"]


def _mirrored_allowed(ctx):
    for path in (P_WSL_SCHEMA, P_PLAN_SCHEMA):
        ctx["files"][path]["$defs"]["wslconfig_wsl2"]["properties"]["networkingMode"]["enum"] = ["nat", "mirrored"]


def _switch_off(name):
    def apply(ctx):
        RULE_SWITCHES[name] = False
    return apply


def _precondition_to_non_edge(ctx):
    for p in ctx["files"][P_STEP_KINDS]["preconditions"]:
        if p["id"] == "wsl_restart_confirmed":
            p["on_reject"]["WSL_RESTART_REQUIRED"]["to"] = "READY"


def _allowlist_entry_without_codeowners(ctx):
    ctx["files"][P_ALLOWLIST]["entries"].append(
        {"repository": "ghcr.io/alexindacomp/sprut-worker", "digest": "sha256:" + "1" * 64, "purpose": "worker",
         "platform": "linux/amd64", "min_client_version": "0.2.0"})


def _verify_source_dropped(ctx):
    ops = _step_kind(ctx, "apt_add_docker_repo")["commands"]["linux"]
    ops[:] = [op for op in ops if op.get("client_action") != "verify_source"]


def _env_launcher(ctx):
    for op in _step_kind(ctx, "install_docker_engine")["commands"]["linux"]:
        op["argv"] = ["/usr/bin/env", "DEBIAN_FRONTEND=noninteractive"] + op["argv"]


def _wsl_display_too_wide(ctx):
    ctx["files"][P_PLAN_SCHEMA]["$defs"]["display_text"].pop("pattern")


def _drop_adoption_rule(ctx):
    reg = ctx["files"][P_OWNERSHIP]
    reg["rules"] = [r for r in reg["rules"] if r["id"] != "adoption"]


def _prerelease_equals_release(ctx):
    global _semver
    original = _semver
    _semver = lambda text: original(text.partition("-")[0])  # noqa: E731


def _object_hash_array_as_kind(ctx):
    ctx["files"][D_CANONICAL_INVALID + "reject-object-hash-of-array.json"]["expected_error"] = "INVALID_KIND"


# --- sprut-contracts 0.3.0 ---

def _drop_reason_code(code):
    def apply(ctx):
        reg = ctx["files"][P_REASON_CODES]
        reg["reason_codes"] = [c for c in reg["reason_codes"] if c["code"] != code]
    return apply


def _wsl_state(ctx, name):
    return next(s for s in _machine(ctx, "wsl_availability")["states"] if s["name"] == name)


def _policy_blocked_not_terminal(ctx):
    m = _machine(ctx, "wsl_availability")
    m["terminal"].remove("WSL_POLICY_BLOCKED")
    m["transitions"].append({"from": "WSL_POLICY_BLOCKED", "to": "WSL_MISSING"})


def _policy_blocked_without_reason(ctx):
    _wsl_state(ctx, "WSL_POLICY_BLOCKED").pop("reason_code")


def _policy_blocked_removed(ctx):
    m = _machine(ctx, "wsl_availability")
    m["states"] = [s for s in m["states"] if s["name"] != "WSL_POLICY_BLOCKED"]
    m["terminal"].remove("WSL_POLICY_BLOCKED")


def _failure_class(ctx, cid):
    return next(c for c in ctx["files"][P_STEP_FAILURES]["failure_classes"] if c["id"] == cid)


def _wsl_failure_as_broken_distro(ctx):
    _failure_class(ctx, "wsl_command_failed")["reason_code"] = "WSL_DISTRO_BROKEN"


def _elevation_unavailable_to_failed(ctx):
    _failure_class(ctx, "elevation_unavailable")["to"] = "FAILED"


def _apt_install_as_source_failure(ctx):
    ctx["files"][P_STEP_FAILURES]["step_kinds"]["install_docker_engine"]["windows"] = \
        ["source_unavailable", "wsl_command_failed", "command_failed"]


def _elevated_step_as_step_failed(ctx):
    ctx["files"][P_STEP_FAILURES]["step_kinds"]["update_wsl"]["windows"] = ["source_unavailable", "command_failed"]


def _probe_failure_class_dropped(ctx):
    ctx["files"][P_STEP_FAILURES]["states"]["PROBING"]["windows"] = ["engine_command_failed"]


def _smoke_engine_failure_dropped(ctx):
    ctx["files"][P_STEP_FAILURES]["states"]["SMOKE_TEST"]["linux"] = ["smoke_test_failed"]


def _step_failure_vector_changed(ctx):
    for case in ctx["files"][P_STEP_FAILURE_VECTORS]["cases"]:
        if case["name"] == "windows-start-engine-command-failed":
            case["reason_code"] = "ENGINE_DAEMON_STOPPED"


def _failure_kind_missing(ctx):
    ctx["files"][P_STEP_FAILURES]["step_kinds"].pop("restart_wsl")


def _unregister_without_replacement(ctx):
    _step_kind(ctx, "unregister_distro")["preconditions"] = ["distro_owned", "sprut_drained"]


def _replacement_never_checked(step, rule, o, env):
    return None


def _replacement_by_presence_only(step, rule, o, env):
    return None if isinstance(o.get("replacement_downloaded_sha256"), str) else "SOURCE_UNAVAILABLE"


def _replacement_reject_to_probing(ctx):
    for p in ctx["files"][P_STEP_KINDS]["preconditions"]:
        if p["id"] == "replacement_source_verified":
            p["on_reject"]["SOURCE_UNAVAILABLE"] = {"to": "PROBING", "event": "state"}


def _wsl_update_without_confirmation(ctx):
    _step_kind(ctx, "update_wsl")["preconditions"] = ["source_verified"]


def _wsl_install_without_confirmation(ctx):
    _step_kind(ctx, "install_wsl")["preconditions"] = ["source_verified"]


def _unreadable_list_is_empty(step, rule, o, env):
    if rule["kind"] != "restart_wsl" and not (o.get("registered_distributions") or []):
        return None
    ok = o.get("sprut_drained") is True and o.get("wsl_restart_confirmed") is True
    return None if ok else "WSL_RESTART_REQUIRED"


def _update_always_without_dialog(step, rule, o, env):
    if rule["kind"] != "restart_wsl":
        return None if _name_list(o.get("registered_distributions")) else "WSL_RESTART_REQUIRED"
    return _PRECONDITION_WSL_RESTART(step, rule, o, env)


def _resize_without_terminate(ctx):
    ops = _step_kind(ctx, "resize_distro_disk")["commands"]["windows"]
    ops[:] = [op for op in ops if "--terminate" not in op.get("argv", [])]


def _resize_without_drain(ctx):
    _step_kind(ctx, "resize_distro_disk")["preconditions"] = []


def _configure_without_drain(ctx):
    _step_kind(ctx, "configure_distro")["preconditions"] = []


def _drain_never_checked(step, rule, o, env):
    return None


def _redirect_host_with_scheme(ctx):
    schema = ctx["files"]["schemas/plan-step-kinds.schema.json"]
    schema["$defs"]["step_kind"]["properties"]["redirect_hosts"]["items"].pop("pattern")
    _step_kind(ctx, "install_wsl")["redirect_hosts"][0] = "https://objects.githubusercontent.com"


def _redirect_host_wildcard(ctx):
    schema = ctx["files"]["schemas/plan-step-kinds.schema.json"]
    schema["$defs"]["step_kind"]["properties"]["redirect_hosts"]["items"].pop("pattern")
    _step_kind(ctx, "install_wsl")["redirect_hosts"][0] = "*.githubusercontent.com"


def _redirect_host_added(ctx):
    _step_kind(ctx, "import_distro")["redirect_hosts"].append("mirror.example.net")


def _redirect_hosts_optional(ctx):
    ctx["files"]["schemas/plan-step-kinds.schema.json"]["$defs"]["step_kind"]["required"].remove("redirect_hosts")
    _step_kind(ctx, "install_wsl").pop("redirect_hosts")


def _client_hash_not_required(step, rule, o, env):
    if "source" not in step:
        return None if "source" in rule["optional_members"] else "INTEGRITY_MISMATCH"
    return None if o.get("downloaded_sha256") == step["source"]["sha256"] else "INTEGRITY_MISMATCH"


def _client_hash_only(step, rule, o, env):
    if "source" not in step:
        return None if "source" in rule["optional_members"] else "INTEGRITY_MISMATCH"
    key = "staged_sha256" if verified_in_distro(rule, env["platform"]) else "downloaded_sha256"
    return None if o.get(key) == step["source"]["sha256"] else "INTEGRITY_MISMATCH"


def _run_profile(ctx, pid):
    return next(p for p in ctx["files"][P_RUN_PROFILES]["profiles"] if p["id"] == pid)


def _diagnostic_drop_group(first):
    def apply(ctx):
        profile = _run_profile(ctx, "diagnostic")
        profile["docker_run_options"] = [g for g in profile["docker_run_options"] if g[0] != first]
    return apply


def _diagnostic_not_removed(ctx):
    ctx["files"]["schemas/run-profiles.schema.json"]["$defs"]["profile"]["properties"]["removal"]["enum"].append("on_success")
    _run_profile(ctx, "diagnostic")["removal"] = "on_success"


def _diagnostic_allows_privileged(ctx):
    _run_profile(ctx, "diagnostic")["other_options"].append(["--privileged"])


def _worker_profile_without_review(ctx):
    worker = _run_profile(ctx, "worker")
    diagnostic = _run_profile(ctx, "diagnostic")
    worker.update({"status": "normative", "docker_run_options": copy.deepcopy(diagnostic["docker_run_options"]),
                   "other_options": copy.deepcopy(diagnostic["other_options"]), "removal": "always"})


def _allowlist_entry_without_run_profile(ctx):
    ctx["codeowners"] = True
    ctx["files"][P_ALLOWLIST]["entries"].append(
        {"repository": "ghcr.io/alexindacomp/sprut-worker", "digest": "sha256:" + "1" * 64, "purpose": "worker",
         "platform": "linux/amd64", "min_client_version": "0.3.0"})


# --- rework round 1 (CR-70 ... CR-81) ---

def _download_limits_removed(ctx):
    ctx["files"]["schemas/plan-step-kinds.schema.json"]["$defs"]["step_kind"]["properties"].pop("download")
    _step_kind(ctx, "import_distro").pop("download")


def _download_cap_raised(ctx):
    _step_kind(ctx, "apt_add_docker_repo")["download"]["max_bytes"] = 1073741824


def _apt_update_default_error_mode(ctx):
    for platform in ("windows", "linux"):
        for op in _step_kind(ctx, "apt_add_docker_repo")["commands"][platform]:
            if op.get("argv", [])[:2] == ["/usr/bin/apt-get", "update"]:
                op["argv"] = ["/usr/bin/apt-get", "update"]


def _nvidia_without_drain(ctx):
    _step_kind(ctx, "install_nvidia_toolkit")["preconditions"] = ["ubuntu_supported", "source_verified"]


def _nvidia_linux_without_acknowledgement(ctx):
    _step_kind(ctx, "install_nvidia_toolkit")["platforms"]["linux"].pop("acknowledgement")


def _nvidia_linux_without_its_title(ctx):
    _step_kind(ctx, "install_nvidia_toolkit")["platforms"]["linux"].pop("title")


def _engine_stop_without_drain(ctx):
    for platform in ("windows", "linux"):
        _step_kind(ctx, "start_engine")["commands"][platform].insert(
            0, {"argv": ["/usr/bin/systemctl", "stop", "docker.service"]})


def _wsl_title_without_disclosure(ctx):
    _step_kind(ctx, "update_wsl")["title"] = {"ru": "Обновить WSL", "en": "Update WSL"}


def _resize_title_without_disclosure(ctx):
    _step_kind(ctx, "resize_distro_disk")["title"]["en"] = "Change the maximum disk size of the Sprut distribution"


def _helper_refusal_without_class(ctx):
    for kind in ("enable_wsl_features", "enable_vm_platform", "install_wsl", "update_wsl"):
        classes = ctx["files"][P_STEP_FAILURES]["step_kinds"][kind]["windows"]
        classes.remove("plan_refused")


def _probe_catch_all_dropped(ctx):
    for state in ctx["files"][P_STEP_FAILURES]["states"].values():
        for classes in state.values():
            classes.remove("probe_failed")


def _probe_failure_as_step_failed(ctx):
    _failure_class(ctx, "probe_failed")["reason_code"] = "STEP_FAILED"


def _plan_ack_dropped_for_engine_restart(ctx):
    _plan_vector(ctx, "linux-nvidia-toolkit")["derived"]["required_acknowledgements"] = []


def _apt_update_with_leading_option(ctx):
    for op in _step_kind(ctx, "install_nvidia_toolkit")["commands"]["linux"]:
        if "update" in op.get("argv", []):
            op["argv"] = ["/usr/bin/apt-get", "-q", "update"]


def _engine_try_restart_without_drain(ctx):
    for platform in ("windows", "linux"):
        _step_kind(ctx, "start_engine")["commands"][platform].insert(
            0, {"argv": ["/usr/bin/systemctl", "try-restart", "docker"]})


def _engine_socket_killed_without_drain(ctx):
    _step_kind(ctx, "install_docker_engine")["commands"]["linux"].append(
        {"argv": ["/usr/bin/systemctl", "kill", "docker.socket"]})


def _engine_disabled_now_without_drain(ctx):
    _step_kind(ctx, "start_engine")["commands"]["linux"].append(
        {"argv": ["/usr/bin/systemctl", "disable", "--now", "docker.service"]})


def _storage_failure_as_insufficient_disk(ctx):
    _failure_class(ctx, "local_storage_failed")["reason_code"] = "INSUFFICIENT_DISK"


def _storage_failure_to_failed(ctx):
    _failure_class(ctx, "local_storage_failed")["to"] = "FAILED"


def _storage_class_dropped(ctx):
    ctx["files"][P_STEP_FAILURES]["step_kinds"]["import_distro"]["windows"] = \
        ["source_unavailable", "wsl_command_failed", "command_failed"]


def _docker_desktop_as_remote_context(ctx):
    _failure_class(ctx, "engine_docker_desktop")["reason_code"] = "ENGINE_REMOTE_CONTEXT"


def _docker_desktop_not_rechecked(ctx):
    for classes in ctx["files"][P_STEP_FAILURES]["states"]["SMOKE_TEST"].values():
        classes.remove("engine_docker_desktop")


def _docker_desktop_by_operating_system_only(ctx):
    global is_docker_desktop
    is_docker_desktop = lambda engine: engine.get("operating_system") == DOCKER_DESKTOP  # noqa: E731


def _allowlist_diagnostic_without_limits(ctx):
    ctx["codeowners"] = True
    ctx["files"][P_ALLOWLIST]["entries"].append(
        {"repository": "ghcr.io/alexindacomp/sprut-diagnostic", "digest": "sha256:" + "2" * 64, "purpose": "diagnostic",
         "platform": "linux/amd64", "min_client_version": "0.3.0"})


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
    # sprut-contracts 0.2.0: issue #2 (CR-12, parser/validator semantics)
    ("step_is_privileged_plan_step no longer declares consented_plan_id", _reads_without_consent, "machines"),
    ("schema type integer accepts 1.0", _integer_accepts_fraction, "all"),
    ("event schema_version without type integer (SEC-m6)", _event_schema_version_untyped, "all"),
    ("object_hash of an array reported as INVALID_KIND", _object_hash_array_as_kind, "all"),
    # issue #3: step kinds, InstallationPlan
    ("step kinds: enable_wsl_features not privileged", _uac_step_unprivileged, "all"),
    ("step kinds: import_distro privileged", _import_distro_privileged, "all"),
    ("step kinds: Linux apt step without sudo", _linux_apt_unprivileged, "all"),
    ("step kinds: vocabulary extended with run_script", _open_vocabulary, "all"),
    ("step kinds: image allowed on install_docker_engine", _image_on_install_step, "all"),
    ("step kinds: rootfs source optional", _rootfs_source_optional, "all"),
    ("step kinds: source prefix without path", _prefix_without_path, "all"),
    ("step kinds: docker group without forced re-login", _relogin_may, "all"),
    ("step kinds: elevated step renamed", _elevated_renamed, "all"),
    ("step kinds: title template changed", _title_template_changed, "all"),
    ("step kinds: title with a free placeholder", _free_placeholder, "all"),
    ("plan schema: unknown top-level members allowed", _plan_allows_unknown_members, "all"),
    ("plan schema: hash optional", _plan_hash_optional, "all"),
    ("plan schema: unknown step members allowed", _plan_step_allows_unknown_members, "all"),
    ("plan vector: consented_image_references = all images", _consented_digests_all_images, "all"),
    ("plan vector: pulls not counted as actions", _action_count_without_pulls, "all"),
    ("plan vector: document changed, stored hash kept", _plan_document_tampered, "all"),
    # issue #3: images, allowlist, ownership, WSL resources, reason codes
    ("allowlist schema: digest copy drifts (uppercase hex)", _allowlist_digest_drift, "all"),
    ("bundled allowlist with a tag instead of a digest", _bundled_allowlist_tag, "all"),
    ("ownership: profile label optional", _profile_label_optional, "all"),
    ("ownership: profile not checked", _profile_not_checked, "all"),
    ("ownership: label namespace changed", _namespace_changed, "all"),
    ("wsl resources: unmanaged .wslconfig keys allowed", _wslconfig_any_key, "all"),
    ("reason codes: FOREIGN_RESOURCE removed", _drop_foreign_resource, "all"),
    # rework round 1: SEC-B1 engine endpoint
    _drop_check("bootstrap", "ENGINE_CHECK", "IMAGE_PULL", "engine_endpoint_local"),
    _drop_check("bootstrap", "ENGINE_CHECK", "SMOKE_TEST", "engine_endpoint_local"),
    ("engine: TCP listener leads to FAILED instead of ACTION_REQUIRED", _engine_reject_to_failed, "machines"),
    ("engine: tcp:// on loopback accepted", _swap_predicate("engine_endpoint_local", _engine_accepts_loopback_tcp), "all"),
    # SEC-m3 allowlist pairs, CR-21 versions
    ("allowlist guard compares digests only", _swap_predicate("image_allowlisted", _allowlist_by_digest), "all"),
    ("consented-plan guard compares digests only (CR-30)", _swap_predicate("image_in_consented_plan", _consented_by_digest), "all"),
    ("allowlist: pre-release client equals its release", _prerelease_equals_release, "all"),
    # CR-20 terms before consent, SEC-C1/C2 acknowledgements
    ("consent effect without terms_accepted", _drop_consent_effect_check, "machines"),
    ("terms_accepted ignores acknowledgements", _swap_predicate("terms_accepted", _terms_without_acknowledgements), "all"),
    ("step kinds: docker group without acknowledgement", _group_without_acknowledgement, "all"),
    ("plan: docker_access rule off", _switch_off("docker_access"), "all"),
    ("plan: unregister without immediate import accepted", _switch_off("unregister_pairing"), "all"),
    # CR04 restart, CR03 file binding
    ("step kinds: restart_wsl without confirmation precondition", _restart_without_precondition, "all"),
    ("precondition: WSL restart without drain", _swap_precondition("wsl_restart_confirmed", _restart_without_drain), "all"),
    ("precondition: rejection to a state INSTALLING cannot reach", _precondition_to_non_edge, "all"),
    ("plan: replaced .wslconfig values not checked", _switch_off("wslconfig_replaced"), "all"),
    ("wsl resources: mirrored networking allowed before S2", _mirrored_allowed, "all"),
    # SEC-A1, SEC-m1, SEC-m2, CR-26
    ("step kinds: install_wsl without the unverified-download title", _unverified_title_removed, "all"),
    ("step kinds: shell in a command template", _shell_command, "all"),
    ("step kinds: unknown placeholder in a command", _free_command_placeholder, "all"),
    ("step kinds: elevated step runs a distro program", _elevated_in_distro_program, "all"),
    ("step kinds: rootfs without licence requirement", _rootfs_without_licence, "all"),
    ("plan: licence requirement not checked", _switch_off("licence_required"), "all"),
    ("step kinds: prefix without trailing slash, schema pattern removed", _prefix_shape, "all"),
    # SEC-m5
    ("ownership: adoption rule removed", _drop_adoption_rule, "all"),
    # final round
    ("allowlist entry without CODEOWNERS (SEC-N3)", _allowlist_entry_without_codeowners, "all"),
    ("apt key used without verify_source as root (SEC-N1)", _verify_source_dropped, "all"),
    ("apt-get started through /usr/bin/env (SEC-N4)", _env_launcher, "all"),
    ("unrepresentable .wslconfig value accepted as replaced (CR-29)", _wsl_display_too_wide, "all"),
    ("ownership: adoption without journal", _switch_off("adoption_needs_journal"), "all"),
    # sprut-contracts 0.3.0. CR-45: reason codes, WSL_POLICY_BLOCKED state, step failures
    ("reason codes: STEP_FAILED removed", _drop_reason_code("STEP_FAILED"), "all"),
    ("reason codes: WSL_COMMAND_FAILED removed", _drop_reason_code("WSL_COMMAND_FAILED"), "all"),
    ("reason codes: ELEVATION_UNAVAILABLE removed", _drop_reason_code("ELEVATION_UNAVAILABLE"), "all"),
    _add_edge("wsl_availability", "WSL_POLICY_BLOCKED", "WSL2_READY"),
    ("wsl_availability: WSL_POLICY_BLOCKED not terminal", _policy_blocked_not_terminal, "machines"),
    ("wsl_availability: WSL_POLICY_BLOCKED without its reason code", _policy_blocked_without_reason, "machines"),
    ("wsl_availability: WSL_POLICY_BLOCKED state removed", _policy_blocked_removed, "machines"),
    ("step failures: a command that could not run reported as WSL_DISTRO_BROKEN", _wsl_failure_as_broken_distro, "all"),
    ("step failures: missing helper leads to FAILED instead of ACTION_REQUIRED", _elevation_unavailable_to_failed, "all"),
    ("step failures: apt-get install failure reported as SOURCE_UNAVAILABLE", _apt_install_as_source_failure, "all"),
    ("step failures: elevated step reported as STEP_FAILED", _elevated_step_as_step_failed, "all"),
    ("step failures: probe command failure has no class", _probe_failure_class_dropped, "all"),
    ("step failures: engine failure in SMOKE_TEST has no class", _smoke_engine_failure_dropped, "all"),
    ("step failures: vector expects ENGINE_DAEMON_STOPPED for start_engine", _step_failure_vector_changed, "all"),
    ("step failures: a step kind without failure classes", _failure_kind_missing, "all"),
    # SEC-1: replacement source verified before unregister_distro
    ("step kinds: unregister_distro without replacement_source_verified", _unregister_without_replacement, "all"),
    ("precondition: replacement source never checked", _swap_precondition("replacement_source_verified", _replacement_never_checked), "all"),
    ("precondition: replacement source present but its hash not compared",
     _swap_precondition("replacement_source_verified", _replacement_by_presence_only), "all"),
    ("precondition: missing replacement leads to PROBING instead of FAILED", _replacement_reject_to_probing, "all"),
    # SEC-5: install_wsl / update_wsl confirmed like restart_wsl
    ("step kinds: update_wsl without the restart confirmation", _wsl_update_without_confirmation, "all"),
    ("step kinds: install_wsl without the restart confirmation", _wsl_install_without_confirmation, "all"),
    ("precondition: unreadable distribution list treated as empty",
     _swap_precondition("wsl_restart_confirmed", _unreadable_list_is_empty), "all"),
    ("precondition: install/update never asks when distributions are registered",
     _swap_precondition("wsl_restart_confirmed", _update_always_without_dialog), "all"),
    # CR-49: terminate before resize, drain before the Sprut distribution is stopped
    ("step kinds: resize without wsl --terminate", _resize_without_terminate, "all"),
    ("step kinds: resize_distro_disk without drain", _resize_without_drain, "all"),
    ("step kinds: configure_distro without drain", _configure_without_drain, "all"),
    ("precondition: drain never checked", _swap_precondition("sprut_drained", _drain_never_checked), "all"),
    # CR-58 / SEC-11: redirects
    ("step kinds: redirect host with a scheme, schema pattern removed", _redirect_host_with_scheme, "all"),
    ("step kinds: wildcard redirect host, schema pattern removed", _redirect_host_wildcard, "all"),
    ("step kinds: unreviewed redirect host added", _redirect_host_added, "all"),
    ("step kinds: redirect_hosts optional and absent", _redirect_hosts_optional, "all"),
    ("download: redirect hosts not checked", _switch_off("redirect_host_check"), "all"),
    ("download: only the final hop restricted (CR-77)", _switch_off("redirect_every_hop"), "all"),
    ("download: requested URL not in the strict form (CR-77)", _switch_off("requested_url_strict"), "all"),
    ("download: no size cap (CR-77)", _switch_off("download_size_cap"), "all"),
    ("step kinds: download limits removed (CR-77)", _download_limits_removed, "all"),
    ("step kinds: download cap raised without review (CR-77)", _download_cap_raised, "all"),
    ("download: http hop accepted", _switch_off("redirect_https_hops"), "all"),
    ("download: prefix check on the final URL (0.2.0 rule)", _switch_off("redirect_prefix_on_requested_only"), "all"),
    # SEC-12: both hashes for in-distribution copies
    ("precondition: client hash not required for in-distribution copies",
     _swap_precondition("source_verified", _client_hash_not_required), "all"),
    ("precondition: distribution hash ignored when the client hash matches",
     _swap_precondition("source_verified", _client_hash_only), "all"),
    # SEC-15: run profiles
    ("run profiles: diagnostic without --network none", _diagnostic_drop_group("--network"), "all"),
    ("run profiles: diagnostic without --cap-drop ALL", _diagnostic_drop_group("--cap-drop"), "all"),
    ("run profiles: diagnostic without --pull=never", _diagnostic_drop_group("--pull=never"), "all"),
    ("run profiles: diagnostic without --read-only", _diagnostic_drop_group("--read-only"), "all"),
    ("run profiles: diagnostic without no-new-privileges", _diagnostic_drop_group("--security-opt"), "all"),
    ("run profiles: diagnostic without --pids-limit", _diagnostic_drop_group("--pids-limit"), "all"),
    ("run profiles: diagnostic without --memory", _diagnostic_drop_group("--memory"), "all"),
    ("run profiles: diagnostic container not always removed", _diagnostic_not_removed, "all"),
    ("run profiles: diagnostic may run privileged", _diagnostic_allows_privileged, "all"),
    ("run profiles: option set not closed", _switch_off("run_profile_closed"), "all"),
    ("run profiles: worker profile defined without review", _worker_profile_without_review, "all"),
    ("allowlist: worker image without a defined run profile", _allowlist_entry_without_run_profile, "all"),
    ("allowlist: diagnostic image before its limits are fixed", _allowlist_diagnostic_without_limits, "all"),
    # rework round 1. CR-70: mechanical classification
    ("classification: exit status outside 0-255 through wsl.exe treated as a program result", _switch_off("wsl_exit_range"), "all"),
    ("classification: a probe that gave no answer counted as evidence", _switch_off("probe_failure_is_not_evidence"), "all"),
    # CR-71: apt
    ("step kinds: apt-get update without Error-Mode=any", _apt_update_default_error_mode, "all"),
    # CR-72: engine restart
    ("step kinds: install_nvidia_toolkit without drain", _nvidia_without_drain, "all"),
    ("step kinds: install_nvidia_toolkit on Linux without the engine_restart acknowledgement", _nvidia_linux_without_acknowledgement, "all"),
    ("step kinds: install_nvidia_toolkit on Linux without its own title", _nvidia_linux_without_its_title, "all"),
    ("step kinds: systemctl stop docker.service added without drain", _engine_stop_without_drain, "all"),
    ("plan vector: engine_restart acknowledgement not derived", _plan_ack_dropped_for_engine_restart, "all"),
    # CR-73, CR-74: classes
    ("step failures: plan refused by the helper has no class", _helper_refusal_without_class, "all"),
    ("step failures: checks outside steps have no catch-all", _probe_catch_all_dropped, "all"),
    ("step failures: a failed check reported as STEP_FAILED", _probe_failure_as_step_failed, "all"),
    # LOCAL_STORAGE_FAILED, ENGINE_DOCKER_DESKTOP
    ("reason codes: LOCAL_STORAGE_FAILED removed", _drop_reason_code("LOCAL_STORAGE_FAILED"), "all"),
    ("reason codes: ENGINE_DOCKER_DESKTOP removed", _drop_reason_code("ENGINE_DOCKER_DESKTOP"), "all"),
    ("step failures: a storage failure reported as INSUFFICIENT_DISK", _storage_failure_as_insufficient_disk, "all"),
    ("step failures: a storage failure leads to FAILED instead of ACTION_REQUIRED", _storage_failure_to_failed, "all"),
    ("step failures: import_distro without the storage classes", _storage_class_dropped, "all"),
    ("step failures: Docker Desktop reported as ENGINE_REMOTE_CONTEXT", _docker_desktop_as_remote_context, "all"),
    ("step failures: Docker Desktop not re-checked before the container run", _docker_desktop_not_rechecked, "all"),
    ("classification: Docker Desktop recognised by OperatingSystem only", _docker_desktop_by_operating_system_only, "all"),
    # final round: CR-82, CR-83
    ("classification: Docker Desktop ignored when docker.service is inactive (CR-82)", _switch_off("docker_desktop_wins"), "all"),
    ("step kinds: apt-get -q update without Error-Mode=any (CR-83)", _apt_update_with_leading_option, "all"),
    ("step kinds: systemctl try-restart docker without drain (CR-83)", _engine_try_restart_without_drain, "all"),
    ("step kinds: systemctl kill docker.socket without drain (CR-83)", _engine_socket_killed_without_drain, "all"),
    ("step kinds: systemctl disable --now docker.service without drain (CR-83)", _engine_disabled_now_without_drain, "all"),
    # CR-76: run profile
    ("run profiles: an option group may repeat", _switch_off("run_profile_exactly_once"), "all"),
    ("run profiles: arguments after the image accepted", _switch_off("run_profile_nothing_after_image"), "all"),
    # CR-80: titles
    ("step kinds: update_wsl title without the stop disclosure", _wsl_title_without_disclosure, "all"),
    ("step kinds: resize title without the stop disclosure", _resize_title_without_disclosure, "all"),
]


_PREDICATES_DEFAULT = dict(PREDICATES)
_STEP_PRECONDITIONS_DEFAULT = dict(STEP_PRECONDITIONS)
_PRECONDITION_WSL_RESTART = _pc_wsl_restart_confirmed
_IS_DOCKER_DESKTOP_DEFAULT = is_docker_desktop
_SEMVER_DEFAULT = _semver


def self_test(base: dict) -> int:
    global SORT_KEY, _semver, is_docker_desktop
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
            SCHEMA_SEMANTICS.update(_SCHEMA_SEMANTICS_DEFAULT)
            RULE_SWITCHES.update(_RULE_SWITCHES_DEFAULT)
            PREDICATES.update(_PREDICATES_DEFAULT)
            STEP_PRECONDITIONS.update(_STEP_PRECONDITIONS_DEFAULT)
            _semver = _SEMVER_DEFAULT
            is_docker_desktop = _IS_DOCKER_DESKTOP_DEFAULT
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
