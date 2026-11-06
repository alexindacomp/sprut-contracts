# sprut-contracts

Shared contracts of Sprut: reason-code registry, CLI exit codes, state
machines, JSON Schemas, Protobuf messages and conformance test vectors.

This repository is the **single source of truth** for everything that the Java
Windows client (Sprut Desktop), the Go Linux client (`sprut` CLI) and the
coordinator must agree on (SPRUT-CLIENT-SPECIFICATION 4.2). There is no shared
executable core: each implementation reads these files or is checked against
them by conformance tests in its own CI.

## Layout

| Path | Content |
|---|---|
| `registry/reason-codes.json` | Reason codes: `code`, `description` {ru, en}, `next_action` {ru, en}, `retryable`, `cli_exit_code`, `platforms`, `spec_refs` (spec 8.3, 03-CONTRACTS 7) |
| `registry/exit-codes.json` | `sprut` CLI exit codes (spec 7.3), the ordered `resolution` rules that choose the exit code, and which reason codes map to them explicitly |
| `registry/state-machines.json` | State machines: `bootstrap` (CF17), `node_status` (CF42), `wsl_availability` (CW01), generic `task` (long operations). A transition not listed is forbidden. `bootstrap` also has machine-readable guards (`guard_context`, `guard_predicates`, `guards` with `on_reject`, `effects` with their own `checks`) for consent and accepted terms, plan staleness, privilege, local engine endpoint, image allowlist and image presence. `operation_kinds` maps every operation kind to its machine |
| `registry/plan-step-kinds.json` | Closed vocabulary of InstallationPlan step kinds: platforms, privilege per platform, Windows elevated-helper operation, acknowledgements, licence requirement, required/allowed members, flag rules, official source prefixes, execution preconditions, fixed command templates, title templates; supported Ubuntu releases |
| `registry/image-allowlist.json` | The bundled image allowlist (`kind: image_allowlist`); empty in 0.2.0, so every image is refused (fail closed) |
| `registry/ownership.json` | Ownership label namespace, labels, charset and rules for Sprut containers, volumes and networks |
| `schemas/*.schema.json` | JSON Schema (draft 2020-12): the registries above, `operation-event.schema.json` (event of spec 7.1 item 4 / 8.1), `installation-plan.schema.json`, `image-reference.schema.json` (ImageDigest, ImageReference), `wsl-resources.schema.json` and the vector file formats |
| `proto/sprut/v1/common.proto` | Protobuf package `sprut.v1`: `OperationEvent`. gRPC services follow at S1 |
| `buf.yaml` | buf lint/breaking configuration for `proto/` |
| `docs/canonical-json.md` | Canonical JSON (RFC 8785 / JCS, restricted), hash rule (CF03) and the JSON Schema number semantics both clients follow |
| `docs/installation-plan.md` | InstallationPlan format and rules (CF12, CF13), guard inputs derived from a plan, error categories |
| `docs/images-and-ownership.md` | ImageDigest / ImageReference, the bundled allowlist, ownership labels, FOREIGN_RESOURCE (CF20–CF23) |
| `docs/wsl-resources.md` | Managed `.wslconfig` keys and the Sprut distribution disk size, rules CR01–CR07 |
| `test-vectors/canonical-json/` | Canonicalization and `object_hash` vectors |
| `test-vectors/canonical-json-invalid/` | Inputs that must be rejected before hashing |
| `test-vectors/state-transitions/` | Allowed and rejected transitions and paths per machine |
| `test-vectors/guards/` | Guard evaluations: transition + context → allowed, or rejected with a reason code |
| `test-vectors/effects/` | Effect preconditions: consent is set only when every licence and acknowledgement was given |
| `test-vectors/step-preconditions/` | Plan step + facts observed before it runs → allowed, or rejected with a reason code and next state |
| `test-vectors/operation-events/` | `OperationEvent` instances with the expected producer and consumer verdicts |
| `test-vectors/exit-codes/` | Inputs (final state, reason code, interactivity) and the expected CLI exit code |
| `test-vectors/installation-plans/` | Valid plans with the derived guard inputs, and invalid plans with the expected error category |
| `test-vectors/image-allowlist/` | Allowlist documents, client version and the resulting `allowlist` guard input or error |
| `test-vectors/ownership/` | Inspected labels → owned or not; journal + inspect → adoptable or not; caller-supplied labels → accepted or refused |
| `test-vectors/wsl-resources/` | WSL resource values → valid or not |
| `tools/validate.py` | Validator, Python 3 standard library only |
| `VERSION` | Semantic version of this contract set |

All registries are JSON so that Java and Go can read them without extra
libraries. Text is UTF-8 without BOM, LF line endings (`.gitattributes`).

## Validate

```sh
python3 tools/validate.py              # validate the repository
python3 tools/validate.py --self-test  # prove the checks reject known-bad changes
```

`validate.py` checks the registries against their schemas and against
cross-file rules: codes are unique, exit codes exist and map consistently,
`WSL_*` codes are Windows-only, and every code listed in spec 8.3 and
03-CONTRACTS 7 is present. It checks state-machine integrity (declared states,
initial/terminal, reachability, no dead ends) and the structural invariants
taken from the spec. For bootstrap:

- READY only after SMOKE_TEST;
- INSTALLING and IMAGE_PULL only after a fresh WAITING_FOR_CONSENT, checked on
  the graph without consent-requiring guards;
- every state resumes through PROBING, and PROBING clears consent;
- the required guards are present.

For node status: jobs only from READY, nothing but OFFLINE after DRAINING. For
WSL: a ready WSL2 is never changed. The `reads` of every guard predicate equal
the inputs of its reference implementation. The step-kind registry is the
agreed closed vocabulary with the agreed privilege per platform (the four
Windows UAC kinds are exactly the elevated-helper operations), sources required
for downloads, and the re-login / WSL-restart flags; copied schema definitions
are identical; the ownership registry keeps the namespace and the required
`managed` and `profile` labels. It also recomputes every test vector,
including guard evaluations with the reference predicates, InstallationPlan
validation and derived guard inputs, allowlist, ownership and WSL resources.

`--self-test` applies a list of known-bad changes in memory and fails if any is
not detected. Examples: `PLAN_READY->READY`, `ACTION_REQUIRED->INSTALLING`, an
unguarded `ENGINE_CHECK->IMAGE_PULL`, PROBING no longer clearing consent, a
tampered canonical vector, code-point key order, an unprivileged UAC step, an
extra step kind, an optional rootfs source, unknown plan members, a plan
changed without a new hash, a schema `integer` accepting `1.0`. CI runs both on every push and
pull request (`.github/workflows/validate.yml`, runner pinned to
`ubuntu-24.04`, which ships Python 3.12; no packages are installed).

## Consuming the contracts

Clients add this repository as a git submodule pinned to a release tag:

```sh
git submodule add https://github.com/alexindacomp/sprut-contracts.git contracts
git -C contracts checkout v0.2.0
git add contracts && git commit -m "Pin sprut-contracts v0.2.0"
```

Then, in each implementation:

- load or generate reason codes, exit codes and state machines from
  `registry/*.json` (generate constants at build time or embed the files);
  never hard-code a code, state or exit code that is not in the registry;
- run the conformance suite over `test-vectors/**` in CI: canonical JSON and
  hash, every state-transition case and sequence, every guard case, every
  exit-code case, every OperationEvent case, every InstallationPlan vector
  (verdict, error category and derived guard inputs), allowlist, ownership and
  WSL resources case;
- embed `registry/image-allowlist.json` at build time as the only allowlist
  (`docs/images-and-ownership.md`), and read plan step kinds and ownership
  labels from `registry/plan-step-kinds.json` and `registry/ownership.json`;
- validate against `schemas/` with the number semantics of
  `docs/canonical-json.md` 3.3 (a stock draft 2020-12 validator differs);
- implement the bootstrap guard predicates exactly as defined in
  `registry/state-machines.json` (reference: `tools/validate.py`), and fail
  closed when an input is missing;
- generate Protobuf code from `proto/` inside the consuming repository (see
  below); the Java package is fixed in the proto files
  (`io.github.alexindacomp.sprut.contracts.v1`);
- report the contracts version (`VERSION`, or the submodule tag) in
  `sprut --version` and in diagnostics (spec 7.5).

### This repository is not a Go module

There is deliberately no `go.mod` here, and the proto files set no
`go_package`. Reasons:

- The Go client embeds the registries with `//go:embed` straight from its
  `contracts/` submodule. `go:embed` cannot reach into a directory that contains
  its own `go.mod`, and patterns cannot use `..`. The embedding Go file must
  therefore sit in a package whose directory contains `contracts/`, for example
  the module root.
- Generated Go code belongs to the consuming module, so there is no second
  module to version and publish.

Each Go consumer generates code into its own module with buf managed mode, for
example in its `buf.gen.yaml`:

```yaml
version: v2
inputs:
  - directory: contracts/proto
managed:
  enabled: true
  override:
    - file_option: go_package_prefix
      value: github.com/alexindacomp/sprut-client-linux/internal/gen
plugins:
  - remote: buf.build/protocolbuffers/go
    out: internal/gen
    opt: paths=source_relative
```

(or `protoc --go_opt=M<file>=<import path>`). Java consumers generate with
their build tool from `contracts/proto`.

### Wire conventions

- Reason codes and state names are plain strings (UPPER_SNAKE_CASE) on the wire,
  in JSON and in Protobuf. They are not Protobuf enums, so that a new code added
  here can pass through an older reader unchanged.
- Optional JSON members are omitted when absent; `null` is not used.
- `ts` values are RFC 3339 UTC with the `Z` suffix, seconds 00–59.
- Every schema `pattern` matches the whole string (`^...$`); see
  `docs/canonical-json.md` section 3.2 for Java and Python matching pitfalls.
- Numbers in schemas (`docs/canonical-json.md` 3.3): `"type": "integer"`
  rejects `1.0`, and every numeric `const`/`enum` carries `"type": "integer"`
  (so `schema_version: 1.0` is rejected); `object_hash` of a non-object is
  `INVALID_JSON`.

### Consent and actions (bootstrap)

An **action** is any step that downloads, installs, elevates or changes the
host, including the worker image pull and any WSL or engine change. Read-only
verification is not an action. Every action runs only under consent to the
exact `plan_id`:

- A plan with zero actions (engine ready, image present by digest) is the only
  one that skips consent: `PLAN_READY → ENGINE_CHECK → SMOKE_TEST`.
- Entering PROBING clears consent. A process or computer restart in any
  unfinished state, including PLAN_READY and WAITING_FOR_CONSENT, resumes in
  PROBING; the journal is never trusted to continue.
- The plan is an InstallationPlan document (`docs/installation-plan.md`):
  every element of `steps[]` is an action (`plan_action_count` = number of
  steps) and an image pull is an `image_pull` step. The consent screen and
  `sprut setup plan` show every typed member of every step.
- Licence terms and the acknowledgements for the docker group and for removing
  the Sprut distribution are accepted separately and never on the user's
  behalf: consent (`set_consented_plan_id`) is set only when all of them were
  given (`terms_accepted`, `test-vectors/effects/`). In the CLI each needs its
  own flag (`--accept-license <id>`, `--accept-docker-group`,
  `--accept-distro-removal`); `--yes` replaces none of them.
- Right before a step runs, its execution preconditions are checked against
  fresh facts (`test-vectors/step-preconditions/`): for example `restart_wsl`
  needs a separate confirmation after the drain (CR04), `write_wslconfig` a
  `.wslconfig` unchanged since the plan.
- Before INSTALLING, the plan is rebuilt from the current host and its
  `plan_id` must equal the consented one (`PLAN_STALE` otherwise). Only steps of
  that plan carrying the privilege flag may be elevated. IMAGE_PULL requires the
  digest to be both allowlisted and listed in the consented plan. These rules
  are the `guards` of the bootstrap machine, tested by `test-vectors/guards/`.
- User consent sets `consented_plan_id` to the `object_hash` recomputed from the
  exact plan displayed to the user (effect `set_consented_plan_id`).
- Every step executed in INSTALLING, privileged or not, must be a step of the
  plan document whose `object_hash` equals `consented_plan_id`. For an elevation
  request, `in_consented_plan` and `privileged` are computed by looking up
  `step.id` in that document; they are never supplied by the caller (UI, helper,
  arguments).
- The smoke test and every worker run use an explicit no-pull mode (for example
  `--pull=never`), so no implicit download can bypass the IMAGE_PULL guard.
  Before SMOKE_TEST the image must be present locally by digest
  (`image_present_by_digest`); if it is missing, the result is PLAN_STALE and the
  operation returns to PROBING, so that the new plan lists the pull as an action.
- After a guard rejects a transition, its `on_reject` entry for the reason code
  says what happens next: move along an existing transition (`to`) or stay in
  the waiting state (`stay`), and which event type to emit. The agreed mapping
  (orchestrator decision 2026-11-06, conservative) is:

  | Rejected transition | Reason code | Then | Event |
  |---|---|---|---|
  | PLAN_READY → ENGINE_CHECK | CONSENT_REQUIRED | WAITING_FOR_CONSENT | state |
  | WAITING_FOR_CONSENT → INSTALLING | CONSENT_REQUIRED | stay (CLI without TTY exits 4) | state |
  | WAITING_FOR_CONSENT → INSTALLING | PLAN_STALE | PROBING | state |
  | INSTALLING → WAITING_FOR_PRIVILEGE | CONSENT_REQUIRED, PLAN_STALE | FAILED | error |
  | WAITING_FOR_PRIVILEGE → INSTALLING | CONSENT_REQUIRED, PLAN_STALE | FAILED | error |
  | WAITING_FOR_PRIVILEGE → INSTALLING | PRIVILEGE_REQUIRED | stay (an explicit decline uses → CANCELLED) | state |
  | ENGINE_CHECK → IMAGE_PULL | CONSENT_REQUIRED | PROBING | state |
  | ENGINE_CHECK → IMAGE_PULL | PLAN_STALE | FAILED | error |
  | ENGINE_CHECK / IMAGE_PULL → SMOKE_TEST | PLAN_STALE (image absent) | PROBING | state |
  | ENGINE_CHECK → IMAGE_PULL / SMOKE_TEST | ENGINE_REMOTE_CONTEXT, ENGINE_TCP_EXPOSED | ACTION_REQUIRED | error |
  | any guard | IMAGE_NOT_ALLOWED | FAILED | error |
- In the CLI, `--yes` is valid only together with `--plan-id <hash>` equal to
  the plan shown, `sprut setup apply --plan-id <hash> --yes`. Consent is for
  that exact plan, and `--yes` without `--plan-id` is refused.

### Operation kinds and the task machine

`OperationEvent.operation` and the exit-resolution input `operation` are
**operation kinds** from `operation_kinds` in `registry/state-machines.json`.
Each kind maps to the machine whose states it uses:

| Kind | Machine |
|---|---|
| `bootstrap` | `bootstrap` |
| `node_status` | `node_status` |
| `model_pull`, `model_import`, `model_load`, `image_update`, `diag_export`, `train_run`, `mode_switch` | `task` |

The generic `task` machine has RUNNING → SUCCEEDED / FAILED / CANCELLED and no
restart edge. After a crash the task is not continued; resuming (for example a
model download) is a new operation with a new `operation_id`, and it re-verifies
the actual state. A failed node-to-single switch is a `mode_switch` task ending
FAILED with a reason code (for example DRAIN_TIMEOUT) while `node_status` stays
DRAINING (CF43, CR-14).

### OperationEvent: producer conformance vs consumer behaviour

There is one rule, stated in `schemas/operation-event.schema.json` and tested by
`test-vectors/operation-events/events.json`:

- **Producers** (the Java and Go cores) emit events that match the schema
  exactly, with no other members. `reason_code` must be registered.
  `operation` is required and must be a registered operation kind, and `state`
  must be a state of its machine. `message` and `progress.step` are
  client-authored text, never raw subprocess output. Limits:
  - at most 1024 and 128 Unicode code points (Java: count with
    `String.codePointCount`, not `length()`, which counts UTF-16 units);
  - no control characters (U+0000–U+001F, U+007F–U+009F);
  - no zero-width characters or BOM (U+200B–U+200F, U+FEFF);
  - no line or paragraph separators (U+2028, U+2029);
  - no bidi embedding, override or isolate controls (U+202A–U+202E,
    U+2066–U+2069).
- **Consumers** (GUI, scripts reading `sprut --json`, other tools) first drop
  members they do not know, at the top level and inside `progress`, then
  validate against the schema. They accept well-formed reason codes,
  operations and states that are missing from their copy of the registries
  (they come from newer contracts) and treat an unknown reason code as a
  generic error.
- Both reject everything else: wrong `schema_version` or `type`, `null`
  members, a missing `operation`, non-UTC `ts`,
  `progress.current > progress.total`, a trailing newline in a patterned
  member, and so on. A rejected line is reported as a diagnostic (stderr or
  log), never silently dropped.
- With `--json`, stdout carries only events (or the single result object of a
  short command). Child processes never inherit the CLI's stdout; their output
  goes to the technical log.
- Consumers never derive readiness or consent from the event stream alone. The
  BootstrapJournal and a fresh probe are authoritative; events are progress
  reports.
- Any member that changes a security or consent decision requires a new
  `schema_version`, never a minor addition.

### CLI exit codes

A reason code's `cli_exit_code` is not by itself the exit code of a command.
The exit code is chosen by the ordered `resolution.rules` in
`registry/exit-codes.json`; the first match wins:

1. usage error → 2;
2. SIGINT → 130;
3. the event stream ended without a result/error event and without a terminal or
   waiting state (for example the core crashed) → 1;
4. `succeeded` → 0. It means the command reached the outcome it was asked for,
   for example `setup plan` showing the plan, which then waits for consent. It
   is false when the operation stops in a waiting state the command was meant
   to leave, for example `setup apply` in WAITING_FOR_CONSENT. `succeeded` is
   valid only without a final state or with a state listed in
   `resolution.succeeded_final_states`, never with FAILED or CANCELLED;
5. final (machine of the operation kind, state), always as a pair. `final_state`
   is the operation's authoritative state at command end according to the
   journal or core, not the last event in the stream:
   - bootstrap or node_status READY → 0;
   - bootstrap ACTION_REQUIRED → 3;
   - bootstrap WAITING_FOR_CONSENT or WAITING_FOR_PRIVILEGE without a TTY or
     with `--no-input` → 4. In WAITING_FOR_CONSENT the host is unchanged; in
     WAITING_FOR_PRIVILEGE earlier plan steps may already have changed it;
   - bootstrap REBOOT_REQUIRED → 5;
   - bootstrap CANCELLED → 130;
   - task SUCCEEDED → 0, task CANCELLED → 130 (task FAILED goes to step 6);
6. otherwise `cli_exit_code` of the reason code (6, 7, 8, …), and 1 for any
   other failure or an unregistered code.

`test-vectors/exit-codes/resolution.json` fixes the expected results.
Cancellation has no reason code; it is expressed by the state CANCELLED and
exit code 130.

## Versioning

- **`schema_version`** — the major version of a data format; every structure
  carries it (CF03), currently `1`. A reader rejects an unknown major version.
  Within one `schema_version` only backward-compatible additions are allowed
  (new optional members, new reason codes, new machines); readers ignore unknown
  members. Removing or renaming a member, code, state or transition, or changing
  its meaning, requires a new `schema_version`. So does any new or changed
  member, state, transition or guard that alters a security or consent decision:
  it is never shipped as a minor addition that older readers would ignore.
- **Releases** are git tags `vMAJOR.MINOR.PATCH` matching `VERSION`:
  - PATCH: wording, descriptions, documentation, new test vectors for existing
    rules;
  - MINOR: backward-compatible additions (new reason code, state machine,
    optional field, Protobuf message);
  - MAJOR: anything incompatible, including any `schema_version` bump and any
    change to CLI exit codes once they are fixed (spec 7.3).
- Reason codes and Protobuf field numbers are never reused after removal.

## Rule: contracts first

A new or changed **reason code, state, transition, event field, CLI JSON field,
exit code or Protobuf message is added here first**, with test vectors and a
passing `tools/validate.py`, and only then implemented in the Java client, the
Go client and the coordinator. Each client mirrors the change in the same
release train so that the same operation yields the same states, reason codes
and result shape on both platforms.

## Status

`0.2.0` — contract prerequisites for C1 (see `CHANGELOG.md`): InstallationPlan
with the closed step-kind vocabulary, preconditions and command templates,
ImageDigest / ImageReference, the bundled image allowlist, ownership labels,
local engine endpoint, WSL resources, FOREIGN_RESOURCE, PLAN_INVALID and
ENGINE_TCP_EXPOSED, and the parser/validator rules of issue #2. Exit codes keep
status `proposal` until fixed at S-1.

## Requirements before the first non-empty allowlist

See `SECURITY.md` for the release checklist; `tools/validate.py` fails on a
non-empty allowlist while `CODEOWNERS` is missing.

The allowlist decides which code runs on users' machines. Before any entry is
added to `registry/image-allowlist.json` (SEC-m4), the repository owner sets up:
CODEOWNERS for `registry/`, `schemas/`, `proto/`, `tools/` and `.github/`;
branch protection on `master` with the `validate` check required; signed
release tags. Clients pin only signed tags.

## Planned

- **C1: BootstrapJournal and diagnostics contract.** Journal record format
  (`kind`, `schema_version`, hashed with `object_hash`), the rule that
  journal content is never used to continue execution without a probe, and the
  diagnostic archive manifest without secrets (CF18, CF81, CF82). Deferred
  from SEC-m10.
- **Signed, updatable image allowlist** (today only the bundled one).
- **ClientProfile contract**, including the profile id format (the ownership
  label already restricts it to `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`).
- **Export/backup of the Sprut distribution** before `unregister_distro`.
- **Signed manifest for download digests** (today they are constants of the
  client build).
- `networkingMode=mirrored` for node mode, after S2 decides Q14.
- `buf lint` / `buf breaking` in CI together with the first gRPC services (S1).
