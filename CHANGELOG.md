# Changelog

## 0.2.0 — contract prerequisites for C1

Issues #3 and #2, plus review round 1 (CR-20…CR-27, SEC-A1…SEC-D1,
SEC-m1…SEC-m7). Everything is new or added; `schema_version` stays 1. Items the
Java (and later Go) client must copy are marked **Mirror**.

### Added

- **InstallationPlan** (`docs/installation-plan.md`,
  `schemas/installation-plan.schema.json`): `kind: installation_plan`,
  `platform`, `current_state` / `target_state`, `docker_access` (Linux only),
  `steps[]`, `images[]` (ImageReference), `licences[]` `{id, url, sha256}`,
  `disk_estimate_bytes`, required `hash` (= `plan_id`). Unknown members are
  rejected; the content is deterministic (no timestamps or operation ids).
  **Mirror** (Java `InstallationPlan`, Go core):
  - every step is an action, `plan_action_count` = number of steps;
  - `consented_image_references` = ImageReferences of the `image_pull` steps;
  - step members `id`, `kind`, `title {ru,en}`, `privileged`,
    `requires_reboot`, `requires_relogin`, `requires_wsl_restart`,
    `estimated_bytes` (required); `image`, `source {url, sha256}`,
    `wslconfig`, `wslconfig_file {sha256|absent, replaced}`,
    `distro_disk_size`, `distro {name, base_path, vhdx_bytes}`,
    `target_user {name, uid}` per kind; optional `licence_ids`;
  - images are ImageReference strings (`repo@sha256:...`), not bare digests;
  - the rules and error categories of `docs/installation-plan.md` section 7,
    checked against `test-vectors/installation-plans/` (66 vectors), including
    `derived` (`plan_id`, `plan_action_count`, `consented_image_references`,
    `privileged_step_ids`, `windows_elevated_steps`, `required_licence_ids`,
    `required_acknowledgements`);
  - the consent screen and `sprut setup plan` show every typed member (SEC-D1).
- **Closed step-kind vocabulary** `registry/plan-step-kinds.json`: Windows
  `enable_wsl_features`, `enable_vm_platform`, `install_wsl`, `update_wsl`,
  `unregister_distro`, `import_distro`, `configure_distro`,
  `write_wslconfig`, `resize_distro_disk`, `restart_wsl`; both platforms
  `apt_add_docker_repo`, `install_docker_engine`, `install_nvidia_toolkit`,
  `start_engine`, `image_pull`; Linux `add_user_to_docker_group`. Per kind:
  privilege per platform, elevated-helper operation, acknowledgement,
  `licence_required`, members, flag rules, provisional source prefixes,
  preconditions, fixed command templates (argv without shell, absolute
  programs, `signed-by` apt keys), titles (`title_without_source` for an
  unverified wsl.exe download), supported Ubuntu codenames (`jammy`, `noble`,
  amd64; provisional). **Mirror**: Java `ElevatedStep` unchanged
  (ENABLE_WSL_FEATURES, ENABLE_VM_PLATFORM, INSTALL_WSL, UPDATE_WSL); the
  helper runs only the registry's `{system32}` commands for its step; Go runs
  the registry commands of each Linux kind through `sudo --`.
- **Execution preconditions** (`test-vectors/step-preconditions/`):
  `source_verified` (INTEGRITY_MISMATCH), `ubuntu_supported`
  (UNSUPPORTED_PROFILE), `target_user_current`, `wslconfig_unchanged`
  (PLAN_STALE), `distro_owned` (FOREIGN_RESOURCE / PLAN_STALE),
  `wsl_restart_confirmed` (WSL_RESTART_REQUIRED: CR04 separate confirmation
  after drain). **Mirror**: evaluate right before each step with fresh facts.
- **Consent needs all terms** (CR-20): effect `set_consented_plan_id` has
  `checks: [terms_accepted]` (new guard-context members `required_licence_ids`,
  `accepted_licence_ids`, `required_acknowledgements`,
  `given_acknowledgements`); otherwise consent stays unset (CONSENT_REQUIRED,
  CLI exit 4). New effect `checks`/`on_reject` in
  `schemas/state-machines.schema.json`; vectors `test-vectors/effects/`.
  **Mirror**: GUI controls per licence and acknowledgement, unchecked by
  default; CLI `--accept-license <id>`, `--accept-docker-group`,
  `--accept-distro-removal`; `--yes` replaces none.
- **Local engine endpoint** (SEC-B1): guard predicate `engine_endpoint_local`
  (reads `engine_endpoint`, `engine_tcp_listener`) first on ENGINE_CHECK →
  IMAGE_PULL and ENGINE_CHECK → SMOKE_TEST; `tcp://` even on loopback is
  ENGINE_REMOTE_CONTEXT, any dockerd TCP listener is ENGINE_TCP_EXPOSED; both go
  to ACTION_REQUIRED. **Mirror** in ENGINE_CHECK.
- **ImageDigest / ImageReference** (`schemas/image-reference.schema.json`):
  `sha256:<64 lowercase hex>`; `<repository>@<digest>` with a fully qualified
  repository (registry host with a dot, no port, no tag). Runs are always
  no-pull. **Mirror**: Java `ImageReference` must require the registry host.
- **Image allowlist** (`registry/image-allowlist.json`): `kind:
  image_allowlist`, `entries[]` `{repository, digest, purpose, platform,
  min_client_version, max_client_version?}`; bundled, never fetched; empty =
  fail closed. The guard input `allowlist` is now a list of ImageReferences and
  `image_allowlisted` reads `image_reference` (SEC-m3: (repository, digest)
  pairs). Client version = the shared Sprut client release line; pre-release
  is lower than its release (CR-21). **Mirror**: Java replaces its provisional
  `{"digests": [...]}` resource with this file and passes `image_reference`.
- **Ownership labels** (`registry/ownership.json`): namespace
  `io.github.alexindacomp.sprut`; required `managed=true`, `profile=<id>`;
  optional `operation_id`; charset; rules incl. adoption (SEC-m5: reuse only if
  in the journal and inspect is clean). **Mirror**: Java
  `DockerEngine.OWNERSHIP_LABELS` adds the profile label; adoption rule.
- **WSL resources** (`schemas/wsl-resources.schema.json`): managed `[wsl2]`
  keys `memory`, `processors`, `swap`, `networkingMode` (only `nat` until S2,
  Q14) and the Sprut distribution `max_disk_size`; no defaults (Q15).
  **Mirror**: Java `.wslconfig` writer; `wslconfig_file` in the plan.
- **Reason codes** `FOREIGN_RESOURCE`, `PLAN_INVALID`, `ENGINE_TCP_EXPOSED`
  (all exit 1). **Mirror**: Java `ForeignResourceException` and the foreign
  container cases of `stopContainer` / `removeContainer` map to
  `FOREIGN_RESOURCE`.

### Final review round (SEC-N1…N4, CR-28…CR-31)

- **Verified copies** (SEC-N1): new `client_action` `verify_source`, run by
  the step's own principal (root / elevated helper) on a root- or
  admin-only copy; placeholder `{source_file}` replaced by `{verified_file}`,
  usable only after `verify_source`. **Mirror**: Java helper and Go sudo
  executor implement `verify_source`.
- **No `/usr/bin/env` in templates** (SEC-N4): per-kind `environment`
  (`DEBIAN_FRONTEND=noninteractive` for apt kinds) set by the executor.
  **Mirror**.
- **`engine_tcp_listener`** means the actual listening sockets of dockerd and
  its socket units (`docker.socket` ListenStream); `engine_endpoint_local` is
  re-checked before every container/task run (SEC-N2). **Mirror**.
- **CR-30, breaking for the provisional Java guard inputs**: guard-context
  `image_digest` removed; `consented_image_digests` renamed
  `consented_image_references`; `image_in_consented_plan` reads
  `image_reference` and compares whole references; plan `derived` renamed
  accordingly. **Mirror**.
- `target_user.name` widened to `^[A-Za-z0-9_][A-Za-z0-9._@-]{0,255}$`
  (CR-28); `distro.base_path` up to 32767 characters; an unrepresentable
  current `.wslconfig` value is WSL_CONFIG_CONFLICT → ACTION_REQUIRED naming
  the key (CR-29, `current_value_cases`). **Mirror**.
- `SECURITY.md` with reporting, repository protection and release checklist;
  the validator fails on a non-empty allowlist without `CODEOWNERS` (SEC-N3).

### Changed (no change of earlier verdicts)

- `step_is_privileged_plan_step` declares `reads: [consented_plan_id, step]`
  and the reference checks consent (CR-12). **Mirror**.
- Guard vectors: ENGINE_CHECK contexts carry the engine inputs; `allowlist`
  holds ImageReferences and contexts carry `image_reference`.
- OperationEvent `schema_version` is `"type": "integer"`; `schema_version: 1.0`
  is now rejected by producers and consumers (SEC-m6, CR-24). Every numeric
  `const`/`enum` in `schemas/` carries `"type": "integer"`. **Mirror**.

### Documented (issue #2)

`docs/canonical-json.md` 2, 3.3 and 5. **Mirror** in Java and Go validators:
`object_hash` of a non-object is `INVALID_JSON`; `"type": "integer"` rejects
`1.0`; numeric `const`/`enum` always come with the integer type.

### Validator

`tools/validate.py` checks the new registries, schemas and vectors, predicate
`reads`, effect checks, command templates, copied schema definitions and raw
invisible characters in schema/registry sources; `--self-test` has 124
mutations (was 66).

## 0.1.0

Minimal contract set for the Windows client C0: reason codes, exit codes,
bootstrap / node / WSL / task state machines with bootstrap guards,
OperationEvent, canonical JSON and hash.
