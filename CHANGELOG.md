# Changelog

## 0.3.0 — contract gaps found by the reviews of the Windows C1 core

Findings CR-44d, CR-45, CR-49, CR-57, CR-58, CR-59.5, SEC-1, SEC-4, SEC-5,
SEC-11, SEC-12, SEC-15 and the review rounds of this release (CR-70…CR-85).
`schema_version` stays 1: the InstallationPlan and OperationEvent formats are
unchanged. The registries are bundled with each client, which implements a
pinned release as a whole; a client moving its pin from 0.2.0 must copy every
item marked **Mirror**. Two kinds of change are visible to an existing client:
six step titles changed, so the `plan_id` of a plan with one of those steps
differs from 0.2.0 (titles are hashed), and new preconditions make execution
stricter (see "Changed vectors").

### Added

- **Reason codes** (CR-45), all with `cli_exit_code` 1:

  | Code | Platforms | Retryable |
  |---|---|---|
  | `STEP_FAILED` | windows, linux | no |
  | `PACKAGE_INSTALL_FAILED` | windows, linux | no |
  | `SECRET_STORE_FAILED` | windows, linux | no |
  | `LOCAL_STORAGE_FAILED` | windows, linux | no |
  | `ENGINE_DOCKER_DESKTOP` | windows, linux | no |
  | `ENGINE_COMMAND_FAILED` | windows, linux | yes |
  | `PROBE_FAILED` | windows, linux | yes |
  | `WSL_COMMAND_FAILED` | windows | yes |
  | `ELEVATED_STEP_FAILED` | windows | no |
  | `ELEVATION_UNAVAILABLE` | windows | no |

  **Mirror**: Java `ReasonCodes` and `FailureReasons` (its provisional
  aliases become the real codes: `LOCAL_STORAGE_FAILED` is no longer
  INSUFFICIENT_DISK, `DOCKER_DESKTOP_ENGINE` becomes `ENGINE_DOCKER_DESKTOP`
  and is no longer ENGINE_REMOTE_CONTEXT, and so on); `DpapiSecretStore`
  reports `SECRET_STORE_FAILED`.
- **Step failures** (CR-45, CR-70, CR-73, CR-74, CR-75):
  `registry/step-failures.json` (`schemas/step-failures.schema.json`),
  `docs/installation-plan.md` section 8, `test-vectors/step-failures/` (101
  mapping cases, 69 classification cases). Thirteen failure classes, each
  with one outcome and an `error` event, listed per step kind and platform
  and for PROBING, ENGINE_CHECK and SMOKE_TEST:

  | Class | Reason code | Next state |
  |---|---|---|
  | `source_unavailable` | SOURCE_UNAVAILABLE | FAILED |
  | `insufficient_disk` | INSUFFICIENT_DISK | ACTION_REQUIRED |
  | `local_storage_failed` | LOCAL_STORAGE_FAILED | ACTION_REQUIRED |
  | `package_install_failed` | PACKAGE_INSTALL_FAILED | FAILED |
  | `wsl_command_failed` | WSL_COMMAND_FAILED | FAILED |
  | `command_failed` | STEP_FAILED | FAILED |
  | `plan_refused` | PLAN_INVALID | FAILED |
  | `elevation_unavailable` | ELEVATION_UNAVAILABLE | ACTION_REQUIRED |
  | `elevated_step_failed` | ELEVATED_STEP_FAILED | FAILED |
  | `smoke_test_failed` | SMOKE_TEST_FAILED | FAILED |
  | `engine_docker_desktop` | ENGINE_DOCKER_DESKTOP | ACTION_REQUIRED |
  | `engine_command_failed` | ENGINE_COMMAND_FAILED | FAILED |
  | `probe_failed` | PROBE_FAILED | FAILED |

  **Mirror** (Java `BootstrapExecutor`, `WslCli`, `CliDockerEngine`,
  `HostProber`; Go executor): choose the class by the ordered rules of
  section 8.2 and take code and state from the registry. The rules are
  mechanical:
  - through `wsl.exe` a process that was not started, timed out or ended
    with an exit status outside 0–255 (for example -1) is
    WSL_COMMAND_FAILED; a status in 1–255 is the program's result;
  - a probe that answers by its output has answered only with exit 0 and
    complete, well-formed output; anything else is WSL_COMMAND_FAILED
    (Windows) or PROBE_FAILED (Linux) and never evidence. Only
    `test -x /usr/bin/docker` and `systemctl is-active --quiet
    docker.service` answer by exit status, and they can only lead to a plan
    that installs or starts;
  - a failed `apt-get update` is SOURCE_UNAVAILABLE, a failed `apt-get
    install` PACKAGE_INSTALL_FAILED, any other failed step command
    STEP_FAILED (not ENGINE_DAEMON_STOPPED, not WSL_DISTRO_BROKEN);
  - the client's own staging, rootfs or verified-copy file could not be
    written: INSUFFICIENT_DISK only when the system reported a full disk,
    otherwise LOCAL_STORAGE_FAILED; both → ACTION_REQUIRED;
  - elevated step: helper cannot start → ELEVATION_UNAVAILABLE →
    ACTION_REQUIRED; UAC prompt or helper prompt declined → CANCELLED; plan
    refused by the helper → PLAN_INVALID; otherwise ELEVATED_STEP_FAILED
    (not WSL_MISSING / WSL_OUTDATED);
  - engine: a pull that exited non-zero (CLI) or whose progress stream
    reported an error (API) is SOURCE_UNAVAILABLE; not started, timed out or
    a request error is ENGINE_COMMAND_FAILED; in SMOKE_TEST only a non-zero
    exit of the container, or a container still running after the wait
    timed out (seen by inspect), is SMOKE_TEST_FAILED;
  - an engine that identifies itself as Docker Desktop (`OperatingSystem`
    equals `Docker Desktop`, or `Platform.Name` starts with it) is
    ENGINE_DOCKER_DESKTOP → ACTION_REQUIRED in PROBING, ENGINE_CHECK and
    again right before every container or task run
    (`docs/images-and-ownership.md` 3.5). Whenever the Docker CLI is present
    the identity is read before the `systemctl is-active` answer is used, and
    a Docker Desktop answer wins whatever the state of `docker.service` is,
    so the plan is never just `start_engine` there; an identity that cannot
    be read while the service is reported inactive is a stopped daemon, not
    a failure (CR-82);
  - any other check that could not be performed (registry or host API read,
    a Linux probe program) is PROBE_FAILED → FAILED; no plan is built.
- **`wsl_availability` state `WSL_POLICY_BLOCKED`** (CR-45): terminal, reason
  code of the same name; bootstrap goes PROBING → ACTION_REQUIRED. Every state
  except WSL2_READY carries the reason code of its name. **Mirror**: Java
  `WslAvailability` returns the state instead of a code without a state.
- **Preconditions** (`registry/plan-step-kinds.json`,
  `test-vectors/step-preconditions/`, 59 cases):
  - `replacement_source_verified` on `unregister_distro` (CR-44d, SEC-1):
    reads `replacement_downloaded_sha256` and `source.sha256` of the next plan
    step (vector member `next_step`); no verified copy → SOURCE_UNAVAILABLE →
    FAILED, other hash → INTEGRITY_MISMATCH → FAILED; nothing is removed.
    **Mirror**: before `wsl --unregister`, download and verify the rootfs of
    the following `import_distro`; keep that verified copy until the import
    ends; the import re-hashes it and never downloads after the removal.
  - `sprut_drained` on `configure_distro`, `resize_distro_disk`,
    `unregister_distro` (CR-49) and `install_nvidia_toolkit` on both
    platforms (CR-72, it restarts Docker Engine): DRAIN_TIMEOUT →
    ACTION_REQUIRED (`error` event). **Mirror**: drain before these steps.
  - `wsl_restart_confirmed` now also first on `install_wsl` and `update_wsl`
    (SEC-5), with two new facts: `registered_distributions` (install/update)
    and `running_distributions` (`restart_wsl`). Install/update: no
    registered distribution of the user → holds without a dialog; at least
    one → drain and the separate confirmation; list unreadable (absent, null
    or not an array of names) → WSL_RESTART_REQUIRED → ACTION_REQUIRED.
    `restart_wsl`: the running list must have been read (fail closed
    otherwise); the confirmation is needed also for an empty list.
    **Mirror**: Java `WslRestartGate` / `runningDistributions()` must not turn
    a read failure into an empty list; ask before the UAC prompt of
    `install_wsl` / `update_wsl`.
  - Preconditions are evaluated in the order the kind lists them; the first
    failing one decides (order vectors, CR-79).
- **Acknowledgement `engine_restart`** (CR-72): on Linux
  `install_nvidia_toolkit` restarts the Docker Engine of the host and stops
  every container on it. New optional members of a platform rule:
  `platforms.<platform>.acknowledgement` and `platforms.<platform>.title`.
  **Mirror**: Go CLI flag `--accept-engine-restart`, derived
  `required_acknowledgements`; both clients read acknowledgement and title
  per platform first, then per kind (Java `PlanStepKinds` parser).
- **`resize_distro_disk` template** (CR-49): `wsl --terminate {distro_name}`
  before `wsl --manage ... --resize`. **Mirror**: Java runs both registry
  commands instead of a hidden extra terminate.
- **`apt-get update` template** (CR-71):
  `/usr/bin/apt-get update -o APT::Update::Error-Mode=any` in
  `apt_add_docker_repo` and `install_nvidia_toolkit`, so that a fetch failure
  is a non-zero exit status. **Mirror**: nothing beyond running the registry
  template.
- **Download rule** (CR-58, SEC-11, CR-77): new required step-kind member
  `redirect_hosts` (bare host names) and, for kinds with a source, `download`
  `{max_bytes, timeout_seconds}`; `install_wsl` / `update_wsl`:
  `objects.githubusercontent.com`, `release-assets.githubusercontent.com`,
  512 MiB, 30 min; `import_distro`: 1 GiB, 60 min; signing keys: 64 KiB,
  60 s (all provisional, S−1; whether `timeout_seconds` becomes a stall
  timeout with a generous total, or downloads resume, is an S−1 decision —
  for now it is the total time). Rule 10 of `docs/installation-plan.md`,
  `test-vectors/download-redirects/` (31 cases). **Mirror** (Java
  `HttpsDownloader`, Go downloader): the prefix check applies to the
  requested URL only, which has the strict form of the plan schema; every
  hop is https with certificate verification, no userinfo, no explicit port,
  and its host is the requested host or one of `redirect_hosts` (exact,
  without case); at most 5 redirects; the body is refused above `max_bytes`
  and the download ends within `timeout_seconds`; a refusal is
  SOURCE_UNAVAILABLE.
- **Both hashes for in-distribution copies** (SEC-12): `source_verified` reads
  the new fact `staged_sha256`, the client's own SHA-256 of the staged
  download; on Windows, for kinds whose `{verified_file}` is used by a Linux
  program (`apt_add_docker_repo`, `install_nvidia_toolkit`), both it and
  `downloaded_sha256` must equal `source.sha256`. **Mirror**: Java hashes the
  staged file before `StoreVerifiedCopy` and hands nothing over on a mismatch.
- **Run profiles** (SEC-15, CR-76): `registry/run-profiles.json`
  (`schemas/run-profiles.schema.json`), `docs/images-and-ownership.md`
  section 5, `test-vectors/run-profiles/` (31 cases). `diagnostic`:
  `--pull=never --network none --cap-drop ALL --security-opt
  no-new-privileges --read-only --pids-limit <n> --memory <limit>`, each
  exactly once; besides them only `--detach`, `--name`, `--label`; nothing
  after the image reference; the container is always removed (failure,
  timeout, cancel, leftover of a crash). `worker` and `inference`: to be
  defined with their own security review. **Mirror**: Java
  `DockerCommand.Run` for the smoke test; Go `HostConfig` and `Config`
  (field mapping in the docs). The limit values are provisional client
  constants until CR-57.
- **Elevated helper** (SEC-4, CR-59.5, CR-73, CR-78):
  `docs/installation-plan.md` section 9, normative for the helper: arguments
  are only plan id, step id and plan path; the path is a local absolute path
  on a fixed drive to a regular file that is no reparse point, its size is
  checked before the single read into memory; `source.url` / `source.sha256`
  are compared with constants compiled into the helper, which are the ones
  used; download and verification in an Administrators-only directory with a
  protected DACL, the verified copy deleted after the step; `msiexec` /
  `dism` only on that copy; its own elevated prompt shows kind, URL and hash
  and, for INSTALL_WSL / UPDATE_WSL, that running WSL distributions may be
  stopped; the result carries `outcome`, a reason code and
  `reboot_required`. `requires_reboot` stays `may` for the four elevated
  kinds: the flag is the forecast, `reboot_required` the fact; either one
  leads INSTALLING → REBOOT_REQUIRED. **Mirror**: Java `ElevationResult` gets
  `reboot_required` and a reason code; `declined` leads to CANCELLED; the
  helper follows section 9.

### Changed

- **Step titles disclose what the step stops** (CR-80, CR-72). Titles are
  hashed, so `plan_id` changes for plans with these steps. **Mirror**: both
  clients take titles from the registry; nothing is hard-coded.
  - `install_wsl`, `update_wsl` (with and without source): "… (running WSL
    distributions may be stopped)";
  - `configure_distro`, `resize_distro_disk`: "… (the Sprut distribution is
    stopped; its tasks are drained first)";
  - `install_nvidia_toolkit`: Windows "… (Docker Engine in the Sprut
    distribution is restarted; its tasks are drained first)", Linux "…
    (Docker Engine is restarted: all containers on this computer are
    stopped)".
- **WSL_DISTRO_BROKEN** needs positive evidence (CR-45, CR-70): the
  registration states a WSL version other than 2, the VHDX is missing (both
  read from the registration and the file system), or a probe inside the
  distribution exited 0 with complete, well-formed output that is not the
  expected answer. Any other probe result is WSL_COMMAND_FAILED and never
  leads to a plan with `unregister_distro`. **Mirror**: Java `WslCli` /
  `HostProber`.
- **Texts**: STEP_FAILED (CR-81), PACKAGE_INSTALL_FAILED (download or
  installation, CR-71), SOURCE_UNAVAILABLE next action (every configured apt
  source), WSL_RESTART_REQUIRED (also the confirmation of `install_wsl` /
  `update_wsl`), DRAIN_TIMEOUT (also the drain before a step).
- `evaluate_preconditions` (reference) takes the next step of the plan;
  precondition vectors may carry `next_step`.

### Changed vectors

No verdict of an unchanged rule changed.

- `test-vectors/installation-plans/`: 28 vectors carry the new titles and,
  with them, new hashes; four new vectors (`windows-wsl-update-verified`,
  `linux-nvidia-toolkit`, `windows-nvidia-toolkit`,
  `linux-nvidia-toolkit-with-windows-title`).
- `test-vectors/step-preconditions/cases.json`: three 0.2.0 cases got the
  facts the stricter rules need to remain "allowed":
  `wsl-restart-confirmed-after-drain` (`running_distributions`),
  `wsl-update-by-wsl-exe` (`registered_distributions`, drain, confirmation)
  and `unregister-own-distro` (`next_step`, drain,
  `replacement_downloaded_sha256`). Four rejected cases
  (`wsl-restart-not-confirmed`, `wsl-restart-before-drain`,
  `unregister-foreign-distro`, `unregister-distro-already-gone`) got the
  facts that keep them single-cause.
- New cases in `test-vectors/state-transitions/wsl_availability.json`,
  `test-vectors/exit-codes/resolution.json` and
  `test-vectors/effects/bootstrap.json`.

### Documented

- README "Planned": the diagnostic image protocol (CR-57: compute, persistent
  state, logs, stop; also `--user`, `--memory-swap`, `--cpus`) is a required
  contract before any image digest is pinned; PROFILE_LOCKED must be a
  cross-process lock (CF04) in both clients; the S−1 checks recorded in these
  contracts (WSL update behaviour including a multi-user computer, the apt
  option on jammy, redirect hosts and download limits, reload instead of
  engine restart).
- An image is allowlisted only for a purpose whose run profile is normative
  with fixed limits (`SECURITY.md`, `docs/images-and-ownership.md` 2.8).

### Validator

`tools/validate.py`: new reason codes required; `wsl_availability` terminal
states and state reason codes; step-failure classes derived from the command
templates and the classification reference; redirect hosts and download
limits; drain precondition for kinds that stop the Sprut distribution or
Docker Engine, the `engine_restart` acknowledgement, `--terminate` before
`--resize`, the fixed `apt-get update`; titles and acknowledgements per
platform; run profiles; allowlist entry ↔ run profile; the new vectors.
1144 checks (was 827); `--self-test` has 206 mutations (was 124).

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
