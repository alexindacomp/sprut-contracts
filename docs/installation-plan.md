# InstallationPlan (CF12, CF13)

Status: normative for `schema_version` 1, from sprut-contracts 0.2.0; execution
rules extended in 0.3.0 (preconditions, redirects, step failures, elevated
helper; the plan document format is unchanged). Files:
`schemas/installation-plan.schema.json` (structure),
`registry/plan-step-kinds.json` (closed step-kind vocabulary, preconditions and
command templates, validated by `schemas/plan-step-kinds.schema.json`),
`registry/step-failures.json` (failure classes and their outcomes),
`test-vectors/installation-plans/`, `test-vectors/step-preconditions/`,
`test-vectors/step-failures/`, `test-vectors/download-redirects/`,
`test-vectors/effects/` (conformance), `tools/validate.py` (`validate_plan`,
`evaluate_preconditions`, `download_allowed`, `failure_outcome`, the reference).

The InstallationPlan is what the user sees and consents to before Sprut
changes the host. Both clients build it in their core, display it, hash it, and
execute only its steps.

## 1. Document

| Member | Content |
|---|---|
| `kind` | `"installation_plan"` (domain separation, `docs/canonical-json.md` 2) |
| `schema_version` | `1` (integer) |
| `platform` | `windows` (Sprut Desktop: WSL2 + Sprut distribution) or `linux` (`sprut` CLI on Ubuntu) |
| `current_state`, `target_state` | State summaries: `docker_engine` (`absent`/`stopped`/`running`) and `worker_image` (`absent`/`present`) always; `nvidia_toolkit` (`absent`/`installed`) optional; Windows only `wsl` (`WSL2_READY`/`WSL_OUTDATED`/`WSL_MISSING`) and `sprut_distro` (`absent`/`broken`/`ready`); Linux only `docker_group` (`member`/`not_member`) |
| `docker_access` | Linux only, required there: `docker_group` or `none` (section 3, rule 17) |
| `steps[]` | The actions, in execution order (section 2) |
| `images[]` | Every image the plan uses, pulled or run, as ImageReference `<repository>@sha256:<64 hex>` |
| `licences[]` | `{id, url, sha256}`: licence terms; `sha256` pins the text the client ships and shows |
| `disk_estimate_bytes` | Sum of the steps' `estimated_bytes` |
| `hash` | `plan_id` = `object_hash` of the document; always present |

Each step has `id`, `kind`, `title` `{ru, en}`, `privileged`,
`requires_reboot`, `requires_relogin`, `requires_wsl_restart`,
`estimated_bytes` (all required), optional `licence_ids[]`, and, depending on
the kind, the typed members:

| Member | Kind | Content |
|---|---|---|
| `image` | `image_pull` | ImageReference listed in `images[]` |
| `source` | downloads | `{url, sha256}` of the artifact (rules 9, 10) |
| `wslconfig` | `write_wslconfig` | managed `[wsl2]` values to write (`docs/wsl-resources.md`) |
| `wslconfig_file` | `write_wslconfig` | `{sha256, replaced}`: SHA-256 of the current `.wslconfig` (or `absent`) and the current text of the managed keys being overwritten; an unrepresentable current value is WSL_CONFIG_CONFLICT (`docs/wsl-resources.md`) |
| `distro_disk_size` | `resize_distro_disk` | new maximum disk size of the Sprut distribution |
| `distro` | `unregister_distro` | `{name, base_path, vhdx_bytes}` of the distribution that will be removed |
| `target_user` | `add_user_to_docker_group` | `{name, uid}` from the uid of the client process, never from environment variables; never root; the name never starts with `-` |

There are no optional booleans: every flag is written explicitly, so the
hashed text has one form.

## 2. Step kinds (closed vocabulary)

`registry/plan-step-kinds.json` is the only source of step kinds; anything else
is `UNKNOWN_STEP_KIND`. "Priv." is host elevation: UAC through the elevated
helper on Windows, `sudo` on Linux. Root inside the Sprut WSL distribution is
not host elevation.

| Kind | Windows | Linux | Members | Flags | Ack. / licence | Preconditions |
|---|---|---|---|---|---|---|
| `enable_wsl_features` | priv., helper `ENABLE_WSL_FEATURES` | – | – | reboot may | – | – |
| `enable_vm_platform` | priv., helper `ENABLE_VM_PLATFORM` | – | – | reboot may | – | – |
| `install_wsl` | priv., helper `INSTALL_WSL` | – | `source` optional | reboot may | – | `wsl_restart_confirmed`, `source_verified` |
| `update_wsl` | priv., helper `UPDATE_WSL` | – | `source` optional | reboot may | – | `wsl_restart_confirmed`, `source_verified` |
| `unregister_distro` | not priv. | – | `distro` | – | ack. `distro_removal` | `distro_owned`, `sprut_drained`, `replacement_source_verified` |
| `import_distro` | not priv. | – | `source` | – | licence required | `source_verified` |
| `configure_distro` | not priv. | – | – | – | – | `sprut_drained` |
| `apt_add_docker_repo` | not priv. | priv. | `source` (signing key) | – | – | `ubuntu_supported`, `source_verified` |
| `install_docker_engine` | not priv. | priv. | – | – | – | `ubuntu_supported` |
| `add_user_to_docker_group` | – | priv. | `target_user` | relogin always | ack. `docker_group` | `target_user_current` |
| `install_nvidia_toolkit` | not priv. | priv. | `source` (signing key) | – | Linux: ack. `engine_restart` | `ubuntu_supported`, `sprut_drained`, `source_verified` |
| `start_engine` | not priv. | priv. | – | – | – | – |
| `write_wslconfig` | not priv. | – | `wslconfig`, `wslconfig_file` | WSL restart always | – | `wslconfig_unchanged` |
| `resize_distro_disk` | not priv. | – | `distro_disk_size` | – | – | `sprut_drained` |
| `restart_wsl` | not priv. | – | – | – | – | `wsl_restart_confirmed` |
| `image_pull` | not priv. | not priv. | `image` | – | – | (guards of IMAGE_PULL) |

The **elevated-step vocabulary** of the Windows UAC helper is exactly the four
kinds privileged on Windows (Java `ElevatedStep`); the helper itself is
specified in section 9. Source URL prefixes are in the registry; all of them
are provisional and confirmed at S−1 (Q10 for the Ubuntu rootfs).
`redirect_hosts` lists, per kind, the hosts a download may end on besides the
requested host (rule 10).

**Commands (SEC-m1).** Each kind has fixed command templates per platform in
the registry (`commands`): `argv` lists started without a shell, `install_file`
(the core writes fixed content and installs it with `/usr/bin/install -D -m`),
and `client_action` (`download_source`, `verify_source`, `edit_wslconfig`,
`engine_pull`).
Programs are absolute: Windows programs as `{system32}\...` (the system
directory from the OS API, never `PATH`); Linux programs by absolute path, run
on Linux through `/usr/bin/sudo --` for privileged kinds and on Windows inside
the Sprut distribution as root through
`{system32}\wsl.exe --distribution {distro_name} --user root --exec`. The only
placeholders are those in `placeholders`, each a whole argument; the two
exceptions are the `{system32}` prefix of `argv[0]` and `{codename}` inside
`install_file` content (CR-31). Nothing from the host, user or network enters a
command otherwise. Shells, interpreters, downloaders, program launchers such as
`env`, and `sudo` never appear in a template. Environment variables are not set
through argv: a kind declares them in `environment` (only
`DEBIAN_FRONTEND=noninteractive`, for kinds running apt-get), and the executor
adds them to its fixed base environment (SEC-N4). `resize_distro_disk` first
runs `wsl --terminate {distro_name}` and then `wsl --manage ... --resize`: the
resize needs a stopped distribution, and the stop is part of the consented
template, not a hidden extra call (CR-49).

**apt (CR-71).** `apt-get update` is always
`/usr/bin/apt-get update -o APT::Update::Error-Mode=any`: by default
`apt-get update` exits 0 with warnings when an index cannot be fetched, and
the failure would surface only later as a confusing installation error. The
option is to be confirmed on jammy at S−1. The update covers every configured
source: the Docker and NVIDIA packages depend on packages of the Ubuntu
archive, whose indexes must be present and current (a freshly imported rootfs
has none). On a Linux host a foreign apt source that cannot be fetched
therefore fails the step with SOURCE_UNAVAILABLE; Sprut never edits or
disables a source it did not add. A non-zero `apt-get install` is
PACKAGE_INSTALL_FAILED whether the packages could not be downloaded or could
not be installed: apt reports both with the same exit status, and splitting
the command (`--download-only`, then `--no-download`) would not separate them
either, because dependency resolution fails in the download phase.

**Engine restart (CR-72).** `install_nvidia_toolkit` ends with
`systemctl restart docker.service`, which stops every container of that
engine. It therefore needs `sprut_drained` on both platforms. On Windows the
engine is the one inside the Sprut distribution and only Sprut's containers
are affected. On Linux it is the engine of the host: containers that are not
Sprut's stop too, so the step there has its own title that says so
(`platforms.linux.title`) and needs the separate acknowledgement
`engine_restart`. Whether a configuration reload can replace the restart is
an S−1 investigation.

**Verified copies (SEC-N1).** A command never uses the downloaded file. Every
kind with a source runs `download_source` (into the client's staging
directory) and then `verify_source`, executed by the same principal as the
step's commands: root through `sudo` on Linux or inside the distribution, or
the elevated helper. `verify_source` copies the file into a directory only that
principal can write (Linux: `install -m 0600 -o root -g root` into a root-only
directory; helper: an Administrators-only directory), hashes that copy and
compares it with `source.sha256` (INTEGRITY_MISMATCH otherwise). Commands use
only `{verified_file}`, that copy; the validator rejects a template that uses
it without a preceding `verify_source`. If the copy or the hash program of
`verify_source` cannot run, that is a command failure of the step (section 8),
not an integrity result; a hash that is missing for any other reason still
fails closed as INTEGRITY_MISMATCH.

**Both hashes for in-distribution copies (SEC-12).** When the verifying
principal is root inside the Sprut distribution (Windows:
`apt_add_docker_repo`, `install_nvidia_toolkit`, where `{verified_file}` is
used by a Linux program), the hash is an answer from the Linux side. The
client therefore also computes the SHA-256 of the staged download itself
(`staged_sha256`) and compares it with `source.sha256` before it hands the
file to the distribution; on a mismatch nothing is handed over.
`source_verified` holds only if both values — the client's own hash and the
hash of the in-distribution copy — equal the pinned one.

The elevated helper runs only `{system32}` programs. apt signing keys
are installed under `/etc/apt/keyrings/` and referenced with `signed-by` in the
repository line, never added to the global trust store. Package versions are
those of the repository at run time; apt verifies them with that key.
Supported Ubuntu releases and architecture are `supported_ubuntu` (codenames
`jammy`, `noble`, `amd64`; provisional); anything else is
UNSUPPORTED_PROFILE.

## 3. Rules

1. **Hash and identity.** The document is parsed with the hashing restrictions
   (`docs/canonical-json.md` 3) and `object_hash` with expected kind
   `installation_plan`. `hash` is required and must equal the recomputed
   `object_hash` (`HASH_MISMATCH`).
2. **Strict members.** Unknown members are rejected at every level
   (`SCHEMA_VIOLATION`). A new member needs a new `schema_version`.
3. **Deterministic.** The plan is a function of the probed host state, the
   client version and the bundled contracts. It contains no timestamps, random
   ids or operation ids (operation ids belong to the operation and the
   journal), so rebuilding it for an unchanged host gives the same `plan_id`.
4. **Every step is an action.** `plan_action_count` = number of `steps[]`; a
   plan with zero steps is the only one that skips consent. Step ids are unique
   (`DUPLICATE_STEP_ID`).
5. **Closed vocabulary and platform** (`UNKNOWN_STEP_KIND`,
   `STEP_NOT_ON_PLATFORM`, `STATE_NOT_ON_PLATFORM`).
6. **Privilege** equals the registry value (`PRIVILEGE_MISMATCH`). The guard
   input `step` is computed by looking up the step id in the consented plan.
7. **Flags** follow `never`/`may`/`always` (`FLAG_MISMATCH`).
8. **Step members.** Required members present (`STEP_MEMBER_MISSING`), others
   refused (`STEP_MEMBER_NOT_ALLOWED`).
9. **Pinned integrity (SEC-A1).** Every `source.sha256` is a constant of the
   client build (later: from a signed manifest, planned). It is never fetched
   at plan time, least of all from the artifact's own origin. The URL prefixes
   are a guard rail; the digest is the trust anchor. `source.url` must start
   with one of the kind's prefixes (`SOURCE_NOT_OFFICIAL`). An `install_wsl` /
   `update_wsl` step without `source` means `wsl.exe` downloads and Sprut does
   not verify the download; its title is then the kind's
   `title_without_source`, which says so.
10. **Downloads (SEC-A2, CR-58 / SEC-11).**
    - **Requested URL.** The prefix check of rule 9 applies to the requested
      URL, `step.source.url`, and not to where redirects lead. It has the
      strict form of the plan schema (`https`, lowercase host, no port,
      userinfo, query, fragment or percent-encoding) and starts with one of
      the kind's `source_url_prefixes`.
    - **Every hop** — the requested URL and each redirect target — is `https`
      with mandatory certificate verification, without userinfo and without an
      explicit port. There is never a downgrade to `http`, also when a later
      hop is `https` again. The client follows redirects itself, at most 5.
    - **Hosts (CR-77).** The host of every hop equals the host of the
      requested URL or is one of the kind's `redirect_hosts` in the registry:
      exact host names compared without case, never by suffix or wildcard. A
      redirect to any other host is refused before a request is sent to it,
      also when a later hop would be allowed again. The lists are per kind.
      Today only `install_wsl` and `update_wsl` have entries, the GitHub
      release-asset CDN hosts `objects.githubusercontent.com` and
      `release-assets.githubusercontent.com` (provisional, confirmed at S−1).
    - **Size and time (CR-77).** Each kind with a source has
      `download.max_bytes` and `download.timeout_seconds` in the registry
      (provisional, confirmed at S−1): 512 MiB / 30 min for the WSL package,
      1 GiB / 60 min for the rootfs, 64 KiB / 60 s for a signing key. A
      response whose announced length is larger than `max_bytes` is refused;
      a body is aborted as soon as more bytes arrive. When the client build
      pins the exact size of an artifact next to its SHA-256, the received
      length must also equal that size; the pinned size is a constant of the
      build like the hash, never larger than the cap, and not a member of the
      plan document. The whole download, redirects included, ends within
      `timeout_seconds`. This meaning of `timeout_seconds` is provisional:
      **S−1 decision** — a stall timeout with a generous total, or resume of
      an interrupted download; until then it is the total time and no client
      behaves differently.
    - A download that breaks one of these rules is not performed; the step
      fails with SOURCE_UNAVAILABLE (section 8). Vectors:
      `test-vectors/download-redirects/`.
    - **The pinned SHA-256 remains the integrity anchor**; the host rules are
      a guard rail. The file is written to a directory only the executing
      principal can write and its SHA-256 is checked before use (precondition
      `source_verified`, INTEGRITY_MISMATCH otherwise). For a privileged step
      this check is the `verify_source` operation of section 2, run by the
      elevated helper or as root on a root-owned copy, so the unprivileged
      client cannot swap the file after the check. The helper receives only
      the plan id, the step id and the plan path and takes everything else
      from the plan document it re-hashes and from its own constants
      (section 9).
11. **Images.** One entry per digest (`DUPLICATE_IMAGE`); a pull's `image`
    equals an entry, repository included (`IMAGE_NOT_LISTED`); one pull per
    digest (`DUPLICATE_PULL`). `consented_image_references` = the images of
    the consented plan's `image_pull` steps; guards compare whole references.
12. **Licences.** Never accepted on the user's behalf (CF13). The client shows
    the pinned text of each entry of `licences[]`. Kinds with
    `licence_required` list at least one licence (`LICENCE_MISSING`);
    references must exist (`LICENCE_UNKNOWN`); ids are unique
    (`DUPLICATE_LICENCE`).
13. **Acknowledgements.** `add_user_to_docker_group` (`docker_group`: the
    group is equivalent to root), `unregister_distro` (`distro_removal`: data
    loss) and, on Linux only, `install_nvidia_toolkit` (`engine_restart`: the
    Docker Engine of the host is restarted and every container on it stops,
    CR-72) each need a separate explicit acknowledgement. An acknowledgement
    belongs to a kind or to one platform of a kind
    (`platforms.<platform>.acknowledgement`). GUI: a control per
    acknowledgement and per licence, unchecked by default. CLI:
    `--accept-license <id>` per licence, `--accept-docker-group`,
    `--accept-distro-removal`, `--accept-engine-restart`; `--yes` replaces
    none of them.
14. **Consent requires all terms (CR-20).** The `user_consent` effect
    `set_consented_plan_id` checks `terms_accepted`: every
    `required_licence_ids` accepted and every `required_acknowledgements` given
    (both derived from the plan). Otherwise consent stays unset
    (CONSENT_REQUIRED; non-interactive `sprut setup apply --plan-id X --yes`
    without them exits 4). Vectors: `test-vectors/effects/`.
15. **What the user sees (SEC-D1).** The consent screen and
    `sprut setup plan` (text and `--json`) show, per step, the title and every
    typed member: `source.url` and `source.sha256`, `wslconfig` values together
    with the `wslconfig_file.replaced` values they overwrite, `distro_disk_size`,
    `distro` (name, path, disk size), `image` with its digest, `target_user`;
    plus each licence with its URL, the flags, `estimated_bytes` and
    `disk_estimate_bytes`. Nothing that is hashed is hidden.
16. **Distribution removal (SEC-C2, CR-27, SEC-1).** `unregister_distro` is
    immediately followed by `import_distro` (`UNPAIRED_UNREGISTER`). Before
    `wsl --unregister` runs, the executor performs `download_source` and
    `verify_source` of that following `import_distro` step; the precondition
    `replacement_source_verified` then compares the hash of the verified copy
    with `source.sha256` of that step. If the rootfs cannot be downloaded
    (SOURCE_UNAVAILABLE) or its hash differs (INTEGRITY_MISMATCH), the
    operation ends FAILED and nothing is removed. The verified copy is kept
    until the import has ended, and `import_distro` uses exactly that copy:
    it hashes it again (`source_verified`) and never downloads after the
    removal. An export/backup option before removal is planned.
17. **Docker access (SEC-C1).** Linux plans state `docker_access`
    (`DOCKER_ACCESS_MISMATCH` if missing, or present on Windows).
    `docker_group`: the plan contains `add_user_to_docker_group` unless the
    user is already a member. `none`: no group step; Sprut never runs engine
    operations through `sudo` by itself, so bootstrap stops at ENGINE_CHECK in
    ACTION_REQUIRED with ENGINE_PERMISSION_DENIED until the user grants access
    themselves. The user chooses before consent; each choice is its own plan.
18. **`.wslconfig` binding (CR03).** `write_wslconfig` carries
    `wslconfig_file`: `replaced` names only keys this step writes and is empty
    when the file is absent (`WSLCONFIG_REPLACED_MISMATCH`). Values not set by
    Sprut are therefore inside `plan_id`.
19. **Titles** are exactly the registry template (`TITLE_MISMATCH`); the only
    placeholder is `{repository}`. The template is `platforms.<platform>.title`
    when the kind has one for the plan's platform, otherwise `title` (or
    `title_without_source`, rule 9). **A title discloses what the step stops
    (CR-80):** `install_wsl` and `update_wsl` say that running WSL
    distributions may be stopped, `restart_wsl` that all are stopped,
    `configure_distro` and `resize_distro_disk` that the Sprut distribution is
    stopped after its tasks are drained, `install_nvidia_toolkit` that Docker
    Engine is restarted (on Linux: all containers of the computer stop),
    `unregister_distro` that the data inside is lost.
20. **Disk.** `disk_estimate_bytes` = sum of `estimated_bytes`
    (`DISK_ESTIMATE_MISMATCH`); free space is checked before INSTALLING
    (INSUFFICIENT_DISK).
21. **Execution.** Every step executed in INSTALLING (and the pull in
    IMAGE_PULL) is obtained by id from the plan document whose `object_hash`
    equals `consented_plan_id`. Right before a step runs, its preconditions are
    evaluated against freshly observed facts (section 4). Steps are idempotent
    and re-verified after a restart; the journal never replaces a probe.
22. **Ownership** (`docs/images-and-ownership.md`): a resource that exists but
    is not Sprut's is `FOREIGN_RESOURCE` and nothing is changed.

## 4. Execution preconditions

| Precondition | Reads (observed) | Fails with → next state |
|---|---|---|
| `source_verified` | `downloaded_sha256`, `staged_sha256` (in-distribution copies) | INTEGRITY_MISMATCH → FAILED |
| `ubuntu_supported` | `ubuntu_codename`, `architecture` | UNSUPPORTED_PROFILE → FAILED |
| `target_user_current` | `process_user` | PLAN_STALE → PROBING |
| `distro_owned` | `registered_distro` | PLAN_STALE → PROBING (not registered), FOREIGN_RESOURCE → ACTION_REQUIRED |
| `wslconfig_unchanged` | `wslconfig_sha256` | PLAN_STALE → PROBING |
| `wsl_restart_confirmed` | `sprut_drained`, `wsl_restart_confirmed`, `running_distributions` (`restart_wsl`), `registered_distributions` (`install_wsl`, `update_wsl`) | WSL_RESTART_REQUIRED → ACTION_REQUIRED |
| `sprut_drained` | `sprut_drained` | DRAIN_TIMEOUT → ACTION_REQUIRED |
| `replacement_source_verified` | `replacement_downloaded_sha256`, and `source.sha256` of the next step | SOURCE_UNAVAILABLE → FAILED (no verified copy), INTEGRITY_MISMATCH → FAILED |

Preconditions are evaluated in the order the kind lists them; the first one
that fails gives the reason code, and the step's commands are not run. Missing
facts fail.

**Steps that stop WSL distributions.** Plan consent alone never stops them.

- `restart_wsl` (CR04). `wsl --shutdown` stops every distribution of the
  user; it is a separate confirmed action. Right before the step the client
  drains Sprut tasks, reads the running distributions and asks in a dialog
  that lists them. `running_distributions` is that list. If it cannot be
  read, the fact is absent, no dialog is shown and the step is not run (fail
  closed). The confirmation is needed also when the list is empty.
- `install_wsl`, `update_wsl` (SEC-5). Installing the WSL package and
  `wsl --update` can stop every running distribution, so these steps get the
  same separate confirmation, before the UAC prompt.
  `registered_distributions` is the list of registered distributions, read
  from the per-user WSL registration
  (`HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss`), which is readable
  also while WSL is not installed; an absent key is an empty list, a read
  error means "cannot be read".
  - No distribution of the current user is registered: the precondition
    holds without a dialog and without a drain. The registration is per
    user, so the client cannot see distributions of other users of the same
    computer; whether installing or updating WSL stops them is part of the
    S−1 check below.
  - At least one is registered: the drain and the confirmation are required,
    in a dialog that lists the registered distributions.
  - The list cannot be read: fail closed, WSL_RESTART_REQUIRED →
    ACTION_REQUIRED.

  Which distributions `wsl --update` and the WSL package really stop on the
  accepted Windows builds, including those of another signed-in user on a
  multi-user computer, is verified on a real host at **S−1**; until then this
  rule applies.
- `configure_distro`, `resize_distro_disk` (`wsl --terminate`) and
  `unregister_distro` stop only the Sprut distribution and need
  `sprut_drained` (CR-49): the client stopped accepting tasks, the tasks
  finished or were stopped per policy, and the release of resources was
  verified. The fact is true in particular when the Sprut distribution is
  not registered or not running. When it is not true the step is not run:
  DRAIN_TIMEOUT → ACTION_REQUIRED.
  For the WSL-wide kinds above the drain is part of `wsl_restart_confirmed`
  and a missing drain is WSL_RESTART_REQUIRED, as in 0.2.0.
- `install_nvidia_toolkit` restarts Docker Engine and needs `sprut_drained`
  on both platforms (CR-72); on Linux also the `engine_restart`
  acknowledgement (rule 13).

`tools/validate.py` checks that every kind whose template stops the Sprut
distribution (`wsl.exe --terminate`, `--unregister`, `--shutdown`,
`--install`, `--update`, or the WSL package installer) or stops or restarts
`docker.service` has a precondition that reads `sprut_drained`, that a kind
which stops or restarts `docker.service` on Linux has the `engine_restart`
acknowledgement, and that `--resize` is preceded by `--terminate`.

## 5. Guard inputs derived from a plan

| Guard input | From the plan |
|---|---|
| `plan_id` | `object_hash` recomputed from the document |
| `plan_action_count` | number of `steps[]` |
| `step` (elevation) | `{id, in_consented_plan, privileged}` by looking up `id` in the consented plan |
| `consented_image_references` | ImageReferences of the consented plan's `image_pull` steps |
| `required_licence_ids` | ids of `licences[]` |
| `required_acknowledgements` | acknowledgements of the steps' kinds on the plan's platform: the kind's `acknowledgement`, or `platforms.<platform>.acknowledgement` per platform |

Valid vectors carry these as `derived` (plus `privileged_step_ids` and
`windows_elevated_steps`).

## 6. Reason codes

- `PLAN_INVALID` (exit 1): a plan document fails this contract; never shown or
  executed.
- `INTEGRITY_MISMATCH`, `UNSUPPORTED_PROFILE`, `PLAN_STALE`, `FOREIGN_RESOURCE`,
  `WSL_RESTART_REQUIRED`, `DRAIN_TIMEOUT`, `SOURCE_UNAVAILABLE`: execution
  preconditions (section 4).
- `SOURCE_UNAVAILABLE`, `INSUFFICIENT_DISK`, `LOCAL_STORAGE_FAILED`,
  `PACKAGE_INSTALL_FAILED`, `STEP_FAILED`, `WSL_COMMAND_FAILED`,
  `PLAN_INVALID` (a plan refused by the elevated helper),
  `ELEVATED_STEP_FAILED`, `ELEVATION_UNAVAILABLE`, `SMOKE_TEST_FAILED`,
  `ENGINE_DOCKER_DESKTOP`, `ENGINE_COMMAND_FAILED`, `PROBE_FAILED`: failures
  while a step or a bootstrap check is executed (section 8).

## 7. Validation order and error categories

The reference checks in this order and reports the first failure:

1. Parsing with the hashing restrictions (`docs/canonical-json.md` 5).
2. `object_hash` input: `INVALID_JSON` (not an object), `INVALID_KIND`,
   `INVALID_HASH_MEMBER`.
3. `SCHEMA_VIOLATION`.
4. `HASH_MISMATCH`.
5. `STATE_NOT_ON_PLATFORM`, `DUPLICATE_IMAGE`, `DUPLICATE_LICENCE`.
6. Per step, in order: `DUPLICATE_STEP_ID`, `UNKNOWN_STEP_KIND`,
   `STEP_NOT_ON_PLATFORM`, `PRIVILEGE_MISMATCH`, `FLAG_MISMATCH`,
   `STEP_MEMBER_NOT_ALLOWED` / `STEP_MEMBER_MISSING`, `SOURCE_NOT_OFFICIAL`,
   `IMAGE_NOT_LISTED`, `DUPLICATE_PULL`, `TITLE_MISMATCH`, `LICENCE_UNKNOWN`,
   `LICENCE_MISSING`, `UNPAIRED_UNREGISTER`, `WSLCONFIG_REPLACED_MISMATCH`.
7. `DOCKER_ACCESS_MISMATCH`.
8. `DISK_ESTIMATE_MISMATCH`.

The user-facing reason code is `PLAN_INVALID`. Each invalid vector contains
exactly one violation, so tests do not depend on the order.

## 8. Step failures (CR-45)

Preconditions (section 4) and guards are evaluated before a command runs. A
**failure** is what happens while a command of a step, or a check of a
bootstrap state outside plan steps, is executed. `registry/step-failures.json`
gives every failure class exactly one outcome and lists, per step kind and
platform and per state, the classes that can occur; `test-vectors/step-failures/`
has a case for each of them and cases for how the class is chosen. Both
clients use this table and nothing else.

**A failure is never reported with a reason code that describes another
condition.** In particular: a command that could not run is not
WSL_DISTRO_BROKEN, a failed engine command is not ENGINE_DAEMON_STOPPED or
SMOKE_TEST_FAILED, a failed elevated step is not PRIVILEGE_REQUIRED,
WSL_MISSING or WSL_OUTDATED, a failed `apt-get install` is not
SOURCE_UNAVAILABLE, a file the client could not write is not
INSUFFICIENT_DISK unless the disk is known to be full, a Docker Desktop
engine is not ENGINE_REMOTE_CONTEXT, and a check that could not be performed
is not STEP_FAILED.

### 8.1. Failure classes

| Class | Reason code | Next state | Event |
|---|---|---|---|
| `source_unavailable` | SOURCE_UNAVAILABLE | FAILED | error |
| `insufficient_disk` | INSUFFICIENT_DISK | ACTION_REQUIRED | error |
| `local_storage_failed` | LOCAL_STORAGE_FAILED | ACTION_REQUIRED | error |
| `package_install_failed` | PACKAGE_INSTALL_FAILED | FAILED | error |
| `wsl_command_failed` | WSL_COMMAND_FAILED | FAILED | error |
| `command_failed` | STEP_FAILED | FAILED | error |
| `plan_refused` | PLAN_INVALID | FAILED | error |
| `elevation_unavailable` | ELEVATION_UNAVAILABLE | ACTION_REQUIRED | error |
| `elevated_step_failed` | ELEVATED_STEP_FAILED | FAILED | error |
| `smoke_test_failed` | SMOKE_TEST_FAILED | FAILED | error |
| `engine_docker_desktop` | ENGINE_DOCKER_DESKTOP | ACTION_REQUIRED | error |
| `engine_command_failed` | ENGINE_COMMAND_FAILED | FAILED | error |
| `probe_failed` | PROBE_FAILED | FAILED | error |

The registry holds the full criterion of each class; section 8.2 is the same
rule as a procedure.

### 8.2. Choosing the class

The class is decided by which command failed and how it ended, never by
parsing free-text output. `classify_result` in `tools/validate.py` is the
reference; `classification_cases` in the vectors fix it.

**How a command ends.**

- A command that starts a process ends in exactly one way: *not started* (the
  process could not be created), *timed out* (it did not exit within the
  command's timeout and is killed), or *exited* with an exit status.
- **Through `wsl.exe` (Windows).** Every program of an unprivileged step and
  every probe inside the Sprut distribution runs as
  `wsl.exe ... --exec <program>`. A Linux program exits with 0–255. An exit
  status outside 0–255, read as a signed or unsigned 32-bit value, is an
  error of `wsl.exe` itself and not a result of the program: measured on a
  real host, an unknown distribution gives -1 (4294967295). A status in
  1–255 is taken as the program's result; a program that does not exist
  inside the distribution gives 1 and cannot be told apart from a program
  that exits 1.
- **Behind `sudo` (Linux).** Privileges are established before the step by a
  separate sudo credential check that runs no command of the step. If it is
  refused or cannot ask, that is PRIVILEGE_REQUIRED through the guard
  `privilege_granted`, not a failure class. After it, the commands run
  through `/usr/bin/sudo --` and the rules below apply to the program behind
  sudo.
- **Probes** are the read-only commands of PROBING, ENGINE_CHECK and
  SMOKE_TEST. A probe answers either by its output or by its exit status.
  Only two probes answer by exit status: `/usr/bin/test -x /usr/bin/docker`
  (is the Docker CLI installed) and
  `/usr/bin/systemctl is-active --quiet docker.service` (is the daemon
  active). Their answer can only lead to a non-destructive plan
  (`apt_add_docker_repo` and `install_docker_engine`, or `start_engine`); it
  never decides that a distribution is broken and never leads to a step that
  removes or stops anything. Every other probe (os-release, architecture,
  init process, resources, listening sockets) answers by its output. A status
  of such a probe in 1–255, whatever its value (1, 2, 3, 4, 127, 255), means
  only "not present" or "not active"; it is never evidence that a
  distribution is broken.
- **Order of the engine probes (CR-82).** Whenever the Docker CLI is present
  (`test -x` answered 0), the client reads the engine's identity before it
  uses the answer of `systemctl is-active`:
  1. the identity was read and it is Docker Desktop:
     `engine_docker_desktop`, whatever the state of `docker.service`. With
     the Docker Desktop WSL integration the CLI reaches Docker Desktop's
     engine while `docker.service` of the distribution is inactive or
     absent, so the plan is never just `start_engine` there;
  2. the identity was read and it is not Docker Desktop: the engine answers,
     and the `is-active` answer is not needed for this decision;
  3. the identity could not be read and `is-active` answers "not active":
     the daemon is stopped. This is the positive evidence of
     ENGINE_DAEMON_STOPPED; in PROBING it leads to a plan with
     `start_engine`, after which ENGINE_CHECK reads the identity again;
  4. the identity could not be read and `is-active` answers "active", or
     gave no answer: `engine_command_failed`.

**The rules, in this order:**

1. **Step privileged on Windows.** The elevated helper runs it and reports
   its own outcome (section 9):

   | Helper | Result |
   |---|---|
   | cannot be started | `elevation_unavailable` |
   | UAC prompt declined, or outcome `declined` | CANCELLED, no reason code (CR-73) |
   | `failed` with PLAN_INVALID | `plan_refused` |
   | `failed` with SOURCE_UNAVAILABLE | `source_unavailable` |
   | `failed` with INTEGRITY_MISMATCH | precondition `source_verified` → FAILED |
   | `failed` with ELEVATED_STEP_FAILED, or no result | `elevated_step_failed` |
   | `completed` | the step is done; `reboot_required` is taken from the result |

   Privileges that cannot be asked for at all (no interactive session) leave
   the operation in WAITING_FOR_PRIVILEGE with PRIVILEGE_REQUIRED.
2. **The client's own files** (the staged download of `download_source`, the
   rootfs copy, a verified copy made by the client). The system reported a
   full disk (Windows ERROR_DISK_FULL or ERROR_HANDLE_DISK_FULL, Linux ENOSPC
   or EDQUOT): `insufficient_disk`. Any other error while creating, writing,
   flushing, renaming or reading back the file (access denied, I/O error):
   `local_storage_failed`.
3. **`download_source` failed otherwise** (network, HTTP status, TLS or
   certificate, a redirect or size refused by rule 10, timeout):
   `source_unavailable`.
4. **Docker Engine command** (an Engine API request or a `docker` CLI call),
   on both platforms and whatever starts it:
   - the engine's identity was read and it is Docker Desktop:
     `engine_docker_desktop` (`docs/images-and-ownership.md` section 3),
     before and regardless of the `systemctl is-active` answer; an identity
     that could not be read while `is-active` answers "not active" is a
     stopped daemon, not a failure (order of the engine probes, above);
   - the diagnostic container exited with a non-zero status:
     `smoke_test_failed`; the wait for it reached the smoke-test timeout and
     the inspect that follows shows it still running: `smoke_test_failed`;
     that inspect gives no answer: `engine_command_failed`;
   - the pull of an `image_pull` step: with the CLI a non-zero exit status in
     1–255 is `source_unavailable`, a pull that was not started, timed out or
     ended outside 0–255 is `engine_command_failed`; with the Engine API an
     error in the progress stream of an accepted request is
     `source_unavailable`, an error of the request itself is
     `engine_command_failed`;
   - any other engine command that was not started, timed out, exited
     non-zero or returned a request error: `engine_command_failed`, unless
     there is positive evidence of ENGINE_CLI_MISSING, ENGINE_DAEMON_STOPPED
     (for example the service manager reports the daemon inactive),
     ENGINE_PERMISSION_DENIED or ENGINE_WRONG_MODE; those codes keep their
     meaning.
5. **A read of the host API that starts no process** (Windows registry and
   system information, files) failed: `probe_failed`.
6. **Windows, any other process** (all of them go through `wsl.exe`): not
   started, timed out, or an exit status outside 0–255: `wsl_command_failed`.
7. **Linux, any other process** that was not started or timed out: a probe is
   `probe_failed`, a step command `command_failed`.
8. **A probe that exited with a status in 0–255.** A probe that answers by
   its exit status has answered. A probe that answers by its output has
   answered only if it exited 0 with complete, well-formed output; a
   non-zero status or incomplete output is no answer: `wsl_command_failed`
   on Windows, `probe_failed` on Linux, and never evidence of anything.
9. **A step command that exited with a status in 1–255:**
   `/usr/bin/apt-get update` is `source_unavailable`,
   `/usr/bin/apt-get install` is `package_install_failed`, any other program
   or `install_file` is `command_failed`.
10. **A client action that failed otherwise** (for example an I/O error while
    writing `.wslconfig`): `command_failed`.

Unchanged and more specific: a `.wslconfig` that changed after the
precondition is PLAN_STALE → PROBING, a conflict in it WSL_CONFIG_CONFLICT →
ACTION_REQUIRED, a resource that is not Sprut's FOREIGN_RESOURCE →
ACTION_REQUIRED (rule 22).

### 8.3. Classes per step kind

The lists follow from the command templates (`expected_step_failures` in
`tools/validate.py` derives them and compares). The last class of each list is
the catch-all, so every failure of a step has an outcome.

| Kind | Windows | Linux |
|---|---|---|
| `enable_wsl_features`, `enable_vm_platform` | `plan_refused`, `elevation_unavailable`, `elevated_step_failed` | – |
| `install_wsl`, `update_wsl` | `source_unavailable`, `plan_refused`, `elevation_unavailable`, `elevated_step_failed` | – |
| `unregister_distro`, `configure_distro`, `resize_distro_disk`, `restart_wsl` | `wsl_command_failed`, `command_failed` | – |
| `import_distro` | `source_unavailable`, `insufficient_disk`, `local_storage_failed`, `wsl_command_failed`, `command_failed` | – |
| `apt_add_docker_repo` | `source_unavailable`, `insufficient_disk`, `local_storage_failed`, `wsl_command_failed`, `command_failed` | `source_unavailable`, `insufficient_disk`, `local_storage_failed`, `command_failed` |
| `install_docker_engine` | `package_install_failed`, `wsl_command_failed`, `command_failed` | `package_install_failed`, `command_failed` |
| `install_nvidia_toolkit` | `source_unavailable`, `insufficient_disk`, `local_storage_failed`, `package_install_failed`, `wsl_command_failed`, `command_failed` | `source_unavailable`, `insufficient_disk`, `local_storage_failed`, `package_install_failed`, `command_failed` |
| `start_engine` | `wsl_command_failed`, `command_failed` | `command_failed` |
| `add_user_to_docker_group` | – | `command_failed` |
| `write_wslconfig` | `command_failed` | – |
| `image_pull` | `source_unavailable`, `engine_command_failed` | `source_unavailable`, `engine_command_failed` |

The failure happens in INSTALLING (a privileged step: in
WAITING_FOR_PRIVILEGE or INSTALLING; `image_pull`: in IMAGE_PULL); the
transition to the next state exists from each of them. A step privileged on
Windows has no storage classes: the helper writes only its own protected
directory, and a failure there is `elevated_step_failed`.

### 8.4. Outside plan steps

| State | Windows | Linux |
|---|---|---|
| PROBING | `wsl_command_failed`, `engine_docker_desktop`, `engine_command_failed`, `probe_failed` | `engine_docker_desktop`, `engine_command_failed`, `probe_failed` |
| ENGINE_CHECK | `wsl_command_failed`, `engine_docker_desktop`, `engine_command_failed`, `probe_failed` | `engine_docker_desktop`, `engine_command_failed`, `probe_failed` |
| SMOKE_TEST | `wsl_command_failed`, `smoke_test_failed`, `engine_docker_desktop`, `engine_command_failed`, `probe_failed` | `smoke_test_failed`, `engine_docker_desktop`, `engine_command_failed`, `probe_failed` |

`probe_failed` is the catch-all of these states (CR-74): every check that
could not be performed and is neither an engine command nor, on Windows, a
process started through `wsl.exe`.

- **No plan from an incomplete probe.** Any of these classes in PROBING ends
  the operation without building a plan.
- **Positive evidence for WSL_DISTRO_BROKEN (CR-70).**
  `current_state.sprut_distro = broken`, and with it a plan that contains
  `unregister_distro`, needs one of exactly these:
  1. the registration of the distribution states a WSL version other than 2;
  2. the VHDX file of the distribution does not exist. Both facts are read
     from the registration and the file system, not from a command;
  3. a probe inside the distribution that answers by its output exited 0
     with complete, well-formed output that is not the expected answer (for
     example os-release names another distribution or release).

  Every other probe result — a status outside 0–255, a non-zero status, a
  timeout, incomplete output — is `wsl_command_failed` and never evidence.
  The two probes that answer by exit status never count as evidence either.
- **SMOKE_TEST.** SMOKE_TEST_FAILED is only the diagnostic container's own
  result. An engine command around it that fails (create, start, wait, logs,
  remove) is ENGINE_COMMAND_FAILED. In both cases the container is removed
  (`docs/images-and-ownership.md` section 5).
- **Docker Desktop.** `engine_docker_desktop` is checked wherever the engine
  is examined or about to be used: PROBING, ENGINE_CHECK and right before the
  container run in SMOKE_TEST.
- **Not a bootstrap failure:** SECRET_STORE_FAILED. The operation that needed
  the secret ends FAILED with it (`task` machine); the secret value is never
  logged.

## 9. Elevated helper (Windows)

Normative for the helper that runs the four elevated kinds (SEC-4, CR-59.5,
CR-73, CR-78). It is the only Sprut code that runs with administrator rights,
and it trusts nothing the unprivileged client can change after the user's
consent.

1. **Arguments.** Only the plan id, the step id and the path of the plan
   file. No URL, hash, kind, command or option comes from the command line,
   the environment or the caller.
2. **Plan path (CR-78).** The path is an absolute local path on a fixed
   drive (`X:\...`): not a UNC path, not a device-namespace path (`\\?\`,
   `\\.\`), not a relative path, not on a removable or network drive. The
   file is opened once, without following reparse points; it must be a
   regular file and not a reparse point (symbolic link, junction, mount
   point). Its size is checked on the opened handle before anything is read
   and must not exceed 1 MiB (`docs/canonical-json.md` 5). Anything else is
   refused (`plan_refused`).
3. **One read.** The helper reads the file into memory through that one
   handle and closes it. Everything that follows uses only that buffer; the
   file is never opened again, so replacing it after the check has no effect.
4. **Validation from the buffer.** Parse with the hashing restrictions,
   recompute `object_hash` and compare it with the plan id argument, validate
   the plan (section 7), look up the step id, and require a kind that is
   privileged on Windows and whose `windows_elevated_step` is one of the four
   operations. Anything else is refused (`plan_refused`, PLAN_INVALID) and
   nothing is run.
5. **Sources are constants of the helper.** For a step with `source`, the
   plan's `source.url` and `source.sha256` are compared with the constants
   compiled into the helper for that kind. They must be equal, otherwise the
   step is refused (`plan_refused`). The download (rule 10) and the hash
   check use the helper's constants, never the plan's values.
6. **Protected directory.** The helper downloads and verifies inside a
   directory it creates itself in an Administrators-only location, with a
   protected DACL: inheritance disabled, access only for Administrators and
   SYSTEM. A path that already exists with another owner or DACL, or that is
   a reparse point, is refused. The staging directory of the unprivileged
   client is never used. The verified copy is deleted when the step has
   ended, whether it succeeded or failed.
7. **Commands only on that copy.** `msiexec` and `dism` are started from
   `{system32}` with the fixed arguments of the registry; the only file
   argument is the verified copy in the protected directory
   (`{verified_file}`).
8. **Own prompt.** Before it changes anything, the helper shows in its own
   elevated window the step kind and the URL and SHA-256 it will use (or that
   `wsl.exe` downloads without verification by Sprut); for INSTALL_WSL and
   UPDATE_WSL also that running WSL distributions may be stopped. It
   continues only after the user confirms there. A refusal is the outcome
   `declined`, which the client treats like a declined UAC prompt: the
   operation goes to CANCELLED (CR-73).
9. **One step per start.** The helper runs the one step it was started for
   and exits.
10. **Result.** The helper reports `outcome` (`completed`, `declined`,
    `failed`); for `failed` a reason code — PLAN_INVALID, SOURCE_UNAVAILABLE,
    INTEGRITY_MISMATCH or ELEVATED_STEP_FAILED (section 8.2, rule 1); and
    `reboot_required` (boolean): true when Windows reports that the change
    takes effect only after a reboot (for example exit status 3010,
    ERROR_SUCCESS_REBOOT_REQUIRED, of `dism` or `msiexec`; that step is
    `completed`). The result contains no file contents, credentials or
    environment. A helper that cannot be started is ELEVATION_UNAVAILABLE; a
    helper that ends without a result is ELEVATED_STEP_FAILED.
11. **Reboot (CR-59.5).** `requires_reboot` of a plan step (`may` for the
    four elevated kinds) is the planner's forecast, shown to the user;
    `reboot_required` of the result is the fact. A reboot is pending when
    either is true. While a reboot is pending, no step whose own
    `requires_reboot` is false is started and the operation never goes on to
    ENGINE_CHECK: it moves INSTALLING → REBOOT_REQUIRED (exit code 5). The
    reboot is only offered (CF15); afterwards the operation resumes through
    PROBING.
