# InstallationPlan (CF12, CF13)

Status: normative for `schema_version` 1, from sprut-contracts 0.2.0. Files:
`schemas/installation-plan.schema.json` (structure),
`registry/plan-step-kinds.json` (closed step-kind vocabulary, preconditions and
command templates, validated by `schemas/plan-step-kinds.schema.json`),
`test-vectors/installation-plans/`, `test-vectors/step-preconditions/`,
`test-vectors/effects/` (conformance), `tools/validate.py` (`validate_plan`,
`evaluate_preconditions`, the reference).

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
| `install_wsl` | priv., helper `INSTALL_WSL` | – | `source` optional | reboot may | – | `source_verified` |
| `update_wsl` | priv., helper `UPDATE_WSL` | – | `source` optional | reboot may | – | `source_verified` |
| `unregister_distro` | not priv. | – | `distro` | – | ack. `distro_removal` | `distro_owned` |
| `import_distro` | not priv. | – | `source` | – | licence required | `source_verified` |
| `configure_distro` | not priv. | – | – | – | – | – |
| `apt_add_docker_repo` | not priv. | priv. | `source` (signing key) | – | – | `ubuntu_supported`, `source_verified` |
| `install_docker_engine` | not priv. | priv. | – | – | – | `ubuntu_supported` |
| `add_user_to_docker_group` | – | priv. | `target_user` | relogin always | ack. `docker_group` | `target_user_current` |
| `install_nvidia_toolkit` | not priv. | priv. | `source` (signing key) | – | – | `ubuntu_supported`, `source_verified` |
| `start_engine` | not priv. | priv. | – | – | – | – |
| `write_wslconfig` | not priv. | – | `wslconfig`, `wslconfig_file` | WSL restart always | – | `wslconfig_unchanged` |
| `resize_distro_disk` | not priv. | – | `distro_disk_size` | – | – | – |
| `restart_wsl` | not priv. | – | – | – | – | `wsl_restart_confirmed` |
| `image_pull` | not priv. | not priv. | `image` | – | – | (guards of IMAGE_PULL) |

The **elevated-step vocabulary** of the Windows UAC helper is exactly the four
kinds privileged on Windows (Java `ElevatedStep`). Source URL prefixes are in
the registry; all of them are provisional and confirmed at S−1 (Q10 for the
Ubuntu rootfs).

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
adds them to its fixed base environment (SEC-N4).

**Verified copies (SEC-N1).** A command never uses the downloaded file. Every
kind with a source runs `download_source` (into the client's staging
directory) and then `verify_source`, executed by the same principal as the
step's commands: root through `sudo` on Linux or inside the distribution, or
the elevated helper. `verify_source` copies the file into a directory only that
principal can write (Linux: `install -m 0600 -o root -g root` into a root-only
directory; helper: an Administrators-only directory), hashes that copy and
compares it with `source.sha256` (INTEGRITY_MISMATCH otherwise). Commands use
only `{verified_file}`, that copy; the validator rejects a template that uses
it without a preceding `verify_source`. The elevated helper runs only `{system32}` programs. apt signing keys
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
10. **Downloads (SEC-A2).** HTTPS only on every hop, certificate verification
    mandatory, at most 5 redirects, never a downgrade to `http`; the prefix
    check applies to the parsed final URL (scheme, host and path compared after
    parsing, not on the raw string). The file is written to a directory only
    the executing principal can write and its SHA-256 is checked before use
    (precondition `source_verified`, INTEGRITY_MISMATCH otherwise). For a
    privileged step this check is the `verify_source` operation of section 2,
    run by the elevated helper or as root on a root-owned copy, so the
    unprivileged client cannot swap the file after the check. The helper
    receives only the plan id and the step id and reads everything else from
    the plan document it re-hashes.
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
    group is equivalent to root) and `unregister_distro` (`distro_removal`:
    data loss) each need a separate explicit acknowledgement. GUI: a control
    per acknowledgement and per licence, unchecked by default. CLI:
    `--accept-license <id>` per licence, `--accept-docker-group`,
    `--accept-distro-removal`; `--yes` replaces none of them.
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
16. **Distribution removal (SEC-C2, CR-27).** `unregister_distro` is
    immediately followed by `import_distro` (`UNPAIRED_UNREGISTER`). An
    export/backup option before removal is planned.
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
    placeholder is `{repository}`.
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
| `source_verified` | `downloaded_sha256` | INTEGRITY_MISMATCH → FAILED |
| `ubuntu_supported` | `ubuntu_codename`, `architecture` | UNSUPPORTED_PROFILE → FAILED |
| `target_user_current` | `process_user` | PLAN_STALE → PROBING |
| `distro_owned` | `registered_distro` | PLAN_STALE → PROBING (not registered), FOREIGN_RESOURCE → ACTION_REQUIRED |
| `wslconfig_unchanged` | `wslconfig_sha256` | PLAN_STALE → PROBING |
| `wsl_restart_confirmed` | `sprut_drained`, `wsl_restart_confirmed` | WSL_RESTART_REQUIRED → ACTION_REQUIRED |

`wsl_restart_confirmed` implements CR04: `wsl --shutdown` is a separate
confirmed action. Plan consent never restarts WSL; right before the step, after
the drain, the user confirms in a dialog that lists the running WSL
distributions. Missing facts fail.

## 5. Guard inputs derived from a plan

| Guard input | From the plan |
|---|---|
| `plan_id` | `object_hash` recomputed from the document |
| `plan_action_count` | number of `steps[]` |
| `step` (elevation) | `{id, in_consented_plan, privileged}` by looking up `id` in the consented plan |
| `consented_image_references` | ImageReferences of the consented plan's `image_pull` steps |
| `required_licence_ids` | ids of `licences[]` |
| `required_acknowledgements` | acknowledgements of the steps' kinds |

Valid vectors carry these as `derived` (plus `privileged_step_ids` and
`windows_elevated_steps`).

## 6. Reason codes

- `PLAN_INVALID` (exit 1): a plan document fails this contract; never shown or
  executed.
- `INTEGRITY_MISMATCH`, `UNSUPPORTED_PROFILE`, `PLAN_STALE`, `FOREIGN_RESOURCE`,
  `WSL_RESTART_REQUIRED`: execution preconditions (section 4).

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
