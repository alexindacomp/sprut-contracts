# WSL resources (Windows, CR01–CR07)

Status: normative from sprut-contracts 0.2.0. Files:
`schemas/wsl-resources.schema.json`, `test-vectors/wsl-resources/cases.json`.
Sprut Desktop only; the Linux client has no WSL.

## 1. Managed values

| Member | Where it is applied | Format |
|---|---|---|
| `wsl2.memory` | `.wslconfig` `[wsl2] memory` | positive whole number + `MB` or `GB` (`8GB`) |
| `wsl2.processors` | `.wslconfig` `[wsl2] processors` | integer 1–1024 |
| `wsl2.swap` | `.wslconfig` `[wsl2] swap` | `0` (no swap) or positive whole number + `MB`/`GB` |
| `wsl2.networkingMode` | `.wslconfig` `[wsl2] networkingMode` | only `nat`; `mirrored` (node mode) is planned and refused until S2 decides Q14 |
| `sprut_distro.max_disk_size` | WSL tooling for the Sprut distribution only | positive whole number + `GB` or `TB` |

Members under `wsl2` are the literal `.wslconfig` key names, and values are
written exactly as given (`memory=8GB`). No other key is managed;
`defaultVhdSize` and every other key, section and comment of the file are
left byte for byte. An absent member is left unchanged; a value is removed only
by restoring the backup.

**No defaults.** Recommended values are an open question (spec Q15). The
contract defines formats and ranges only; a client never fills in a value the
user did not choose or confirm.

In an InstallationPlan, `write_wslconfig` carries the `wsl2` values as
`wslconfig`, plus `wslconfig_file` (the SHA-256 of the current file, or
`absent`, and the current text of the managed keys it overwrites), and
`resize_distro_disk` carries `distro_disk_size`; all are hashed and consented
with the plan. A current value is shown as text; if it cannot be represented
(control or invisible characters, more than 256 code points) the probe reports
WSL_CONFIG_CONFLICT naming that key, no plan is built and the operation is
ACTION_REQUIRED until the user fixes the file (CR-29; vectors
`current_value_cases`). Before writing, the client re-hashes the file (precondition
`wslconfig_unchanged`); a changed file is PLAN_STALE and the user is asked
again.

## 2. Rules

1. **Only managed keys** (CR02). Writes change only the keys above in
   `[wsl2]`; everything else is preserved byte for byte.
2. **Backup and atomic write** (CR02, CR07). Before every change a backup is
   created in the client's state directory with create-new (never overwrite);
   the write compares the file hash read earlier, writes a temporary file,
   flushes it and renames atomically. A file changed in between is re-read and
   the user asked again.
3. **Global effect** (CR03). `.wslconfig` applies to all WSL2 distributions of
   the user; this is shown before saving. Existing values not set by Sprut are
   shown, and replacing them needs confirmation (WSL_CONFIG_CONFLICT until
   then).
4. **Restart only with confirmation** (CR04). New VM values take effect after
   `wsl --shutdown`, which stops all distributions. The plan step
   `restart_wsl` runs only after a drain of Sprut tasks and a separate
   confirmation given right before it, in a dialog that lists the running WSL
   distributions (precondition `wsl_restart_confirmed`); plan consent alone
   never restarts WSL. Without it the state is WSL_RESTART_REQUIRED
   (ACTION_REQUIRED).
5. **Verify** (CR05). After the restart the effective memory and CPU count are
   read inside the Sprut distribution and used as the budget (CF24); a
   difference from the configured values is a warning with a reason.
6. **Consistent limits** (CR06). Task and model limits never exceed the VM
   resources with a 20% reserve; lowering resources below current limits
   offers to lower the limits or cancel (WSL_RESOURCES_INSUFFICIENT).
7. **Reset** (CR07). "Reset to pre-Sprut values" restores the managed keys from
   the backup; uninstall offers it (CF92).
