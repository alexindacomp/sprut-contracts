# Images, allowlist and ownership (CF20–CF23)

Status: normative from sprut-contracts 0.2.0; section 5 (run profiles) from
0.3.0. Files:
`schemas/image-reference.schema.json`, `schemas/image-allowlist.schema.json`,
`registry/image-allowlist.json`, `schemas/ownership.schema.json`,
`registry/ownership.json`, `schemas/run-profiles.schema.json`,
`registry/run-profiles.json`, `test-vectors/image-allowlist/`,
`test-vectors/ownership/`, `test-vectors/run-profiles/`.

## 1. ImageDigest and ImageReference

- **ImageDigest**: `sha256:` followed by 64 lowercase hex digits
  (`^sha256:[0-9a-f]{64}$`). Compared as a string.
- **ImageReference**: `<repository>@<ImageDigest>`. No tag form, no
  `repo:tag@digest` form. The repository is fully qualified: a lowercase
  registry host with at least one dot and no port, then one or more lowercase
  path components (`ghcr.io/alexindacomp/sprut-worker`), at most 255
  characters. A short name such as `ubuntu` is refused, so no implicit Docker
  Hub resolution can apply.
- **Run only by digest, never pull implicitly.** Pulls use the ImageReference.
  Every run (smoke test, worker, diagnostic, inference) uses an explicit no-pull
  mode: `docker run --pull=never`, or with the Go SDK `ContainerCreate` on an
  image already present (the SDK never pulls on create). A missing image is
  PLAN_STALE and a re-plan that lists the pull as an action
  (`image_present_by_digest`), never a download.

The definitions are copied verbatim into the schemas that use them;
`tools/validate.py` checks the copies are identical.

## 2. Image allowlist

`registry/image-allowlist.json` (`kind: image_allowlist`) lists the images
Sprut may pull or run. Each entry: `repository`, `digest`, `purpose`
(`diagnostic`, `worker`, `inference`), `platform` (`linux/amd64`),
`min_client_version` and optional `max_client_version` (`MAJOR.MINOR.PATCH`,
inclusive).

1. **Bundled.** Each client embeds `registry/image-allowlist.json` from its
   pinned sprut-contracts submodule at build time (Java: resource generated
   from the submodule; Go: `//go:embed`). It is never fetched, replaced or
   extended at runtime, from configuration, from a task manifest or from the
   coordinator. `sprut --version` shows it (spec 7.5). A signed, updatable
   allowlist is a later stage and needs its own contract.
2. **Strict parsing.** Parse with the hashing restrictions, check
   `kind = image_allowlist`, the schema (unknown members rejected) and unique
   digests (`DUPLICATE_DIGEST`). An invalid bundled allowlist is a build
   failure; at runtime it means every image is refused.
3. **Fail closed.** An empty `entries` array is valid: every pull and run is
   refused with IMAGE_NOT_ALLOWED. 0.3.0 still ships it empty because no
   image is pinned yet.
4. **Guard input.** `allowlist` is the ImageReferences `<repository>@<digest>`
   of the entries with `min_client_version` <= client version <=
   `max_client_version` (when present), in document order. The guards
   `image_allowlisted` and `image_in_consented_plan` compare whole references,
   i.e. (repository, digest) pairs (SEC-m3, CR-30): the same digest under
   another repository is IMAGE_NOT_ALLOWED, or CONSENT_REQUIRED when only the
   consented plan names another repository. There is no separate digest input.
5. **Client version (CR-21).** The client version is the shared Sprut client
   release version: Sprut Desktop and the `sprut` CLI use one version line.
   Comparison is numeric on MAJOR, MINOR, PATCH; a pre-release client
   (`0.3.0-rc.1`) is lower than the release with the same numbers, and
   pre-release identifiers are not compared further. Removing an entry from
   the bundled list revokes the image for every client built from it.
6. **Repository.** A pull or run uses the entry's reference. A task manifest or
   user input can never supply an image, repository, tag, Dockerfile, mount,
   socket or `privileged` (CF21).
7. **Before the first non-empty allowlist (SEC-m4)** the repository must have
   CODEOWNERS for `registry/`, `schemas/`, `proto/`, `tools/`, `.github/`,
   branch protection on `master` with the `validate` check required, and
   signed release tags; clients pin only signed tags. `tools/validate.py`
   fails on a non-empty allowlist while `CODEOWNERS` is missing; the release
   checklist is in `SECURITY.md`.
8. **Run profile first (SEC-15).** An image is allowlisted only for a purpose
   whose run profile is normative and has fixed limits (section 5), and a
   diagnostic image only after the diagnostic image protocol is part of these
   contracts (CR-57, see README "Planned"). `tools/validate.py` fails on an
   entry whose purpose has no such profile.

## 3. Docker Engine endpoint (SEC-B1)

1. dockerd listens only on its local unix socket. `daemon.json` has no `hosts`
   entry with `tcp://` and dockerd runs without `-H tcp://...`; a Sprut-installed
   engine is configured this way, an existing one is checked, never changed.
2. The client determines the endpoint itself (never from `DOCKER_HOST` or a
   Docker context) and accepts only `unix://` paths; `tcp://` is refused even
   on loopback (`ENGINE_REMOTE_CONTEXT`).
3. ENGINE_CHECK fails on any TCP listener of dockerd (`ENGINE_TCP_EXPOSED`):
   the actual listening sockets of the dockerd process and of its socket units
   (for example `ListenStream=` of `docker.socket`), not only `hosts` in
   `daemon.json` and `-H` flags.
   Both are checked by the guard predicate `engine_endpoint_local` on
   ENGINE_CHECK → IMAGE_PULL and ENGINE_CHECK → SMOKE_TEST and lead to
   ACTION_REQUIRED (exit 3): the user fixes the engine configuration. The
   same check is repeated before every container or task run, not only in
   ENGINE_CHECK; a failure stops the run with the same reason code.
4. Containers never use `--network=host`; if a port is ever published, it binds
   `127.0.0.1` only. Programs are started by absolute path, never via `PATH`
   or a shell.
5. **Not Docker Desktop (CW06).** The engine Sprut uses is the Docker Engine
   of the Sprut distribution (Windows) or of the host (Linux), never Docker
   Desktop. The client reads the engine's identity: `OperatingSystem` of
   `docker info` (Engine API `GET /info`) and `Platform.Name` of
   `docker version` (`GET /version`). If `OperatingSystem` equals
   `Docker Desktop` or `Platform.Name` starts with `Docker Desktop`, the
   engine is refused with ENGINE_DOCKER_DESKTOP → ACTION_REQUIRED and nothing
   in it is changed. On Windows this is the case when the Docker Desktop WSL
   integration is enabled for the Sprut distribution; the next action is to
   disable it for that distribution. The check is made in PROBING and
   ENGINE_CHECK together with the endpoint check and, like it, repeated
   before every container or task run. Whenever the Docker CLI is present
   the identity is read before the state of `docker.service` is used, and a
   Docker Desktop answer wins whatever that state is. An identity that cannot
   be read is ENGINE_COMMAND_FAILED, not a verdict, unless the service
   manager reports the daemon inactive (then the daemon is stopped,
   `docs/installation-plan.md` section 8.2). This is the failure class
   `engine_docker_desktop` of `registry/step-failures.json`
   (`docs/installation-plan.md` section 8); the guard `engine_endpoint_local`
   is unchanged, and ENGINE_REMOTE_CONTEXT stays the code of an endpoint that
   is not a local unix socket.

## 4. Ownership labels

`registry/ownership.json` defines the label namespace
`io.github.alexindacomp.sprut` and the labels every container, volume and
network created by Sprut carries (CF22):

| Key | Required | Value | Ownership check |
|---|---|---|---|
| `io.github.alexindacomp.sprut.managed` | yes | `true` | equals `true` |
| `io.github.alexindacomp.sprut.profile` | yes | profile id, `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` | equals the current profile |
| `io.github.alexindacomp.sprut.operation_id` | no | operation id | not checked (diagnostics) |

Rules (the `rules` of the registry):

1. **Labels are a hint.** Anyone with engine access can set them. Before a
   stop, removal or change the client inspects the resource and checks the
   labels, and acts only on ids it recorded when it created the resource.
2. **Filter, never prune.** Listing, stop and cleanup filter by `managed` and
   `profile` in the engine and re-check with inspect. No global prune, no
   unfiltered operation.
3. **Reserved namespace.** Only the core sets keys in the namespace (the key
   equal to the namespace or starting with it plus `.`); extra labels from
   callers with such keys are refused.
4. **Charset.** Every label key and value, also of extra labels, matches
   `^[A-Za-z0-9._/:=@+-]{1,1024}$` (no spaces, quotes, backslashes, control or
   non-ASCII characters).
5. **Foreign resources.** If an operation needs to change a resource that
   exists but is not Sprut's (same name, no or other labels, another profile),
   nothing is changed and the operation reports `FOREIGN_RESOURCE`
   (exit code 1; in bootstrap the state is ACTION_REQUIRED, exit 3). Listing and
   cleanup skip foreign resources silently.
6. **WSL distribution (Windows).** A distribution is Sprut's only if it is
   registered under the Sprut name and its `BasePath` equals the Sprut
   directory under `%LOCALAPPDATA%\Sprut\wsl\`; `BasePath` is re-read before
   every changing call, otherwise `FOREIGN_RESOURCE`. User distributions and
   `docker-desktop*` are never changed.
7. **Adoption (SEC-m5).** An existing labelled container or volume is reused
   only if its id is in this profile's journal AND inspect shows an
   allowlisted image, no host bind mounts, not privileged and no Docker socket.
   A labelled resource that is not in the journal is never reused
   (`adoption_cases` in the vectors).
8. **Images** are not labelled. The client removes only images it pulled
   (digest recorded at pull time), by digest, and only if no container that is
   not Sprut's uses the image.

`test-vectors/ownership/cases.json` fixes the ownership decision and the
caller-label check.

## 5. Container run profiles (SEC-15)

`registry/run-profiles.json` fixes how a container is started, per image
purpose. A client never starts a container in another way.

| Profile | Status |
|---|---|
| `diagnostic` (smoke test, CF16) | normative, below |
| `worker`, `inference` | to be defined with their own security review; until then no container of that purpose is run and no image of that purpose is allowlisted |

The diagnostic container is started with exactly these options:

| `docker run` option | Engine API (Go SDK) | Purpose |
|---|---|---|
| `--pull=never` | `ContainerCreate` on a present image, no `ImagePull` | no download can bypass the IMAGE_PULL guard |
| `--network none` | `HostConfig.NetworkMode = "none"` | the diagnostic needs no network |
| `--cap-drop ALL` | `HostConfig.CapDrop = ["ALL"]` | no Linux capabilities |
| `--security-opt no-new-privileges` | `HostConfig.SecurityOpt = ["no-new-privileges"]` | no privilege gain through setuid programs |
| `--read-only` | `HostConfig.ReadonlyRootfs = true` | read-only root filesystem |
| `--pids-limit <n>` | `HostConfig.Resources.PidsLimit = n` | bounded number of processes |
| `--memory <limit>` | `HostConfig.Resources.Memory = limit` | bounded memory |

1. **Each option exactly once**, in the token form of the registry (CLI) or
   as the equivalent field (API). A repeated option, also with the same
   value (`--memory` twice, `--pids-limit` twice, `--pull=never` twice), is
   non-conforming, so that no later option can override an earlier one.
2. **Closed option set.** Besides these options a diagnostic run carries only
   `--detach`, `--name <name>` and `--label <key=value>` (the ownership labels
   of section 4 and accepted caller labels). Any other option makes the run
   non-conforming: no mount, device, added capability, other network, host
   namespace or privileged mode. With the Engine API every other `HostConfig`
   field keeps its zero value. An option the diagnostic protocol needs, for
   example the mount of its state volume, is added to the registry together
   with that protocol (CR-57), never by a client alone.
3. **Nothing after the image (CR-76).** No command and no argument follows
   the image reference: the image's own entrypoint runs. With the Engine API
   `Config` carries only `Image` and `Labels` until the diagnostic protocol
   (CR-57) says otherwise: no `Cmd`, `Entrypoint`, `Env`, `User`,
   `WorkingDir`, `Volumes` or `ExposedPorts`. CR-57 also has to decide
   `--user` (a non-root user), `--memory-swap` (no swap beyond the memory
   limit) and `--cpus`, which this profile does not set yet.
4. **Limits.** `<n>` is a positive integer; `<limit>` is a positive integer
   followed by `m` or `g`. Their values are fixed in the registry as `limits`
   together with the diagnostic image protocol; until then they are
   provisional client constants and no diagnostic image can be allowlisted
   (section 2, rule 8).
5. **Always removed.** The diagnostic container is removed after every run:
   after success, after a failed check, when the smoke-test timeout expires
   (it is stopped first) and when the operation is cancelled. A container
   that a crashed run left behind is removed on the next start, found by its
   recorded id and checked as in section 4. Removal is by that id, never by a
   filter alone. If the removal itself fails, the operation ends with
   ENGINE_COMMAND_FAILED (`docs/installation-plan.md` section 8) and the id
   stays in the journal for the next start.
6. The endpoint check and the Docker Desktop check of section 3 and the
   allowlist check precede every run.

`test-vectors/run-profiles/cases.json` fixes which option lists conform.
