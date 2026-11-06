# Images, allowlist and ownership (CF20–CF23)

Status: normative from sprut-contracts 0.2.0. Files:
`schemas/image-reference.schema.json`, `schemas/image-allowlist.schema.json`,
`registry/image-allowlist.json`, `schemas/ownership.schema.json`,
`registry/ownership.json`, `test-vectors/image-allowlist/`,
`test-vectors/ownership/`.

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
   refused with IMAGE_NOT_ALLOWED. 0.2.0 ships it empty because no worker
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
