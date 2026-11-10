# Security

This repository decides what Sprut clients may run and change on users'
machines: the image allowlist, the InstallationPlan step kinds and their command
templates, consent and guard rules. Changes here are security changes.

## Reporting

Report a vulnerability privately to the repository owner through GitHub
security advisories ("Report a vulnerability" on the Security tab). Do not open
a public issue for it.

## Repository protection (required before the first non-empty allowlist)

- `CODEOWNERS` covering `registry/`, `schemas/`, `proto/`, `tools/`,
  `.github/`, `SECURITY.md` and `CODEOWNERS` itself.
  `tools/validate.py` fails on a non-empty `registry/image-allowlist.json`
  while `CODEOWNERS` is missing.
- Branch protection on `master`: pull requests only, code-owner review, the
  `validate` check required, no force pushes.
- Release tags `vMAJOR.MINOR.PATCH` are signed; clients pin only signed tags,
  and moving a client's submodule pin is reviewed by a human.
- The run profile of the image's purpose is normative and has fixed limits in
  `registry/run-profiles.json` (worker and inference profiles need their own
  security review), and for a diagnostic image the diagnostic image protocol
  (CR-57) is part of these contracts. `tools/validate.py` fails on an
  allowlist entry whose purpose has no such profile.

## Release checklist

1. `python3 tools/validate.py` and `python3 tools/validate.py --self-test` pass.
2. `VERSION` and `CHANGELOG.md` are updated; every item clients must copy is
   marked "Mirror".
3. Allowlist changes: each new entry names the image's source, purpose and
   build provenance in the pull request; a code owner reviews it.
4. New or changed step kinds, command templates, preconditions, source
   prefixes, redirect hosts, download limits, acknowledgements, titles (they
   are what the user consents to), failure classes, run profiles or pinned
   digests: security review in the pull request.
5. Branch protection is active and the tag is signed (`git tag -s`).
