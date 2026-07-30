# Security Policy

## Scope

`untrust` is a read-mostly auditing tool. It inspects cloud and host
configuration and, for a single check (`BOOTSTRAP-01`), writes and then deletes
canary objects in a bucket you explicitly target. It ships no exploit code and
no vendor-specific or proprietary information.

## Reporting a vulnerability

If you find a security issue in `untrust` itself — for example a check that
could be coerced into a destructive or unintended action, or a way the tool
leaks the credentials it runs with — please report it privately.

- Use GitHub's **Report a vulnerability** (Security → Advisories) on this
  repository, or
- Open a minimal issue asking for a private contact channel (do not include
  details in the public issue).

Please include:

- the version (`untrust --version`) and how it was invoked,
- the observed behavior and why it is a security concern,
- a minimal reproduction if possible.

We aim to acknowledge reports within 5 business days.

## Using `untrust` safely

- Run against infrastructure you are **authorized** to assess.
- Scope the `s3:PutObject` / `s3:DeleteObject` permissions used by
  `BOOTSTRAP-01` to a dedicated audit role and bucket.
- Use `--read-only` to skip intrusive checks (the write probe and all on-host
  SSM commands) when you only need a passive posture snapshot.

## Supported versions

The latest released `1.x` version receives security fixes.
