# Submissions

Add one new JSON file to the matching subdirectory here to submit an indicator. See
[../SCHEMA.md](../SCHEMA.md) for the exact format of each type and
[../CONTRIBUTING.md](../CONTRIBUTING.md) for the submission process and review criteria.

- `domains/` — hostnames
- `ips/` — IP addresses / CIDR ranges
- `ja3/` — TLS client fingerprints
- `jarm/` — TLS server fingerprints
- `apps/` — stalkerware/malware Android app package names (+ signing certificates)

Files here that have been merged (i.e. passed review) are folded into `../feed/` automatically —
see [`../.github/workflows/build-feed.yml`](../.github/workflows/build-feed.yml).
