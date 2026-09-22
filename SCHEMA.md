# Submission schema

Every submission is one JSON file. One indicator (or one closely-related group, for app packages)
per file — small, independently-reviewable, and mergeable without fighting another contributor's
PR over the same file.

File naming: `<yyyy-mm-dd>-<short-slug>.json`, e.g. `2026-09-22-fake-parental-control-c2.json`.
The date is when you observed it, not when you're submitting — if those differ, use the observation
date.

## Categories

Must be exactly one of (matches `ThreatCategory` in the ENCLAY app — case-sensitive):

- `STALKERWARE_C2` — infrastructure a stalkerware/monitoring app phones home to
- `SPYWARE_C2` — infrastructure for spyware not specifically marketed as "monitoring" software
- `MALWARE_C2` — banking trojans, RATs, droppers, general malware C2
- `ADWARE_TRACKER` — ad/analytics/tracking infrastructure
- `PHISHING` — a confirmed-active phishing page's host
- `MINING_POOL` — cryptocurrency mining-pool infrastructure

Three categories exist in the app but are **not submittable here** because they're computed
locally, not intelligence: `USER_BLOCKED` (a user's own manual rule), `ENCRYPTED_DNS` (the app's
own DoH/DoT detection), `UNKNOWN` (internal fallback).

## Severities

Must be exactly one of: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

As a rough guide: `LOW` for ad/tracker infrastructure with no data-exfiltration capability,
`MEDIUM` for infrastructure that's part of a wider malicious campaign but not itself doing the
harm, `HIGH` for confirmed active C2/exfiltration/phishing, `CRITICAL` reserved for infrastructure
tied to confirmed, ongoing, high-impact campaigns (large-scale banking-trojan C2, active
stalkerware C2 currently receiving victim data). When in doubt, submit one level below what you're
tempted to pick — severity inflation makes the whole feed less trustworthy for everyone downstream.

## Domain submission

`submissions/domains/<file>.json`:

```json
{
  "domain": "c2.fake-parental-control.example",
  "matchSubdomains": true,
  "category": "STALKERWARE_C2",
  "severity": "HIGH",
  "dateObserved": "2026-09-20",
  "reportedBy": "your-github-username",
  "evidence": "One sentence: what you saw, and how you know it's this category. A link to a\nwrite-up, sandbox report, or your own analysis notes is stronger than a claim alone."
}
```

- `matchSubdomains: true` blocks the domain and everything under it — only use this when you have
  evidence the whole domain is dedicated malicious infrastructure, not just one subdomain. If
  you're only confident about the specific host you saw, set `matchSubdomains: false`.
- Don't submit a domain you haven't personally observed traffic to/from, or verified via a
  reputable second source (sandbox report, established threat-intel write-up). "This looks
  suspicious" is not evidence.

## IP / CIDR submission

`submissions/ips/<file>.json`:

```json
{
  "network": "172.64.0.0",
  "prefixLength": 24,
  "category": "MALWARE_C2",
  "severity": "MEDIUM",
  "dateObserved": "2026-09-20",
  "reportedBy": "your-github-username",
  "evidence": "..."
}
```

- `prefixLength` for a single IP is `32` (IPv4) or `128` (IPv6).
- Prefer the narrowest range you actually have evidence for. Blocking a whole `/16` because one
  `/32` inside it was bad will get the submission rejected — that's collateral damage against
  everything else in that range, likely including unrelated legitimate services.

## JA3 fingerprint submission

`submissions/ja3/<file>.json`:

```json
{
  "fingerprint": "51c64c77e60f3980eea90869b68c58a8",
  "category": "MALWARE_C2",
  "severity": "MEDIUM",
  "dateObserved": "2026-09-20",
  "reportedBy": "your-github-username",
  "evidence": "Which malware family/client this fingerprint belongs to, and your source (sandbox run, published research, etc.)."
}
```

- Must be the actual JA3 hash (32 lowercase hex characters) of a **client**'s TLS ClientHello, not
  a server fingerprint (that's JARM, below) and not the raw cipher-suite string.

## JARM fingerprint submission

`submissions/jarm/<file>.json`:

```json
{
  "jarmHash": "2ad2ad0002ad2ad00042d42d0000009ab3ee5c093d3f2e7b64f9edb0c1e6a0",
  "category": "MALWARE_C2",
  "severity": "MEDIUM",
  "dateObserved": "2026-09-20",
  "reportedBy": "your-github-username",
  "evidence": "The server this JARM belongs to, and how you obtained/confirmed it (a JARM scan you ran yourself against a known C2 listener, or a published one)."
}
```

- Must be the full 62-character JARM hash.

## App package submission (stalkerware / malware)

`submissions/apps/<file>.json` — one vendor per file, one or more packages:

```json
{
  "vendorLabel": "FakeParentalGuard",
  "category": "STALKERWARE_C2",
  "packages": [
    "com.fakeparentalguard.monitor"
  ],
  "signingCertificatesSha1": [
    "1C6E171D3A6E51947DF9E83946BB115ED4A41C6A"
  ],
  "dateObserved": "2026-09-20",
  "reportedBy": "your-github-username",
  "evidence": "Where you found this app (store listing URL if still up, or how you obtained the APK), and why it's stalkerware/malware rather than a legitimate monitoring/security tool."
}
```

- `category` here is either `STALKERWARE_C2` or `MALWARE_C2` — this feeds the app's installed-app
  scanner (package name + signing certificate matching), not the network-traffic feed. It's a
  coarser split than the app's own bundled seed database (which further subdivides into vendor
  categories like `COMMERCIAL_SPYWARE`/`WATCHWARE`/`PREMIUM_SMS_FRAUD`) — a maintainer assigns the
  finer category by hand when merging a reviewed submission into that database.
- `signingCertificatesSha1` is optional but strongly preferred — a package name alone is trivial
  for a vendor to evade by renaming; a signing certificate persists across renames far better.
  **Format: 40 uppercase hex characters, no colons or spaces** (e.g.
  `1C6E171D3A6E51947DF9E83946BB115ED4A41C6A`) — matching exactly how the app stores it. Get it with
  `keytool -printcert -jarfile app.apk` (then strip the colons and uppercase it) or
  `apksigner verify --print-certs app.apk` (SHA-1 digest line, same treatment).
- Parental-control and employee-monitoring apps are a genuinely contested category — some are
  legitimate when used with the device owner's knowledge and consent, and become stalkerware only
  when deployed covertly against someone without their knowledge. Use your judgment and say so
  explicitly in `evidence`; a maintainer will weigh it. When in doubt, open an issue with the
  `false-positive`/discussion template instead of a PR, so it can be discussed before it's merged.

## Fields common to every submission type

| Field | Required | Notes |
|---|---|---|
| `dateObserved` | yes | `YYYY-MM-DD`, when you personally observed/confirmed this |
| `reportedBy` | yes | Your GitHub username (for attribution/follow-up questions — this is already public via the PR itself) |
| `evidence` | yes | Free text. See per-type notes above. This is the single most important field for review — a submission with a weak or missing `evidence` field will be asked for more before merge |

None of these provenance fields end up in the published `feed/intel.json` — they're for review
only. The published feed stays bare, matching every other source ENCLAY's pipeline merges in.
