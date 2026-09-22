# ENCLAY Intelligence

Community-submitted threat intelligence for [ENCLAY](https://encryptlayer.net) — an on-device
Android firewall that blocks stalkerware, spyware, banking trojans, and malware infrastructure by
IP, domain, and TLS fingerprint.

This repository is the crowdsourced half of ENCLAY's threat feed. Most of what ENCLAY blocks comes
from established public threat-intelligence feeds, merged automatically by the app's own
pipeline. Those feeds are broad but slow to pick up something new — a stalkerware
vendor's C2 domain that just went live, a banking-trojan APK that just started circulating, a JA3
fingerprint from a C2 framework nobody's cataloged yet. That gap is what this repo exists to close:
anyone who spots one of these can submit it here, in the open, with the evidence that convinced
them.

## How it fits together

```
you spot something  -->  open a PR here  -->  CI validates the submission
                                                        |
                                                        v
                                          a maintainer reviews & merges
                                                        |
                                                        v
                          feed/intel.json is rebuilt (same shape ENCLAY already fetches)
                                                        |
                                                        v
                                   picked up by ENCLAY's own aggregation pipeline
```

Submissions here don't go straight to a running app — they go through review, the same way any of
the established feeds do. Nothing merged into `feed/intel.json` is silently trusted; it's reviewed
against the same categories and severities ENCLAY's own aggregator uses, so it slots in without a
schema mismatch.

## Two datasets, not one

- **[`baseline/`](baseline/)** — the established-source dataset ENCLAY already ships with,
  already merged into the same shape as the app's own feed, plus the real bundled
  stalkerware/malware package databases. This is "all existing
  intelligence," made public rather than kept behind the app. It's a periodic snapshot (see
  [`baseline/README.md`](baseline/README.md) for what's in it and how stale it might be), not
  something submissions PRs touch.
- **[`submissions/`](submissions/) → [`feed/`](feed/)** — the crowdsourcing loop this README is
  mostly about: new reports, reviewed and merged one PR at a time.

The tooling that *produces* `baseline/` (the actual crawler/aggregator scripts — source-specific
parsers, rate-limit handling, retry logic) is deliberately **not** published here, even though its
output is. That's a judgment call about what's worth open-sourcing (the data, so anyone can use or
audit it) versus what reveals more about how the collection itself works than is useful to publish.
The published data is the deliverable; the collection pipeline behind it is not described here.

## What you can submit

| Type | What it means | Where |
|---|---|---|
| Domain | A hostname serving C2, tracking, phishing, or mining-pool infrastructure | `submissions/domains/` |
| IP / CIDR | A network range hosting the same | `submissions/ips/` |
| JA3 fingerprint | A TLS *client* fingerprint (observed in a ClientHello) belonging to known-bad client software | `submissions/ja3/` |
| JARM fingerprint | A TLS *server* fingerprint belonging to a C2 listener or malicious server | `submissions/jarm/` |
| App package | A stalkerware/spyware/banking-trojan Android app's package name (+ signing certificate, if you have it) | `submissions/apps/` |

Read [CONTRIBUTING.md](CONTRIBUTING.md) before your first submission — it covers the exact format,
what evidence to include, and what gets rejected on sight (this is a security-sensitive dataset;
low-effort or unverifiable submissions cost reviewer time other contributors are waiting on).

## What you should NOT submit

See [CONTRIBUTING.md § What doesn't belong here](CONTRIBUTING.md#what-doesnt-belong-here) — in
short: no personal disputes, no submitting a domain because you dislike it rather than because it's
actually malicious infrastructure, no PII about a specific person, no unverified claims. This repo
is public and permanent; treat every submission like the evidence you'd want to see if someone
submitted a domain *you* run.

## License

All intelligence data (everything under `submissions/`, `examples/`, `feed/`, and `baseline/`) is
released under [CC BY 4.0](LICENSE-DATA). Scripts and CI workflows are [MIT](LICENSE).
