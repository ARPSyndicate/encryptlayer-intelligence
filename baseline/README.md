# Baseline

The established-source dataset ENCLAY already ships with and already trusts — everything the
crowdsourcing pipeline in [`../submissions/`](../submissions/)/[`../feed/`](../feed/) is meant to
*supplement*, not replace. Published here so the full picture (not just new community reports) is
public.

| File | What it is | Size |
|---|---|---|
| `network_feed.json.gz` | The real merged output of the same aggregation this project's main app pipeline runs — same `ThreatFeedDto` shape as `../feed/intel.json`. 1,377,031 domain entries, 79,193 IP networks, 97 JA3 fingerprints and 2,372 JARM fingerprints. Gzipped (12 MB) because uncompressed it's ~155 MB, over GitHub's per-file limit; decompress with `gunzip -k network_feed.json.gz`. |
| `stalkerware_packages.json` | The real bundled stalkerware vendor/package/signing-certificate database, as shipped. |
| `malware_packages.json` | The real bundled banking-trojan/RAT/dropper package database. Smaller and explicitly a floor set, not comprehensive — see the file's own `_comment` field for why (most modern families use per-campaign randomized package names, so a stable list doesn't meaningfully exist for them). |
| `domain_categories.json` | Domain → category (CLOUD, ANALYTICS, CDN, etc.) reference data — not a block list, used for classification/display rather than enforcement. |

## Staleness

This is a snapshot, not a live feed — check this file's last commit date. It's refreshed
periodically by re-running the aggregation tooling (kept local-only, not published here — see the
top-level README's note on why), not automatically. Each refresh is a full rebuild, so entry counts
move between snapshots in both directions. If you notice it's gone stale, that's useful
feedback: open an issue.

## License

Same as the rest of this repository's data — [CC BY 4.0](../LICENSE-DATA). These files are
aggregated here as a derived work over publicly available threat-intelligence data.
