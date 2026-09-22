#!/usr/bin/env python3
"""
build_feed.py -- merges every submission under submissions/<type>/ into the published outputs
under feed/. Run after PRs are merged (see .github/workflows/build-feed.yml); never run against
unreviewed submissions, since merging to main IS the review gate this repo relies on.

Outputs:
  feed/intel.json               -- domains/ips/ja3/jarm, in the exact ThreatFeedDto shape ENCLAY's
                                    ThreatFeedClient already fetches (feedVersion, generatedAt,
                                    ipEntries[], domainEntries[], ja3Entries[], jarmEntries[]). All
                                    provenance fields (dateObserved/reportedBy/evidence) are
                                    stripped -- the published feed stays bare, same as every
                                    upstream source aggregate_threat_feed.py merges in.
  feed/stalkerware_packages.json -- app submissions with category STALKERWARE_C2, grouped by
                                    vendorLabel, in the same vendorLabel/category/packages/
                                    certificates shape as the app's bundled
                                    seed_stalkerware_packages.json. NOTE: 'category' here is
                                    intentionally left as the coarse STALKERWARE_C2/MALWARE_C2 a
                                    contributor submitted, NOT the finer vendor-type taxonomy
                                    (COMMERCIAL_SPYWARE/WATCHWARE/...) the app's own bundled seed
                                    uses -- this file is a reviewed INPUT for a maintainer to merge
                                    into that seed by hand (assigning the finer category then),
                                    not something the app reads directly.
  feed/malware_packages.json    -- same, for category MALWARE_C2.

Stdlib only, matching validate_submission.py and the main ENCLAY repo's aggregator script.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
SUBMISSIONS_DIR = REPO_ROOT / "submissions"
FEED_DIR = REPO_ROOT / "feed"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from validate_submission import (  # noqa: E402
    find_all_submission_files,
    load_json,
    submission_type_for,
    validate_file,
)


def bare_entries(submission_type: str, fields: tuple[str, ...]) -> list[dict[str, Any]]:
    """Reads every valid file of the given type and projects it down to just `fields`, in file
    order (sorted by filename, so output is stable/deterministic across runs)."""
    entries: list[dict[str, Any]] = []
    type_dir = SUBMISSIONS_DIR / submission_type
    if not type_dir.is_dir():
        return entries
    for path in sorted(type_dir.glob("*.json")):
        if validate_file(path):
            # Should not happen if build only ever runs post-merge (validation already gated the
            # PR) -- skipped rather than aborting the whole build over one bad file, so a single
            # regression doesn't take down every other already-reviewed entry.
            print(f"warning: skipping invalid file at build time: {path}", file=sys.stderr)
            continue
        data = load_json(path)
        entries.append({f: data[f] for f in fields})
    return entries


def build_intel_feed() -> dict[str, Any]:
    return {
        "feedVersion": "1",
        "generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ipEntries": bare_entries("ips", ("network", "prefixLength", "category", "severity")),
        "domainEntries": bare_entries("domains", ("domain", "matchSubdomains", "category", "severity")),
        "ja3Entries": bare_entries("ja3", ("fingerprint", "category", "severity")),
        "jarmEntries": bare_entries("jarm", ("jarmHash", "category", "severity")),
    }


def build_app_packages(category: str) -> dict[str, Any]:
    """Groups every submissions/apps/*.json entry matching `category` by vendorLabel -- a vendor
    might get reported more than once, in separate PRs, each adding more packages/certificates for
    the same vendor rather than always being one-file-per-vendor forever."""
    by_vendor: dict[str, dict[str, Any]] = {}
    type_dir = SUBMISSIONS_DIR / "apps"
    if type_dir.is_dir():
        for path in sorted(type_dir.glob("*.json")):
            if validate_file(path):
                print(f"warning: skipping invalid file at build time: {path}", file=sys.stderr)
                continue
            data = load_json(path)
            if data.get("category") != category:
                continue
            vendor = data["vendorLabel"]
            bucket = by_vendor.setdefault(
                vendor, {"vendorLabel": vendor, "category": category, "packages": [], "certificates": []}
            )
            for pkg in data.get("packages", []):
                if pkg not in bucket["packages"]:
                    bucket["packages"].append(pkg)
            for cert in data.get("signingCertificatesSha1", []) or []:
                if cert not in bucket["certificates"]:
                    bucket["certificates"].append(cert)
    return {
        "_comment": (
            f"Community-submitted {category} app packages, reviewed and merged via GitHub PR "
            f"(see ../CONTRIBUTING.md). A reviewed INPUT for a maintainer to fold into the app's "
            f"bundled seed_{'stalkerware' if category == 'STALKERWARE_C2' else 'malware'}_"
            f"packages.json by hand, not consumed by the app directly."
        ),
        "entries": [by_vendor[v] for v in sorted(by_vendor)],
    }


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {path.relative_to(REPO_ROOT)}")


def main() -> int:
    # Refuse to build over any currently-invalid submission -- a maintainer merging a PR that CI
    # already approved shouldn't be able to accidentally rebuild the feed while an unrelated,
    # separately-added bad file sits in the tree; surface it instead of silently dropping it.
    all_files = find_all_submission_files()
    hard_errors = []
    for f in all_files:
        findings = validate_file(f)
        if findings:
            hard_errors.extend(findings)
    if hard_errors:
        print(f"refusing to build: {len(hard_errors)} submission file(s) currently fail validation:", file=sys.stderr)
        for finding in hard_errors:
            print(f"  - {finding}", file=sys.stderr)
        print(
            "\nfix or remove the offending file(s) (they should never have been merged past CI -- "
            "if they were, that's a bug in validate_submission.py's CI wiring worth reporting) "
            "before rebuilding.",
            file=sys.stderr,
        )
        return 1

    write_json(FEED_DIR / "intel.json", build_intel_feed())
    write_json(FEED_DIR / "stalkerware_packages.json", build_app_packages("STALKERWARE_C2"))
    write_json(FEED_DIR / "malware_packages.json", build_app_packages("MALWARE_C2"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
