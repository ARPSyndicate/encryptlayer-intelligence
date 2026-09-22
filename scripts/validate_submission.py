#!/usr/bin/env python3
"""
validate_submission.py -- validates every JSON file under submissions/<type>/ against the schema
documented in SCHEMA.md, and checks for duplicates against the rest of the submission set plus the
already-published feed/intel.json. Stdlib only, matching the main ENCLAY repo's aggregator script
(android/antispyware/tools/aggregate_threat_feed.py) so this needs no dependency-install step in CI.

Usage:
    scripts/validate_submission.py                 # validate every submission file
    scripts/validate_submission.py path/to/one.json path/to/another.json
                                                     # validate only the given files (CI uses this
                                                     # on a PR to check just the changed files, but
                                                     # duplicate-checking still runs against the
                                                     # full set so a PR can't collide with something
                                                     # already merged)

Exit code 0 if everything given is valid, 1 otherwise -- errors are printed to stderr, one per
line, prefixed with the offending file path so they're easy to spot in CI output or a PR comment.
"""
from __future__ import annotations

import ipaddress
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
SUBMISSIONS_DIR = REPO_ROOT / "submissions"
FEED_PATH = REPO_ROOT / "feed" / "intel.json"

# Matches ThreatCategory.kt in the main ENCLAY app. USER_BLOCKED/ENCRYPTED_DNS/UNKNOWN are computed
# locally by the app itself and deliberately excluded -- see SCHEMA.md.
SUBMITTABLE_CATEGORIES = {
    "STALKERWARE_C2",
    "SPYWARE_C2",
    "MALWARE_C2",
    "ADWARE_TRACKER",
    "PHISHING",
    "MINING_POOL",
}
# App-package submissions feed the installed-app scanner, not the network feed -- only these two
# categories are meaningful there (see SCHEMA.md's app-package section).
APP_CATEGORIES = {"STALKERWARE_C2", "MALWARE_C2"}

SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
JA3_RE = re.compile(r"^[0-9a-f]{32}$")
JARM_RE = re.compile(r"^[0-9a-f]{62}$")
# Matches StalkerwareCertificateEntity/MalwareAppCertificateEntity.certificateSha1 exactly:
# uppercase hex, no colons/spaces (40 chars = 20 bytes of SHA-1).
SHA1_HEX_RE = re.compile(r"^[0-9A-F]{40}$")
# Reverse-DNS Android package name: at least two dot-separated segments, each starting with a
# letter or underscore. Deliberately conservative (matches what the Android build tooling itself
# accepts for applicationId) rather than trying to allow every technically-legal edge case.
PACKAGE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$")
# A hostname label: 1-63 chars, alphanumeric/hyphen, no leading/trailing hyphen. The full domain is
# one or more labels joined by dots, with a bare TLD label at the end (no dot-per-label length
# limit enforced beyond the overall 253-char cap -- that's DNS's own rule, checked separately).
LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")

REQUIRED_COMMON_FIELDS = ("dateObserved", "reportedBy", "evidence")

# A small, deliberately narrow safety net mirroring KNOWN_LEGITIMATE_APEX_DOMAINS in the main
# ENCLAY repo's aggregate_threat_feed.py -- bare bones here on purpose. This is NOT meant to be an
# exhaustive allowlist (that would give a false sense of safety); it exists to hard-reject the most
# obviously-wrong submissions (a typo, a prank, someone testing the pipeline) before they ever reach
# a human reviewer. Everything else is caught by review, not by this list.
HARD_PROTECTED_APEX_DOMAINS = {
    "google.com", "youtube.com", "android.com", "gstatic.com", "googleapis.com",
    "apple.com", "icloud.com",
    "microsoft.com", "windows.com", "live.com", "office.com",
    "amazon.com", "cloudflare.com", "akamai.com", "fastly.net",
    "facebook.com", "instagram.com", "whatsapp.com",
    "mozilla.org", "wikipedia.org",
    "github.com", "encryptlayer.net",
}


class ValidationError(Exception):
    pass


@dataclass
class Finding:
    path: Path
    message: str

    def __str__(self) -> str:
        try:
            rel = self.path.relative_to(REPO_ROOT)
        except ValueError:
            rel = self.path
        return f"{rel}: {self.message}"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def require_str_field(entry: dict, field: str) -> str:
    value = entry.get(field)
    require(isinstance(value, str) and value.strip() != "", f"'{field}' must be a non-empty string")
    return value


def validate_common_fields(entry: dict) -> None:
    for field in REQUIRED_COMMON_FIELDS:
        require_str_field(entry, field)
    date_observed = entry["dateObserved"]
    require(bool(DATE_RE.match(date_observed)), "'dateObserved' must be YYYY-MM-DD")
    require(
        len(entry["evidence"].strip()) >= 20,
        "'evidence' is too short to be useful for review -- explain what you saw and how you "
        "confirmed it (see CONTRIBUTING.md)",
    )


def validate_category(entry: dict, allowed: set[str]) -> None:
    category = require_str_field(entry, "category")
    require(
        category in allowed,
        f"'category' must be one of {sorted(allowed)}, got {category!r}",
    )


def validate_severity(entry: dict) -> None:
    severity = require_str_field(entry, "severity")
    require(severity in SEVERITIES, f"'severity' must be one of {sorted(SEVERITIES)}, got {severity!r}")


def validate_domain_syntax(domain: str) -> None:
    require(len(domain) <= 253, "domain exceeds 253 characters")
    require("." in domain, "domain must have at least two labels (e.g. 'example.com', not 'example')")
    labels = domain.split(".")
    for label in labels:
        require(bool(LABEL_RE.match(label)), f"'{domain}' has an invalid DNS label: {label!r}")


def validate_domain_entry(entry: dict, path: Path) -> None:
    domain = require_str_field(entry, "domain").lower()
    validate_domain_syntax(domain)
    require(
        domain not in HARD_PROTECTED_APEX_DOMAINS,
        f"'{domain}' is on the hard-protected apex list and cannot be submitted here -- if you "
        f"believe this is a genuine false negative, open an issue to discuss it instead of a PR",
    )
    require(isinstance(entry.get("matchSubdomains"), bool), "'matchSubdomains' must be true or false")
    validate_category(entry, SUBMITTABLE_CATEGORIES)
    validate_severity(entry)
    validate_common_fields(entry)


def validate_ip_entry(entry: dict, path: Path) -> None:
    network = require_str_field(entry, "network")
    prefix_length = entry.get("prefixLength")
    require(isinstance(prefix_length, int) and not isinstance(prefix_length, bool), "'prefixLength' must be an integer")
    try:
        parsed = ipaddress.ip_network(f"{network}/{prefix_length}", strict=True)
    except ValueError as exc:
        raise ValidationError(
            f"invalid network/prefixLength combination ({network}/{prefix_length}): {exc}. "
            f"'network' must be the network address itself, not a host address inside it -- e.g. "
            f"203.0.113.0/24, not 203.0.113.7/24."
        ) from None
    require(
        not parsed.is_private and not parsed.is_loopback and not parsed.is_link_local,
        f"'{network}/{prefix_length}' is a private/loopback/link-local range and cannot be a "
        f"public threat-intel entry",
    )
    validate_category(entry, SUBMITTABLE_CATEGORIES)
    validate_severity(entry)
    validate_common_fields(entry)


def validate_ja3_entry(entry: dict, path: Path) -> None:
    fingerprint = require_str_field(entry, "fingerprint").lower()
    require(bool(JA3_RE.match(fingerprint)), "'fingerprint' must be a 32-character lowercase hex JA3 hash")
    validate_category(entry, SUBMITTABLE_CATEGORIES)
    validate_severity(entry)
    validate_common_fields(entry)


def validate_jarm_entry(entry: dict, path: Path) -> None:
    jarm_hash = require_str_field(entry, "jarmHash").lower()
    require(bool(JARM_RE.match(jarm_hash)), "'jarmHash' must be a 62-character lowercase hex JARM hash")
    validate_category(entry, SUBMITTABLE_CATEGORIES)
    validate_severity(entry)
    validate_common_fields(entry)


def validate_app_entry(entry: dict, path: Path) -> None:
    require_str_field(entry, "vendorLabel")
    validate_category(entry, APP_CATEGORIES)
    packages = entry.get("packages")
    require(isinstance(packages, list) and len(packages) > 0, "'packages' must be a non-empty list")
    for pkg in packages:
        require(isinstance(pkg, str), "every entry in 'packages' must be a string")
        require(bool(PACKAGE_NAME_RE.match(pkg)), f"'{pkg}' is not a valid Android package name")
    certs = entry.get("signingCertificatesSha1")
    if certs is not None:
        require(isinstance(certs, list), "'signingCertificatesSha1' must be a list if present")
        for cert in certs:
            require(isinstance(cert, str), "every entry in 'signingCertificatesSha1' must be a string")
            require(
                bool(SHA1_HEX_RE.match(cert)),
                f"'{cert}' is not a valid signing certificate SHA-1 -- expected 40 uppercase hex "
                f"characters, no colons or spaces (e.g. 1C6E171D3A6E51947DF9E83946BB115ED4A41C6A)",
            )
    validate_common_fields(entry)


VALIDATORS = {
    "domains": validate_domain_entry,
    "ips": validate_ip_entry,
    "ja3": validate_ja3_entry,
    "jarm": validate_jarm_entry,
    "apps": validate_app_entry,
}


def submission_type_for(path: Path) -> str | None:
    try:
        rel = path.relative_to(SUBMISSIONS_DIR)
    except ValueError:
        return None
    if len(rel.parts) < 2:
        return None
    return rel.parts[0]


def load_json(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValidationError(f"could not read file: {exc}") from None
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid JSON: {exc}") from None


def validate_file(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    submission_type = submission_type_for(path)
    if submission_type is None or submission_type not in VALIDATORS:
        findings.append(Finding(path, "not inside a recognized submissions/<type>/ directory"))
        return findings
    try:
        data = load_json(path)
    except ValidationError as exc:
        findings.append(Finding(path, str(exc)))
        return findings
    if not isinstance(data, dict):
        findings.append(Finding(path, "top level of the file must be a JSON object"))
        return findings
    try:
        VALIDATORS[submission_type](data, path)
    except ValidationError as exc:
        findings.append(Finding(path, str(exc)))
    return findings


def indicator_key(submission_type: str, entry: dict) -> tuple:
    """A tuple identifying "the same indicator" for duplicate detection, independent of filename,
    evidence text, or reporter -- two submissions with the same key are reporting the same thing."""
    if submission_type == "domains":
        return ("domain", str(entry.get("domain", "")).lower())
    if submission_type == "ips":
        return ("ip", str(entry.get("network", "")).lower(), entry.get("prefixLength"))
    if submission_type == "ja3":
        return ("ja3", str(entry.get("fingerprint", "")).lower())
    if submission_type == "jarm":
        return ("jarm", str(entry.get("jarmHash", "")).lower())
    if submission_type == "apps":
        packages = entry.get("packages")
        if isinstance(packages, list):
            return ("apps", tuple(sorted(str(p).lower() for p in packages)))
        return ("apps", ())
    return ("unknown",)


def find_all_submission_files() -> list[Path]:
    files: list[Path] = []
    if not SUBMISSIONS_DIR.is_dir():
        return files
    for type_dir in sorted(SUBMISSIONS_DIR.iterdir()):
        if not type_dir.is_dir():
            continue
        for f in sorted(type_dir.glob("*.json")):
            files.append(f)
    return files


def check_duplicates(target_files: list[Path]) -> list[Finding]:
    """Checks every file in target_files for a duplicate indicator anywhere else in the submission
    set (any other pending file, regardless of whether it's also being validated this run)."""
    findings: list[Finding] = []
    all_files = find_all_submission_files()
    seen: dict[tuple, Path] = {}
    for f in all_files:
        submission_type = submission_type_for(f)
        if submission_type not in VALIDATORS:
            continue
        try:
            data = load_json(f)
        except ValidationError:
            continue  # already reported as a validation error if this file was in target_files
        if not isinstance(data, dict):
            continue
        key = indicator_key(submission_type, data)
        if key in seen and seen[key] != f:
            if f in target_files or seen[key] in target_files:
                findings.append(
                    Finding(f, f"duplicate indicator, already submitted in {seen[key].relative_to(REPO_ROOT)}")
                )
        else:
            seen[key] = f
    return findings


def main(argv: list[str]) -> int:
    if argv:
        target_files = [Path(a).resolve() for a in argv]
        for f in target_files:
            if not f.is_file():
                print(f"error: {f} does not exist", file=sys.stderr)
                return 1
    else:
        target_files = find_all_submission_files()

    if not target_files:
        print("no submission files to validate")
        return 0

    all_findings: list[Finding] = []
    for f in target_files:
        all_findings.extend(validate_file(f))
    all_findings.extend(check_duplicates(target_files))

    if all_findings:
        print(f"{len(all_findings)} problem(s) found:\n", file=sys.stderr)
        for finding in all_findings:
            print(f"  - {finding}", file=sys.stderr)
        return 1

    print(f"{len(target_files)} submission file(s) valid, no duplicates found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
