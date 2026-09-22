# Contributing

## Before you submit

1. Read [SCHEMA.md](SCHEMA.md) for the exact format of whichever indicator type you're submitting.
2. Check the file doesn't already exist — search `submissions/` and `feed/intel.json` for the
   domain/IP/fingerprint/package name first. A duplicate submission just costs a reviewer time.
3. Have real evidence. See below.

## How to submit

**Preferred: a pull request.**

1. Fork this repo.
2. Add one new JSON file under the matching `submissions/<type>/` directory. Copy the
   closest template from [`examples/`](examples/) as a starting point.
3. Open a PR. CI runs `scripts/validate_submission.py` automatically and comments on the PR if
   anything's wrong (bad JSON, wrong category/severity, malformed domain/IP/fingerprint, missing
   required field, or a hard-blocked entry — see below).
4. A maintainer reviews the evidence and either merges, asks a follow-up question, or closes with
   a reason. Merged submissions get folded into `feed/intel.json` automatically on merge.

**If you can't/don't want to use git:** open an issue with the "Report an indicator" template
instead. It asks for the same fields; a maintainer (or another contributor) will turn it into a PR.

## What makes a submission mergeable

The single biggest reason a submission gets rejected isn't a formatting mistake — it's evidence a
maintainer can't independently verify. Good evidence looks like one of:

- You captured the traffic yourself (a packet capture, a Frida/mitmproxy trace, ENCLAY's own Live
  Feed/Sandbox screen) and can describe what you saw.
- A reputable second source already published this (a sandbox report — Any.Run, Joe Sandbox,
  VirusTotal community notes, Hybrid Analysis — or a named security researcher's/vendor's
  write-up). Link it.
- For app packages: the app is still on a store listing (link it) or you have the APK and can
  describe its behavior, and ideally its signing certificate.

Evidence that will get a submission asked to be redone or closed:

- "This looks suspicious" / "I have a feeling about this" with nothing else.
- A domain pulled from a random blocklist you found online, with no independent verification —
  that blocklist should be proposed as its own source in ENCLAY's main aggregator instead (see
  the `android/antispyware/tools/aggregate_threat_feed.py` source list in the main ENCLAY repo),
  not laundered through here one domain at a time.
- Anything you can't actually explain if a maintainer asks a follow-up question.

## What doesn't belong here

- **Personal disputes.** A domain someone you're in conflict with runs is not "infrastructure"
  just because you want it blocked. If it's genuinely malicious, the evidence should stand on its
  own without needing to mention who you're upset with.
- **PII about a specific individual.** Don't include someone's real name, address, phone number,
  or other personal details in an `evidence` field, a filename, or anywhere else in a submission —
  even if it's relevant context, summarize it without it. This repo is public and permanent.
- **Unverified claims** — see above.
- **Competitor products.** Submitting a competing app or service as "spyware" because you compete
  with it, rather than because it's actually deceptive/covert surveillance software, will be
  rejected and likely gets you blocked from further contributions.
- **Legitimate infrastructure a stalkerware app merely uses.** A stalkerware app's C2 domain
  belongs here. The cloud provider hosting it (AWS, a CDN, Firebase) does not — that's shared
  infrastructure millions of legitimate apps also use; blocking it has enormous collateral damage
  for approximately zero benefit (the stalkerware vendor just gets a new address on the same
  provider). Submit the actual dedicated domain/IP, not its landlord.
- **Contested parental-control/employee-monitoring apps without discussion first.** See the note
  in [SCHEMA.md](SCHEMA.md#app-package-submission-stalkerware--malware) — open an issue, not a PR,
  for these.
- **Anything requiring you to have done something illegal to obtain it** (e.g. unauthorized
  access to a system you don't own or have permission to test). Evidence obtained that way won't
  be merged regardless of how good the indicator itself is.

## Style / format notes

- One indicator (or one vendor's app packages) per file. Don't batch unrelated indicators into one
  PR/file — it makes partial review and partial rejection impossible.
- Valid JSON, UTF-8, no trailing commas, no comments (CI will reject non-strict JSON).
- Filenames: `YYYY-MM-DD-short-slug.json`, lowercase, hyphens not spaces/underscores.

## After merge

Merging a PR here does not immediately change what ENCLAY blocks on anyone's phone. It updates
`feed/intel.json` in this repo, which is the input to ENCLAY's own aggregation pipeline (merged
alongside its other inputs the same way every one of them is) — see that pipeline's own release
cadence for when it actually reaches the app.
