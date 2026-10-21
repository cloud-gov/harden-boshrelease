---
title: "Adopt Ubuntu Security Guide (usg) STIG baseline in harden-boshrelease, audit-first"
status: "accepted"
date: "2026-08-11"
decision_makers: ["Robert Gottlieb"]
category: "Deployment and Infrastructure"
nist_controls: ["CM-2", "CM-6", "CM-7", "RA-5", "SA-11", "SI-2"]
impact_level: "moderate"
ato_relevance: "yes-internal"
risk_treatment: "mitigate"
---

# Adopt Ubuntu Security Guide (usg) STIG baseline in harden-boshrelease, audit-first

## Context and Problem Statement

The `harden` job in `cloud-gov/harden-boshrelease` (deployed as release
`fisma-jammy`) currently applies a hand-rolled CIS-style hardening baseline via a
shell script (`jobs/harden/templates/bin/post-deploy`). As part of the Jammy -> Noble
(Ubuntu 24.04) migration, the team wants to move from the bespoke CIS scripting to
Canonical's **Ubuntu Security Guide (`usg`)** using a **DISA STIG** baseline, and to
wire up `usg audit` (and later `usg fix`) in the release. This decision records that
direction and how it is sequenced against the Nessus acceptance requirement
("scans must show the same or fewer findings").

## Decision Drivers

- Co-worker / repo owner direction: move from CIS scripting to STIG via `usg`.
- Ticket requirement: Noble hardened hosts must produce **same-or-fewer Nessus
  findings** than the Jammy baseline (RA-5).
- Maintainability: replace fragile hand-rolled controls with Canonical-maintained,
  versioned compliance content (CM-2, CM-6).
- Safety: avoid changing the security posture and the finding surface in the same
  step that introduces new tooling (audit-first).
- Environment constraints: hardening runs inside a **Garden container**
  (`0::/init.scope`), not the outer VM; usg requires Ubuntu Pro attach + enable.

## Considered Options

1. **World A — runtime `pro attach` + `pro enable usg` + `usg audit` at post-deploy.**
   The release attaches each instance to Ubuntu Pro (token supplied via a job
   property/CredHub), enables the `usg` service (installs the `usg` package from the
   Pro/esm mirror), and runs `usg audit stig-v1r1`. Proven feasible in the spike.
2. **World B — vendor `usg` + the STIG datastream as a release blob (offline).**
   No per-instance Pro attach or per-deploy egress; the release ships the tooling
   and content. More robust and reproducible, but more work and does not use the
   token workflow the co-worker set up.
3. **Keep hand-rolled CIS scripting**, port it to Noble paths only (no usg). Rejected
   — does not meet the STIG direction and keeps the fragile bespoke baseline.

## Decision Outcome

Chosen option: **World A (runtime `pro attach` + `pro enable usg` + `usg audit`),
audit-first**, because the spike proved it works in the container and it uses the
Pro token workflow already established in the release. Adoption is **phased**:

- **Increment 0 (spike) — DONE.** In-container feasibility confirmed on the Noble
  stemcell: `pro status` shows `usg AVAILABLE: yes`; egress to
  `contracts.canonical.com` (HTTP 404 to `/` = reachable) and DNS for `esm.ubuntu.com`
  resolve (IPv6); after enable, `usg` at `/usr/sbin/usg`; `usg list` shows STIG
  profile **`stig-v1r1`** (STIG/ubuntu2404 V1R1) plus CIS profiles; `usg audit`
  runs and emits an HTML report + stdout/stderr.
- **Increment 1 — audit-only (this decision's near-term scope).** Add `pro attach`
  (idempotent) + `pro enable usg` + **`usg audit stig-v1r1`** (report-only, NO fix)
  to `post-deploy` on the `noble-main` branch. Report written to a collectable path
  under `/var/vcap/sys/log/harden/`. Because audit-only does not remediate, the
  hardened posture is unchanged from the CIS baseline, so the differential Nessus
  scan should be **unchanged** — an easy pass and a safe first step.
- **Increment 2 — remediation (LATER, separate ticket, blocked on Increment 1).**
  Introduce `usg fix stig-v1r1`, then reconcile/remove the hand-rolled CIS blocks
  that STIG now covers. This is where findings actually move; the Nessus criterion
  becomes "STIG-hardened findings, same-or-fewer, no new Critical/High vs the CIS
  baseline." Requires its own differential scan.

### Correct usg CLI (confirmed on the spike)

Profile is a **positional argument**; there is **no `--profile` flag** in this usg
version. Profile name is **`stig-v1r1`**.

```bash
usg audit stig-v1r1            # report-only (Increment 1)
usg fix   stig-v1r1            # remediate  (Increment 2, later)
usg generate-fix stig-v1r1 fix.sh
```

### Positive Consequences

- Canonical-maintained, versioned STIG content replaces bespoke scripting.
- Audit-first adds STIG visibility with zero posture change — safe, reversible.
- Feasibility de-risked before any real testing (spike done, egress confirmed).

### Negative Consequences

- **Per-instance Pro attach**: every hardened Garden container attaches to Ubuntu
  Pro, counting against the subscription. Fleet-scale license impact must be
  confirmed with the license owner (token is in hand; fleet-use approval to verify).
- **Per-deploy egress dependency** on `contracts.canonical.com` and the Pro/esm
  mirror; fragile in locked-down environments. World B remains the more robust
  long-term design if this becomes a problem.
- Runtime `apt`/`pro enable` at post-deploy is not fully reproducible (violates the
  pin/vendor-dependencies principle) — revisit World B for Increment 2+.
- STIG baseline differs from CIS: the finding set will change at Increment 2, so the
  Nessus acceptance criterion must be re-agreed for that increment.

### Compliance Consequences

- CM-2 / CM-6: baseline configuration source changes from bespoke script to
  usg/STIG content — update configuration baseline docs.
- RA-5: Nessus differential-scan acceptance criterion applies per increment;
  Increment 1 expected no-change, Increment 2 re-baselined to STIG.
- SI-2 / SA-11: remediation (Increment 2) and audit reporting feed flaw remediation
  and developer testing evidence.
- Pro token MUST be a job property sourced from CredHub, never hardcoded in
  `post-deploy` (secrets handling).
- ATO: the hardening baseline change (CIS -> STIG) is ATO-internal; ISSO should
  review the STIG posture and the Nessus differential evidence.

## Links

- Repo: https://github.com/cloud-gov/harden-boshrelease (branch `jammy-main`;
  target new branch `noble-main`, release `fisma-noble`)
- Migration record: `bosh_release_process.md` (this folder) — fisma-jammy section
- Nessus differential-scan procedure: `bosh_release_process.md`
- Ubuntu Security Guide / usg (STIG profile `stig-v1r1`, STIG/ubuntu2404 V1R1)
