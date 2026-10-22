---
title: "Add cracklib-runtime as a required harden dependency on Noble for pwquality dictcheck"
status: "accepted"
date: "2026-08-19"
decision_makers: ["Robert Gottlieb"]
category: "Deployment and Infrastructure"
nist_controls: ["IA-5", "CM-2", "CM-6", "CM-7", "SA-11", "SI-2"]
impact_level: "moderate"
ato_relevance: "yes-internal"
risk_treatment: "mitigate"
---

# Add cracklib-runtime as a required harden dependency on Noble for pwquality dictcheck

## Context and Problem Statement

During Increment 1 live testing of `cloud-gov/harden-boshrelease` on the Noble
(Ubuntu 24.04) stemcell, **every password change failed** — even `chpasswd` as
root — with:

```
chpasswd: pam_chauthtok() failed, error: Authentication token manipulation error
```

Root cause: the harden PAM stack runs `pam_pwquality` as a `requisite` (first in
`common-password`), and `pwquality` has `dictcheck` enabled by default. `dictcheck`
loads the cracklib dictionary `/var/cache/cracklib/cracklib_dict.pwd`. The **Noble
stemcell ships no cracklib** (`dpkg -l | grep cracklib` empty; `/var/cache/cracklib/`
absent), so the dictionary load fails, the `requisite` module fails, and the whole
password-change stack aborts with a generic token-manipulation error. This also
matches the usg STIG audit finding `accounts_password_pam_dictcheck: fail`.

This is **not** the historical `libpam-cracklib` PAM module (correctly removed in
PAM 1.5.0 in favor of the modern `pam_pwquality`, which the release already uses).
It is the separate **`cracklib-runtime`** package that *builds* the dictionary that
`pwquality`'s `dictcheck` still needs. This decision records that `cracklib-runtime`
is now a **required** harden dependency on Noble, and why.

## Decision Drivers

- **Correctness / usability:** without it, no account on a hardened Noble box can
  change its password — a promotion blocker (IA-5, authenticator management).
- **STIG compliance:** disabling `dictcheck` (`dictcheck=0`) would make password
  changes work but would **fail** the STIG control that requires dictionary
  checking — an unacceptable workaround (SA-11, SI-2).
- **Provenance / supply chain:** the package must come from an allow-listed mirror,
  not an arbitrary source (CM-7, supply chain).
- **Noble-vs-Jammy delta:** the Jammy stemcell effectively provided what `dictcheck`
  needed; the Noble stemcell does not. The dependency is now explicit, not implicit.

## Considered Options

1. **Install `cracklib-runtime` in the harden job (chosen).** harden's
   `post-deploy` installs `cracklib-runtime` from the allow-listed mirrors
   (`snapshot.ubuntu.com` + the `us-gov-west-1` archive, both confirmed reachable),
   which builds `/var/cache/cracklib/cracklib_dict.{pwd,pwi,hwm}`. `pwquality`
   `dictcheck` then succeeds and password changes work while the STIG control is
   satisfied.
2. **Disable `dictcheck` (`dictcheck=0`) in `pwquality.conf`.** Rejected — makes
   password changes work but **fails** the STIG dictionary-check control; trades a
   real security control for convenience.
3. **Ship the cracklib dictionary as a release blob (offline).** Rejected for now —
   more robust/reproducible (no runtime `apt`), but more work, and the mirror install
   is already proven. Revisit alongside the World B direction in ADR-0001 if runtime
   `apt` at post-deploy becomes a problem.

## Decision Outcome

Chosen option: **Option 1 — install `cracklib-runtime` in the harden job from the
allow-listed mirror.** It restores password changes AND keeps the STIG `dictcheck`
control satisfied, using mirrors already trusted by the release.

**Verified live (2026-08-18, fresh deploy, instance `4c2d8789`):**
`dpkg -l | grep cracklib` shows it installed; the dictionary files are present;
`chpasswd` on a fresh unique-uid user SUCCEEDS; and a second change reusing the same
password is REJECTED ("Password has been already used.") — confirming both password
changes and pwhistory now work end-to-end.

> Note: this dependency was necessary but not *sufficient* — a second, independent
> defect (a malformed `common-password` stack) also blocked password changes and was
> fixed separately in Increment 1 (see `fisma-noble-increment1-edits.md` §B4b.0
> BUG 2). Both fixes together restore password changes.

> **Correction (2026-09-16, staging session):** the 2026-08-18 "REJECTED" evidence
> above was produced via **root-driven `chpasswd`**, which is a weaker test than it
> appears. `pam_pwquality`/`pam_pwhistory` checks are **not enforced for root by
> default** (`enforce_for_root` is off unless explicitly configured) — when root runs
> `chpasswd`/`passwd <user>`, the reuse/complexity checks are advisory-only and the
> password change proceeds regardless of any printed warning. Confirmed directly on
> staging: `passwd t2` as root printed **both** `Password has been already used.`
> **and** `passwd: password updated successfully` for the same reuse attempt — a
> warning followed by an unconditional update, not a rejection. `chpasswd` prints no
> success confirmation line, so this ambiguity was invisible in the original
> 2026-08-18 test; a true hard-rejection and a warn-then-proceed outcome look
> identical from `chpasswd`'s output alone.
>
> **Re-verified correctly (2026-09-16, staging, dpkg-fix box, user `t2`):** the
> STIG-relevant scenario is **self-service** password change (the account owner
> changing their own password via bare `passwd`, no username argument), where
> `pam_pwhistory` enforcement is not bypassed. Reusing the same password as `t2`
> itself produced a **hard rejection**:
> ```
> Changing password for t2.
> Current password:
> passwd: Authentication token manipulation error
> passwd: password unchanged
> ```
> followed by confirmation that the *original* password was still valid (successful
> login). This is the trustworthy result; the dictcheck fix + pwhistory enforcement
> are confirmed working end-to-end via the correct (self-service) test path. The
> 2026-08-18 root-driven result likely reflects the same true behavior — the
> underlying PAM module config hasn't changed — but should not be cited as proof
> going forward; cite this entry instead.

### Positive Consequences

- Password changes work on hardened Noble boxes (IA-5).
- The STIG `dictcheck` control is satisfied rather than disabled (no security
  regression to buy usability).
- The Noble dependency that the Jammy stemcell provided implicitly is now explicit
  and documented.

### Negative Consequences

- **Runtime `apt` at post-deploy** to install `cracklib-runtime` is not fully
  reproducible and depends on mirror egress — the same reproducibility concern
  raised for `pro enable`/`usg` in ADR-0001. Shipping the dictionary as a release
  blob (Option 3) remains the more robust long-term design.
- Adds a small package + dictionary-build step to every hardened Noble deploy.

### Compliance Consequences

- **IA-5 (Authenticator Management):** restores the ability to set/change passwords
  under the enforced complexity + history policy.
- **CM-2 / CM-6:** `cracklib-runtime` is now part of the Noble hardening baseline —
  update baseline configuration documentation.
- **CM-7:** package sourced only from allow-listed mirrors (`snapshot.ubuntu.com`,
  `us-gov-west-1` archive), consistent with least-functionality / supply-chain.
- **SA-11 / SI-2:** documented as part of developer testing evidence and flaw
  remediation for Increment 1.
- **ATO:** internal baseline change; ISSO should note the added dependency alongside
  the CIS→STIG posture change from ADR-0001.

## Links

- Supersedes/relates: `0001-adopt-usg-stig-baseline-harden-boshrelease.md` (this
  folder) — the usg/STIG direction that surfaced the `dictcheck` requirement.
- Detailed root cause + verification: `fisma-noble-increment1-edits.md` §B4b.0
  BUG 1 (this folder).
- Corrected pwhistory re-verification (self-service vs. root-bypass distinction):
  staging validation session, 2026-09-16 (this document, correction note above).
- Repo: https://github.com/cloud-gov/harden-boshrelease (branch `noble-main`,
  release `fisma-noble`)
- Ubuntu Security Guide / usg STIG profile `stig-v1r1` (STIG/ubuntu2404 V1R1)
