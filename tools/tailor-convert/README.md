# tailor-convert

Generates `jobs/harden/templates/files/tailor.xml` — the XCCDF tailoring file
that the `harden` job's `post-deploy` feeds to `usg fix`, and that the
`harden-audit` errand feeds to `usg audit`.

**This directory is NOT shipped in the BOSH release.** A release packages only
`jobs/` and `packages/`, so nothing here is uploaded to the director or lands on
a VM. It is build-time tooling plus the compliance decision record.

## Why keep it

`tailor.xml` is a **generated artifact**, not a hand-maintained file. It carries
230 `<select>` and 33 `<set-value>` elements, 64 of them disabled. Without this
tooling you would be hand-editing a 460-line XCCDF file and hoping you
remembered why each rule was switched off.

Three concrete reasons it earns its place:

1. **It is the compliance evidence.** `decisions.yml` holds 90 decisions with
   ~2300 words of recorded rationale — why `ufw` is excepted (ASGs replace it),
   why `unlock_time=0` is refused (it would permanently lock the only two
   accounts BOSH needs), why the AC-7 lockout gap is accepted, why the MAC list
   cannot be tailored. When an assessor asks "why is this control not
   enforced?", this file is the answer. Deleting it means re-deriving all of it
   from a diff.

2. **Reproducibility is verifiable.** Re-running the tool must produce a
   byte-identical `tailor.xml`. That check has caught real mistakes in this
   work, and it is what lets you trust the deployed file matches the recorded
   decisions.

3. **The next benchmark bump is a rerun, not a redo.** Decisions are keyed by
   ComplianceAsCode *rule name*, not the `UBTU-XX-NNNNNN` control ID (which
   gets renumbered every STIG revision). Migrating 22.04 V1R1 → 24.04 V1R6
   required changing exactly 3 of 43 decisions; `--check` found all three by
   hard-failing on the renamed rules instead of silently dropping them.

## Usage

```sh
cd tools/tailor-convert
pip3 install lxml pyyaml     # dependencies

# Dry run — report what would change, write nothing:
python3 apply_decisions.py \
  --gold gold/ubuntu2404-stig-v1r6.xml \
  --decisions decisions.yml \
  --check

# Regenerate the deployed tailoring file:
python3 apply_decisions.py \
  --gold gold/ubuntu2404-stig-v1r6.xml \
  --decisions decisions.yml \
  --output ../../jobs/harden/templates/files/tailor.xml
```

Then commit the regenerated `tailor.xml` — it is the file the release ships.

## decisions.yml schema

```yaml
decisions:
  - rule: package_ufw_installed        # ComplianceAsCode rule name (no xccdf_org.ssgproject.* prefix)
    action: disable                    # disable | set-value | accept
    stig_ids: [UBTU-24-100300]         # informational, for traceability to the STIG
    rationale: >-
      Free-text justification. Becomes an XML comment above the affected
      element in the generated tailor.xml.
```

- `disable` — sets `selected="false"` on the matching `<select>`.
- `set-value` — requires `value:`; overwrites the matching `<set-value>` text.
  Note that not every value is tailorable: the `*_ordered_stig` SSH crypto rules
  hardcode their lists at content build time, so a `set-value` on them is
  silently ineffective. See the `ssh_approved_macs` note in `decisions.yml`.
- `accept` — no XML change. Records that a control was considered and
  deliberately left enforced, so it does not vanish from the decision record.

## Regenerating the gold file

`gold/*.xml` is unmodified `usg` output. It can only be produced on a machine
with `usg` installed and Ubuntu Pro attached — i.e. one of the deployed VMs,
not a workstation:

```sh
# on a Noble VM with usg installed:
sudo usg generate-tailoring disa_stig /tmp/gold-noble.xml
# then copy it back into gold/ and re-run apply_decisions.py --check
```

## Migrating to a new benchmark

1. Generate a new gold file (above) on a VM running the target OS/benchmark.
2. Run `apply_decisions.py --check` against it. Every decision whose `rule:`
   no longer resolves is reported as an error — that is the tool telling you
   ComplianceAsCode renamed or removed the rule. Fix `decisions.yml`;
   `stig_ids:` helps you locate the replacement by cross-referencing
   `controls/stig_ubuntu<VER>.yml` in
   [ComplianceAsCode/content](https://github.com/ComplianceAsCode/content).
3. Review rules that are **new** in the target benchmark and have no decision —
   they default to enabled. `--check` does not flag these, so diff the gold
   files' rule lists.
4. Once `--check` is clean, regenerate with `--output` and commit.
5. Validate on a real VM: deploy, then `bosh run-errand harden-audit`. Cross-
   reference any `fail` against `decisions.yml` — a fail on an `accept`
   decision is a real gap; a rule with a `disable` decision should not appear.

## Files

- `apply_decisions.py` — the merge tool.
- `decisions.yml` — the 90-decision record. The important file.
- `gold/ubuntu2404-stig-v1r6.xml` — **current** source. Canonical Ubuntu 24.04
  STIG V1R6, benchmark channel `ubuntu2404_STIG_1`. This is what the deployed
  `tailor.xml` is built from.
- `gold/ubuntu2204-stig-v1r1.xml` — **historical**, retained only as the
  provenance of the 22.04 → 24.04 rename mappings recorded in `decisions.yml`
  (`permissions_local_var_log` → `file_permissions_var_log_stig`,
  `verify_use_mappers` → `sssd_enable_user_cert`, `service_ufw_enabled`
  removed). Not used by any current build; safe to delete if you do not want
  the audit trail.
