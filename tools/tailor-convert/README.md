# tailor-convert

Merges an environment-specific `decisions.yml` on top of a "gold" XCCDF
Tailoring file (as produced by `usg generate-tailoring`) to produce the
`tailor.xml` shipped in `jobs/harden/templates/files/tailor.xml` and consumed
by:

```
usg fix --tailoring-file tailor.xml
usg audit --tailoring-file tailor.xml
```

## Why this exists

The STIG checklist (`docs/compliance/ubuntu.ckl`) documents ~15 DISA STIG
controls that are legitimately `Open`/`Not_Reviewed` for this platform, each
with a BOSH/Cloud Foundry-specific rationale (e.g. `vcap` needs group-write
on `/var/log`, ASGs replace `ufw`, BOSH SSH uses passwordless sudo, etc). The
raw usg-generated tailoring file has no place to record that rationale, and
hand-editing a 2,000+ line XCCDF file every time the source benchmark changes
(STIG revision bump, or a future Ubuntu 24.04/Noble benchmark) is error-prone
and throws away institutional memory.

This tool keeps two inputs, each independently regenerable:

- **gold/*.xml** — an unmodified XCCDF `<Tailoring>` file for a specific
  benchmark, produced by `usg generate-tailoring disa_stig <output>` on a
  matching Ubuntu release. Check these in for reproducibility/diffing even
  though they can be regenerated from a live `usg` install.
- **decisions.yml** — the list of overrides, keyed by stable ComplianceAsCode
  *rule name* (not the numeric `UBTU-XX-NNNNNN` STIG control ID, which gets
  renumbered between STIG revisions).

`apply_decisions.py` merges them, writing the rationale as an XML comment
directly above each affected `<select>`/`<set-value>` element, and refuses
to produce output if any decision fails to match a rule in the gold file
(which is what happens when a rule is renamed/removed upstream — this is
intentionally a hard failure, not a silent skip).

## Usage

```sh
# Regenerate the gold tailoring file from a live usg install matching the
# target OS release (run this ON a VM/stemcell with usg installed):
sudo usg generate-tailoring disa_stig gold/ubuntu2204-stig-v1r1.xml

# Merge decisions on top of it and write the deployed tailor.xml:
python3 apply_decisions.py \
  --gold gold/ubuntu2204-stig-v1r1.xml \
  --decisions decisions.yml \
  --output ../../jobs/harden/templates/files/tailor.xml

# Dry run — report what would change without writing anything:
python3 apply_decisions.py \
  --gold gold/ubuntu2204-stig-v1r1.xml \
  --decisions decisions.yml \
  --check
```

Dependency: `pip3 install lxml pyyaml`.

## decisions.yml schema

```yaml
decisions:
  - rule: package_ufw_installed        # ComplianceAsCode rule name (no xccdf_org.ssgproject.* prefix)
    action: disable                    # disable | set-value | accept
    stig_ids: [UBTU-22-251010]         # informational only, for traceability to the STIG checklist
    rationale: >-
      Free-text justification. Becomes an XML comment above the affected
      element in the generated tailor.xml.
```

- `disable` — sets `selected="false"` on the matching `<select>` element.
- `set-value` — requires a `value:` key; overwrites the matching
  `<set-value>` element's text.
- `accept` — no XML change; exists purely so a known STIG finding is
  represented and doesn't silently disappear from the decision record (e.g.
  a finding that's already resolved by a value the gold file sets).

## Migrating to a new benchmark (e.g. Ubuntu 24.04/Noble)

1. On a representative VM/stemcell running the new OS with `usg` installed,
   run `usg generate-tailoring disa_stig gold/<new-name>.xml`.
2. Run `apply_decisions.py --check` against the new gold file. Any decision
   whose `rule:` no longer matches will be reported as an error — usually
   because ComplianceAsCode renamed the rule for the new product. Update
   `decisions.yml` to the new rule name(s); the `stig_ids:` field will often
   help you find the renamed rule by cross-referencing the new
   `controls/stig_ubuntu24XX.yml` in
   [ComplianceAsCode/content](https://github.com/ComplianceAsCode/content).
3. Once `--check` passes clean, regenerate the deployed `tailor.xml` with
   `--output`.
4. Validate end-to-end with a live `usg audit --tailoring-file tailor.xml`
   run on a real VM before merging (this cannot be verified from a sandbox
   without `usg`/Ubuntu Pro installed).

## Files

- `apply_decisions.py` — the merge tool.
- `decisions.yml` — the current set of environment-specific overrides.
- `gold/ubuntu2204-stig-v1r1.xml` — the unmodified tailoring file this
  release currently builds from (`ubuntu2204_STIG_1` benchmark, STIG V1R1).
  Note: upstream ComplianceAsCode is already at V2R8 for 22.04; regenerating
  this gold file against a current `usg` install and re-running
  `apply_decisions.py --check` is recommended to pick up renamed/added
  rules — see the open tracking issue.
