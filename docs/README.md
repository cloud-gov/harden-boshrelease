# Compliance Artifacts

## `ubuntu.ckl`

`ubuntu.ckl` is a historical DISA STIG Viewer checklist export for the
Canonical Ubuntu 22.04 LTS STIG V1R1. It preserves the prior TAS assessment
results and assessor comments for compliance provenance.

It is not consumed by BOSH, packaged into the release, or read by `usg`.
Do not use it as a tailoring file.

The current compliance implementation is maintained elsewhere:

- `tools/tailor-convert/decisions.yml` is the active, reviewable record of
  environment-specific compliance decisions.
- `tools/tailor-convert/` generates the deployed tailoring file.
- `jobs/harden/templates/files/tailor.xml` is the XCCDF tailoring file shipped
  in the release and passed to `usg fix` and `usg audit`.

When updating the Ubuntu benchmark, follow
`tools/tailor-convert/README.md`. Retain `ubuntu.ckl` unless the historical
22.04 assessment record is no longer needed as compliance evidence.
