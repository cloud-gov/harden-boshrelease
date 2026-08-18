#!/bin/bash
set -e

USG_PROFILE='<%= p("stig_profile") %>'
REPORT_DIR=/var/vcap/sys/log/usg
mkdir -p "${REPORT_DIR}"

if command -v usg >/dev/null 2>&1; then
  echo "Running usg STIG audit (report-only): ${USG_PROFILE}"
  # usg audit exits non-zero when the scan finds STIG failures — which is ALWAYS
  # in audit-only mode. Guard it so a findings-exit never aborts this script.
  usg audit "${USG_PROFILE}" \
    --html-file    "${REPORT_DIR}/usg-${USG_PROFILE}-audit.html" \
    --results-file "${REPORT_DIR}/usg-${USG_PROFILE}-audit.xml" \
    || echo "usg audit returned non-zero (expected for an audit with findings)"
else
  echo "usg not installed after enable; skipping STIG audit"
fi

# Report-only step: never fail the BOSH deploy on the audit result.
exit 0
