USG_PROFILE='<%= p("stig_profile") %>'
REPORT_DIR=/var/vcap/sys/log/usg
mkdir -p "${REPORT_DIR}"

if command -v usg >/dev/null 2>&1; then
  echo "Running usg STIG audit (report-only): ${USG_PROFILE}"
  usg audit "${USG_PROFILE}" \
    --html-file   "${REPORT_DIR}/usg-${USG_PROFILE}-audit.html" \
    --results-file "${REPORT_DIR}/usg-${USG_PROFILE}-audit.xml" \
    || echo "usg audit failed"
else
  echo "usg not installed after enable; skipping STIG audit"
fi