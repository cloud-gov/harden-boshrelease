#!/bin/bash
#
# BOSH errand: on-demand STIG audit.
#
#   bosh -d <deployment> run-errand harden-audit
#
# Reads the SAME tailoring file the harden job uses to remediate, so the audit
# and the remediation can never drift apart.
#
# WHY AN ERRAND RATHER THAN AUTOMATIC:
#
#   * usg serialises itself on a single global flock at /run/lock/usg.lock and
#     exits non-zero IMMEDIATELY rather than waiting. BOSH runs every job's
#     post-deploy script in PARALLEL, so an audit wired into post-deploy races
#     the harden job's `usg fix` and one of them dies -- that was the original
#     "first deploy fails, second succeeds" bug. An errand runs on its own,
#     after the deploy, so there is no race. (We still wait on the lock below,
#     in case an operator runs this while a deploy is in flight.)
#
#   * A full audit takes minutes and produces a report nobody reads on a
#     routine redeploy. Auditing is an assessment activity, not a deploy step.
#
#   * Errand output is capped at 1 MB by BOSH, so the full report is written to
#     disk and only a summary is printed.
#
set -uo pipefail

HARDEN_JOB_DIR=/var/vcap/jobs/harden
TAILORING="${HARDEN_JOB_DIR}/files/tailor.xml"
REPORT_DIR=/var/vcap/sys/log/harden-audit
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOCK_WAIT=<%= p("harden_audit.lock_wait_seconds") %>

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: must run as root (usg reads /etc/shadow, audit rules, etc)." >&2
  exit 1
fi

if ! command -v usg >/dev/null 2>&1; then
  echo "ERROR: usg is not installed. It is provided by 'pro enable usg', which" >&2
  echo "       the ubuntu-advantage-pro-token job's pre-start performs." >&2
  exit 1
fi

if [[ ! -f "${TAILORING}" ]]; then
  echo "ERROR: tailoring file not found: ${TAILORING}" >&2
  echo "       The 'harden' job must be colocated in this instance group." >&2
  exit 1
fi

mkdir -p "${REPORT_DIR}"

###
# Wait for any other usg instance to release the global lock rather than
# failing immediately the way usg itself does.
###

usg_lock_wait() {
  local timeout="${1:-900}" elapsed=0 interval=5
  while :; do
    if ( exec 9>>/run/lock/usg.lock && flock --nonblock --exclusive 9 ) 2>/dev/null; then
      return 0
    fi
    if (( elapsed >= timeout )); then
      echo "ERROR: /run/lock/usg.lock still held after ${timeout}s." >&2
      if command -v fuser >/dev/null 2>&1; then
        echo "Lock holder(s):" >&2
        fuser -v /run/lock/usg.lock >&2 2>&1 || true
      fi
      return 1
    fi
    if (( elapsed % 30 == 0 )); then
      echo "---> Waiting for another usg instance to release /run/lock/usg.lock (${elapsed}s elapsed)"
    fi
    sleep "${interval}"
    elapsed=$(( elapsed + interval ))
  done
}

###
# NO REBOOT IS REQUIRED before auditing.
#
# Verified against a live run on 2026-09-29: with no reboot between `usg fix`
# and `usg audit`, every reboot-sensitive-looking control passed --
# grub2_audit_argument, kernel_module_usb-storage_disabled,
# sysctl_kernel_dmesg_restrict, sysctl_net_ipv4_tcp_syncookies and
# sysctl_kernel_randomize_va_space. Their OVAL checks inspect CONFIG FILES
# (/etc/default/grub, /etc/modprobe.d/*, sysctl values), not running kernel
# state. The one genuinely boot-gated control is audit rules immutability
# (-e 2, UBTU-24-909000), and this baseline excepts it -- see
# tools/tailor-convert/decisions.yml.
#
# So this errand can be run at any point after a deploy and the result is
# authoritative. No reboot step, and no warning to ignore.
###

echo "---> Running usg audit against ${TAILORING}"
usg_lock_wait "${LOCK_WAIT}" || exit 1

HTML="${REPORT_DIR}/usg-audit-${STAMP}.html"
XML="${REPORT_DIR}/usg-audit-${STAMP}.xml"
TXT="${REPORT_DIR}/usg-audit-${STAMP}.txt"

# usg exits non-zero whenever the scan finds any failure, which is normal for an
# audit. Capture its status but judge the run on the report, not the exit code.
#
# Output goes ONLY to ${TXT}, deliberately not to stdout: usg prints a 4-line
# block per rule and this profile evaluates ~170 rules, so echoing it here
# buries the summary below and pushes towards BOSH's 1 MB errand output cap.
# The summary below is the errand's output; ${TXT} is the full detail on disk.
usg audit \
  --tailoring-file "${TAILORING}" \
  --html-file      "${HTML}" \
  --results-file   "${XML}" \
  > "${TXT}" 2>&1
rc=$?

chmod 0600 "${HTML}" "${XML}" "${TXT}" 2>/dev/null || true

###
# Summarise. BOSH caps errand output at 1 MB, and the full run is ~170 rules, so
# print counts plus the non-passing rules only -- the detail is on disk.
###

# NOTE: do NOT use `grep -c ... || echo 0` here -- grep -c already prints 0 and
# exits 1 when there are no matches, so the fallback appends a SECOND 0 and the
# arithmetic below breaks on the two-line value. Count with awk in one pass.
counts="$(awk '
  /^Result[[:space:]]/ { n[$2]++ }
  END { printf "%d %d %d %d", n["pass"]+0, n["fail"]+0, n["notchecked"]+0, n["notapplicable"]+0 }
' "${TXT}" 2>/dev/null)"
read -r pass fail notchecked notapplicable <<< "${counts:-0 0 0 0}"

echo
echo "================ USG AUDIT SUMMARY ================"
echo "  pass          : ${pass}"
echo "  fail          : ${fail}"
echo "  notchecked    : ${notchecked}"
echo "  notapplicable : ${notapplicable}"
echo
# NOTE on paths: /var/vcap/sys is a symlink to /var/vcap/data/sys on a BOSH VM,
# so usg's own completion message (which resolves the link) prints
# /var/vcap/data/sys/log/... for the same files listed here. Same files.
echo "  HTML report   : ${HTML}"
echo "  XCCDF results : ${XML}"
echo "  Raw output    : ${TXT}"
echo "==================================================="

# List anything that did not pass. Driven by fail + notchecked rather than fail
# alone: a "notchecked" rule has no automated OVAL check and needs manual
# review, so silently omitting it would hide required work. "notapplicable" is
# included in the listing for completeness when it appears alongside the others.
if (( fail > 0 || notchecked > 0 )); then
  echo
  echo "NON-PASSING RULES:"
  # Pair each "Rule <id>" with the "Result <x>" line that follows it.
  awk '
    /^Rule[[:space:]]/   { rule = $2 }
    /^Result[[:space:]]/ { if ($2 != "pass") printf "  %-14s %s\n", $2, rule }
  ' "${TXT}"
  echo
  echo "  Cross-reference each against tools/tailor-convert/decisions.yml:"
  echo "    - a 'fail' on a rule with an 'accept' decision is a REAL gap"
  echo "    - a rule with a 'disable' decision should not appear at all"
  echo "    - 'notchecked' means the rule requires manual review (no OVAL check)"
fi

# Exit 0 on a completed scan: findings are data, not an errand failure. A
# genuine execution problem (missing usg, missing tailoring file, lock timeout)
# exits non-zero above, before this point.
exit 0
