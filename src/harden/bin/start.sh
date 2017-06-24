#!/bin/bash
set -e

echo "---> Starting hardening process"

cd /var/vcap/packages/harden/files

###
# /etc/modprobe.d Safe Defaults
# See https://github.com/18F/ubuntu/blob/master/hardening.md
###

cp etc/modprobe.d/18Fhardened.conf /etc/modprobe.d/18Fhardened.conf
chmod 0644 /etc/modprobe.d/18Fhardened.conf
chown root:root /etc/modprobe.d/18Fhardened.conf

###
# Redirect protections
# See https://github.com/18F/ubuntu/blob/master/hardening.md#redirect-protections
###

cp etc/sysctl.conf /etc/sysctl.conf
chmod 0644 /etc/sysctl.conf
chown root:root /etc/sysctl.conf


ICMP_SETTINGS[0]="net.ipv4.conf.default.rp_filter=1"
ICMP_SETTINGS[1]="net.ipv4.conf.all.rp_filter=1"
ICMP_SETTINGS[2]="net.ipv4.conf.all.accept_redirects=0"
ICMP_SETTINGS[3]="net.ipv6.conf.all.accept_redirects=0"
ICMP_SETTINGS[4]="net.ipv4.conf.default.accept_redirects=0"
ICMP_SETTINGS[5]="net.ipv6.conf.default.accept_redirects=0"
ICMP_SETTINGS[6]="net.ipv4.conf.all.secure_redirects=0"
ICMP_SETTINGS[7]="net.ipv4.conf.default.secure_redirects=0"
ICMP_SETTINGS[8]="net.ipv4.conf.all.send_redirects=0"
ICMP_SETTINGS[9]="net.ipv4.conf.default.send_redirects=0"
ICMP_SETTINGS[10]="net.ipv4.conf.all.accept_source_route=0"
ICMP_SETTINGS[11]="net.ipv6.conf.all.accept_source_route=0"
ICMP_SETTINGS[12]="net.ipv4.conf.default.accept_source_route=0"
ICMP_SETTINGS[13]="net.ipv6.conf.default.accept_source_route=0"
ICMP_SETTINGS[14]="net.ipv4.conf.all.log_martians=1"
ICMP_SETTINGS[15]="net.ipv4.conf.default.log_martians=1"
ICMP_SETTINGS[16]="net.ipv4.icmp_echo_ignore_broadcasts=1"
ICMP_SETTINGS[17]="net.ipv4.icmp_ignore_bogus_error_responses=1"
ICMP_SETTINGS[18]="net.ipv4.tcp_syncookies=1"
ICMP_SETTINGS[19]="net.ipv4.route.flush=1"
ICMP_SETTINGS[20]="net.ipv6.route.flush=1"

for setting in "${ICMP_SETTINGS[@]}"; do
  /sbin/sysctl -w $setting
done

###
# Audit Strategy!
# See https://github.com/18F/ubuntu/blob/master/hardening.md#audit-strategy
###

mkdir -p /etc/audit
cp etc/audit/audit.rules /etc/audit/audit.rules
chmod -R 0640 /etc/audit
chown -R root:root /etc/audit


###
# System Access, Authentication and Authorization
# See https://github.com/18F/ubuntu/blob/master/hardening.md#system-access-authentication-and-authorization
###

rm -f /etc/at.deny

CRON_FILES[0]="/etc/cron.allow"
CRON_FILES[1]="/etc/at.allow"
CRON_FILES[2]="/etc/crontab"
CRON_FILES[3]="/etc/cron.hourly"
CRON_FILES[4]="/etc/cron.daily"
CRON_FILES[5]="/etc/cron.weekly"
CRON_FILES[6]="/etc/cron.monthly"
CRON_FILES[7]="/etc/cron.d"

for file in "${CRON_FILES[@]}"; do
  chmod 0700 $file
  chown root:root $file
done


###
# Password Policy
# See https://github.com/18F/ubuntu/blob/master/hardening.md#password-policy
###


apt-get upgrade -y libpam-cracklib

cp etc/pam.d/common-password /etc/pam.d/common-password
cp etc/pam.d/login /etc/pam.d/login
cp etc/login.defs /etc/login.defs

chown root:root /etc/pam.d/common-password /etc/pam.d/login /etc/login.defs
chmod 0644 /etc/pam.d/common-password /etc/pam.d/login /etc/login.defs

###
# SSH Settings
# See https://github.com/18F/ubuntu/blob/master/hardening.md#ssh-settings
###

cp etc/ssh/sshd_config /etc/ssh/sshd_config
chmod 0600 /etc/ssh/sshd_config

###
# Set warning banner for login services
###

cp etc/issue /etc/issue
cp etc/issue /etc/issue.net
touch /etc/motd

ISSUE_FILES[0]="/etc/issue"
ISSUE_FILES[1]="/etc/issue.net"
ISSUE_FILES[2]="/etc/motd"

for file in "${ISSUE_FILES[@]}"; do
  chmod 0644 $file
  chown root:root $file
done

###
# Restrict Core Dumps
###

cp etc/security/limits.conf /etc/security/limits.conf

###
# Change permissions on home directory
###

chmod 0750 /home/vcap

###
# Ensure syslog emits at least one entry each minute
###
sed -i 's/^#\($ModLoad immark\)/\1/' /etc/rsyslog.conf
sed -i 's/^\($ModLoad imuxsock\)/#\1/' /etc/rsyslog.conf
sed -i 's/^\($RepeatedMsgReduction on\)/#\1/' /etc/rsyslog.conf

cat << 'EOF' > /etc/rsyslog.d/00-heartbeat.conf
$MarkMessagePeriod 60
$ActionWriteAllMarkmessages on

module(load="imuxsock" SysSock.IgnoreOwnMessages="off" SysSock.RateLimit.Interval="0")
EOF

# write iptables connection logs to their own log file
cat << 'EOF' > /etc/rsyslog.d/01-tcp_connections.conf
if $syslogfacility-text == 'kern' and $msg contains 'IN=' and $msg contains 'OUT='  and $msg contains 'MAC=' then {
    /var/log/tcp_connections.log
    stop
}
EOF

service rsyslog restart


echo "---> Finished hardening process"
