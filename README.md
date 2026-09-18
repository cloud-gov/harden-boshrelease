# System Hardening BOSH Release

[BOSH Release](http://bosh.io/docs/release.html) to run hardening tasks in a system, for use with [cloud.gov](https://cloud.gov).

## See also

* [The FISMA Ready Ubuntu machine image](https://github.com/fisma-ready/ubuntu-lts)

## Pinning versions to avoid auto-patching
If you want a quick way to exclude a specific package from auto-patching 
without setting up a full pin file (e.g., "hold openssh-server at this 
version while we validate a client compatibility issue"), unattended-upgrades 
has a native primitive for that: 
Unattended-Upgrade::Package-Blacklist.

An empty file with Package-Blacklist is located in jobs/harden/templates at: 
```bash
files/etc/apt/apt.conf.d/51unattended-upgrades-security

# Here's an example block
Unattended-Upgrade::Package-Blacklist {
    "libpam-pwquality";   // e.g. if a future version changes dictcheck default behavior
    "cracklib-runtime";   // e.g. if you need to control exactly when the dictionary rebuilds};
}
```