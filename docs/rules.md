# Arcane Guard Rules

Arcane Guard is a heuristic review assistant. It does not prove code is safe, and clean output does not mean a package or script is trustworthy.

This document explains the current rules, why they exist, and where false positives can happen.

## Severity levels

| Severity | Meaning |
| --- | --- |
| LOW | Worth noticing, often normal depending on context |
| MEDIUM | Review recommended |
| HIGH | Strong warning; understand before running |
| CRITICAL | Stop and review carefully before running |

## Rules

### pipe-to-shell

Detects remote download commands piped directly into a shell.

Examples:

- `curl https://example.com/install.sh | bash`
- `wget -O- https://example.com/script.sh | sh`

Why it matters:

This runs remote code immediately without giving the user a chance to inspect it.

False positives:

Some official installers use this pattern, but it is still worth reviewing.

Severity: CRITICAL

---

### dangerous-rm

Detects recursive and forceful deletion aimed at dangerous targets such as `/`, `$HOME`, `${HOME}`, `~`, or `.`.

Examples:

- `rm -rf "$HOME"`
- `rm --recursive --force "$HOME"`
- `rm -fr /`

Why it matters:

These commands can delete important user or system files.

False positives:

Rare in install scripts. In build scripts, deletion should normally target `$srcdir`, `$pkgdir`, or a temporary build directory.

Severity: CRITICAL

---

### dangerous-cd-home-then-rm

Detects changing into the home directory and then recursively deleting the current directory.

Example:

- `cd "$HOME" && rm -rf .`

Why it matters:

This can delete the contents of the user's home directory.

False positives:

Very unlikely in legitimate package/install scripts.

Severity: CRITICAL

---

### dangerous-find-delete-home

Detects `find -delete` targeting home or root-like paths.

Examples:

- `find "$HOME" -delete`
- `find ~ -delete`
- `find / -delete`

Why it matters:

`find -delete` can remove large numbers of files quickly.

False positives:

Rare when targeting home or root paths.

Severity: CRITICAL

---

### dangerous-find-delete-current

Detects `find . -delete`.

Why it matters:

This can be destructive depending on the current working directory.

False positives:

Can be legitimate in temporary build directories, but should be reviewed in install scripts and dotfiles.

Severity: HIGH

---

### sudo-in-command

Detects `sudo` inside executable logic.

Why it matters:

PKGBUILDs and package build scripts should not need to call `sudo`. `makepkg` handles privilege separation.

False positives:

Some personal install scripts may use `sudo`, but users should review exactly what is being elevated.

Severity: HIGH

---

### privilege-change

Detects privilege-changing commands such as `su`, `doas`, or `pkexec`.

Why it matters:

Privilege changes can hide or expand what a script is able to do.

False positives:

Some admin scripts may legitimately use these, but package/build scripts should generally not.

Severity: HIGH

---

### setuid-or-capability

Detects setuid-style permissions or Linux capability changes.

Examples:

- `chmod u+s`
- `chmod 4755`
- `setcap ...`

Why it matters:

These can increase the privileges of executables.

False positives:

Some packages legitimately require capabilities, but this should always be reviewed.

Severity: HIGH

---

### chmod-777

Detects `chmod 777`.

Why it matters:

World-writable files are usually a poor security practice.

False positives:

Sometimes used in quick-and-dirty scripts, but usually should be replaced with tighter permissions.

Severity: MEDIUM

---

### systemd-action

Detects systemd service actions during executable logic.

Examples:

- `systemctl enable service`
- `systemctl start service`
- `systemctl restart service`

Why it matters:

Packages and install scripts generally should not start or enable services without clear user consent.

False positives:

Personal setup scripts may do this intentionally.

Severity: MEDIUM

---

### eval-usage

Detects `eval`.

Why it matters:

`eval` can make it harder to understand what code actually runs.

False positives:

Some shell scripts use `eval` legitimately, but it deserves review.

Severity: MEDIUM

---

### binary-source / binary-reference

Detects references to prebuilt binary/archive formats.

Examples:

- `.AppImage`
- `.deb`
- `.rpm`
- `.tar.gz`
- `.zip`
- `.run`

Why it matters:

Prebuilt binaries are not automatically unsafe, but they reduce source transparency.

False positives:

Common for `-bin` AUR packages.

Severity: MEDIUM

---

### install-script-reference

Detects PKGBUILDs that reference an `.install` script.

Why it matters:

`.install` files can run package lifecycle commands and should be reviewed alongside the PKGBUILD.

False positives:

Many legitimate packages use install scripts.

Severity: MEDIUM

---

### network-command

Detects network commands inside executable logic.

Examples:

- `curl`
- `wget`
- `git clone`
- `ssh`
- `scp`
- `rsync`

Why it matters:

Network access is normal in source arrays, but can be suspicious in executable script logic.

False positives:

Some setup scripts intentionally download assets or dependencies.

Severity: LOW
