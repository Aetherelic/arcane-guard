# Arcane Guard

Arcane Guard is the safety inspection module of Arcane Studio.

It scans AUR packages, PKGBUILDs, install scripts, and dotfiles for suspicious or review-worthy patterns before you run them.

Arcane Guard does not prove code is safe or malicious. It highlights obvious red flags and patterns worth reviewing.

## Commands

- arcane guard inspect ./PKGBUILD
- arcane guard inspect-aur yay-bin
- arcane guard inspect-script ./install.sh
- arcane guard inspect-dir ./dotfiles

## What it checks for

- pipe-to-shell patterns such as curl or wget piped into bash
- dangerous removal commands
- sudo, doas, pkexec, or su inside scripts
- chmod 777
- systemd service enable/start commands
- eval usage
- prebuilt binary downloads
- install script references in PKGBUILDs

## Risk levels

- LOW
- MEDIUM
- HIGH
- CRITICAL

## Example

Arcane Guard can scan a real AUR package:

- arcane guard inspect-aur yay-bin

This may flag prebuilt binary archives as medium risk. That does not mean the package is malicious. It means the package is less transparent than building from source.

## Part of Arcane Studio

Arcane Studio is the umbrella project.

- Arcane Guard: safety inspection
- Arcane Themes: theme and rice management
- Arcane Studio: project hub

Repository hub: https://github.com/Aetherelic/arcane-studio
