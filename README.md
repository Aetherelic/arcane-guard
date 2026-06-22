# Arcane Guard

Arcane Guard is the safety inspection module of Arcane Studio.

It scans AUR packages, PKGBUILDs, install scripts, and dotfiles for suspicious or review-worthy patterns before you run them.

Arcane Guard is a heuristic review assistant. It does not prove code is safe or malicious, and clean output does not mean a script or package is safe. It highlights common red flags and patterns worth reviewing before you run unknown code.


## Installation

### From GitHub

Until AUR publishing is available, the recommended install method is `pipx`:

- sudo pacman -S --needed git python python-pipx
- pipx ensurepath
- git clone https://github.com/Aetherelic/arcane-guard.git
- cd arcane-guard
- pipx install .

Restart your terminal, then test:

- arcane --version
- arcane guard inspect-aur yay-bin

### AUR

AUR publishing is planned under:

- arcane-guard-git

Once available, it will install with:

- yay -S arcane-guard-git

## Commands

- arcane guard inspect ./PKGBUILD
- arcane guard inspect-aur yay-bin
- arcane guard inspect-script ./install.sh
- arcane guard inspect-dir ./dotfiles

## What it checks for

- pipe-to-shell patterns such as curl or wget piped into bash
- dangerous removal commands, including rm -rf, rm --recursive --force, cd "$HOME" && rm -rf ., and find -delete patterns
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


## Security model

Arcane Guard is not an antivirus, sandbox, or malware detector.

It is a static heuristic scanner. It can catch common dangerous patterns, but it can be bypassed by obfuscation, unusual shell syntax, variables, sourced files, encoded commands, or logic spread across multiple files.

Use Arcane Guard as a review assistant, not as a guarantee.


## Rule documentation

Detailed rule explanations are available in:

- docs/rules.md
