# Arcane Studio

Arcane Studio is a suite of tools for safer aesthetic Linux customization.

Rice harder. Break less.

## Modules

### Arcane Guard

Status: 0.1.0-rc

Arcane Guard inspects community packages, scripts, and dotfiles before you run them.

Current commands:

- arcane guard inspect ./PKGBUILD
- arcane guard inspect-aur yay-bin
- arcane guard inspect-script ./install.sh
- arcane guard inspect-dir ./dotfiles

Useful options:

- --json outputs a JSON report
- --fail-on high exits with code 2 if risk is high or critical
- --fail-on critical exits with code 2 only if risk is critical

Arcane Guard checks for patterns like:

- curl piped into shell
- wget piped into shell
- dangerous recursive delete commands
- sudo, doas, pkexec, or su in executable logic
- chmod 777
- systemd service start or enable actions
- eval
- prebuilt binary/archive references
- install script references

Important: Arcane Guard does not prove a package is safe. It highlights obvious red flags and review-worthy patterns.

### Arcane Themes

Status: experimental prototype

Arcane Themes is separate from Arcane Guard.

Current commands:

- arcane themes status
- arcane themes snapshot
- arcane themes list
- arcane themes restore <snapshot>

Arcane Themes is paused while Arcane Guard is polished for a 0.1 release.

## Installation from source

1. git clone https://github.com/Aetherelic/arcane-studio
2. cd arcane-studio
3. python -m venv .venv
4. source .venv/bin/activate
5. python -m pip install -e .

## Development

Run tests with:

python -m unittest discover -s tests -v

## Vision

Arcane Studio will eventually include:

- Arcane Guard: safety inspection
- Arcane Themes: rollback-safe theme/rice management
- Arcane Doctor: desktop diagnostics
- Arcane Hub: theme/widget registry
