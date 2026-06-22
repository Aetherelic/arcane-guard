# Arcane Studio

Arcane Studio is a suite of tools for safer aesthetic Linux customization.

Rice harder. Break less.

## Modules

### Arcane Guard

Arcane Guard inspects community packages, scripts, and dotfiles before you run them.

Current commands:

- arcane guard inspect ./PKGBUILD
- arcane guard inspect-aur yay-bin
- arcane guard inspect-script ./install.sh
- arcane guard inspect-dir ./dotfiles

Important: Arcane Guard does not prove a package is safe. It highlights obvious red flags and review-worthy patterns.

### Arcane Themes

Arcane Themes is experimental and separate from Arcane Guard.

Current commands:

- arcane themes status
- arcane themes snapshot
- arcane themes list
- arcane themes restore <snapshot>

Arcane Themes is paused while Arcane Guard is polished for a 0.1 release.

## Development

- python -m venv .venv
- source .venv/bin/activate
- python -m pip install -e .
- python -m unittest -v
