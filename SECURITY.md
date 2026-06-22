# Security Policy

Arcane Guard is a static inspection tool. It can highlight suspicious patterns, but it cannot guarantee that a package, script, or dotfiles repo is safe.

Security-relevant issues include:

- false negatives for clearly dangerous shell patterns
- unsafe behavior in Arcane Studio itself
- path traversal or overwrite bugs
- restore/snapshot issues in Arcane Themes
- command execution vulnerabilities
