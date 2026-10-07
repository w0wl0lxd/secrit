# Security

secrit handles secrets, so please report a vulnerability privately.

- Do not open a public issue for a vulnerability.
- Use GitHub's private vulnerability reporting on this repository, or contact the
  maintainer listed on the GitHub profile.
- Include the version (`secrit --version`), the command, and what you saw. Do not include
  a real secret value.

The threat model and its limits are in `docs/PLAN.md` section 13 and in the README section
"What secrit does not protect against". Reports about a hostile process of the same user
are out of scope (PLAN N1), unless secrit makes such an attack easier than plain `sops`.
