# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- Add durable project-specific notes here as they are discovered through real work.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.

- Profile-managed OpenCode support consumes the maintained AgentField Python
  fork commit `aa0304577017ee25c405db2a7c2b5fd666f7decc`; the dependency pins
  and `docs/deployment.md` are the release/source-of-truth references.
- Keep role identity in `swe_af/runtime/profiles.py`. AgentField owns OpenCode
  configuration and process policy; validate direct profile wiring with the
  focused profile tests before running `make check`.
