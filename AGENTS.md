# Project continuity rules for AI agents and contributors

These rules are mandatory whenever work is performed in this repository.

## Before starting
1. Read `docs/CONTINUATION.md` and the repository README.
2. Inspect the current branch, latest commit, relevant source files, tests and latest GitHub Actions runs. Do not rely on old status notes as proof of current state.
3. Confirm the intended working branch. Do not make unrelated changes or silently switch branches.
4. Identify the exact task, acceptance criteria and any required owner action.

## During work
1. Make scoped changes on a feature branch. Do not merge to the default/production branch, publish releases, deploy live services or alter production configuration without explicit owner approval.
2. Never commit API keys, passwords, tokens, webhook secrets, private subscription URLs or personal data. Use GitHub Actions Secrets / the relevant secret store. Documentation may name secret variables but must never include their values.
3. Run relevant tests, builds, linters and security checks. If a check cannot be run, state why.
4. Do not claim functional success from a green workflow or successful compilation alone. Perform and record the relevant runtime/device/integration test where possible.
5. Preserve existing behavior and user requirements. Avoid destructive changes and record material decisions.

## Required close-out after every material work session
Update `docs/CONTINUATION.md` in the same working branch. Include:
- Date (ISO format) and timezone where relevant.
- Branch name and resulting commit SHA.
- What changed, including paths/files.
- Tests/builds executed and exact results.
- Runtime/device/integration verification and what remains unverified.
- Artifact names, exact workflow run URLs and SHA-256 checksums when applicable.
- Blockers, missing evidence and the single clearest next action.
- Any action that the owner must perform.

If `docs/CONTINUATION.md` does not exist on the working branch, create it before closing the task. Never replace verified history with guesses; label unknowns as unknown and keep dated entries.

## Reporting to the owner
Use plain Russian unless the owner requests otherwise. Report what was actually completed, what was not completed, evidence/links, risks and any required user action. Give phone-friendly, step-by-step instructions when user action is necessary. Do not say “done” until the relevant operation has succeeded and been verified.

## Cross-project index
The cross-project starting point is `sokfrut-tech/Gemeni:PROJECTS_INDEX.md`. Update it when a repository is added/retired, its continuation branch changes, or its major status/next checkpoint changes.