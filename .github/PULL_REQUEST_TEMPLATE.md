<!--
Thanks for the PR. Please fill out the sections below so reviewers have the
context they need. Delete sections that don't apply.
-->

## Summary

<!-- A short, plain-English description of what this PR changes and why. -->

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing behavior to change)
- [ ] Refactor / internal cleanup (no functional change)
- [ ] Documentation only
- [ ] Build / CI / tooling
- [ ] Dependency update
- [ ] Performance improvement
- [ ] Test-only change

## Testing

<!--
Describe how you verified this change. Include commands run and any manual
test steps. Reviewers should be able to reproduce.
-->

- [ ] `pytest backend/tests` passes locally
- [ ] `cd frontend && npm run test` passes locally
- [ ] `ruff check backend` and `mypy backend` pass
- [ ] `npm run lint && npm run typecheck` pass in frontend
- [ ] Manual smoke test performed (describe below)

<details>
<summary>Manual test notes</summary>

<!-- e.g. "Logged in as test user, ran agent task X, verified Y" -->

</details>

## Security checklist

- [ ] Does this change touch authentication, authorization, or session handling?
- [ ] Does this change introduce any new secrets, API keys, or tokens? (If yes, are they sourced from env / a secret store, never committed?)
- [ ] Does this change introduce a new external network call or third-party dependency?
- [ ] Does this change include a database schema migration? (If yes, is it backwards-compatible / reversible?)
- [ ] Does this change alter `backend/core/security.py` or `backend/core/network_security.py`?
- [ ] Does this change parse, render, or proxy untrusted user input?
- [ ] Have you reviewed for SQL injection, SSRF, XSS, and prompt-injection risks?

## Screenshots (UI changes only)

<!--
Drag-and-drop before/after screenshots or a short screen recording for any
visible UI change. Delete this section if it doesn't apply.
-->

| Before | After |
| ------ | ----- |
|        |       |

## Related issues / context

<!-- e.g. Closes #123, Refs #456, design doc link, RFC link -->
