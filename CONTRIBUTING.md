# Contributing

## Branches and changes

`main` is the releasable line, `develop` is the integration line, and work starts from `develop` on `feature/<short-name>`. Use `fix/<short-name>` for defects and `docs/<short-name>` for documentation-only work. Open pull requests into `develop`; release owners promote reviewed work to `main`.

## Commits

Use Conventional Commits: `feat: add import validation`, `fix: reject self-approved exception`, `docs: explain local TLS setup`, or `test: cover risk score boundaries`. Keep each commit focused and describe user-visible behavior in the body when the subject is not enough.

## Pull request checklist

- [ ] The change maps to a requirement or records why it is an operational fix.
- [ ] Synthetic data only; no real bank, customer, credential, scanner, or network data.
- [ ] Authorization and audit behavior are considered for every new endpoint.
- [ ] Validation, error responses, and accessible labels are present.
- [ ] Backend tests and frontend build pass locally.
- [ ] Docs, API behavior, and `.env.example` are updated when needed.
- [ ] No secrets or generated build artifacts are committed.

Reviewers check correctness, privacy boundaries, maintainability, accessibility, and test evidence. A request with an unresolved critical security finding is not merged.
