# Domain documentation

## Layout

This repository uses a single-context layout:

- `CONTEXT.md` at the repository root contains current domain knowledge.
- `docs/adr/` contains architecture decision records.

## Consumer rules

Before planning or implementing domain-sensitive changes:

1. Read the root `CONTEXT.md` if it exists.
2. Read relevant ADRs under `docs/adr/`.
3. Treat ADRs as historical decisions; newer ADRs supersede conflicting older ones.
4. Keep `CONTEXT.md` focused on current understanding rather than decision history.
5. Add or update an ADR when making a durable architectural decision.
6. Update `CONTEXT.md` when the current domain model or constraints change.
