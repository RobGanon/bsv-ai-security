# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

- `GLOSSARY.md` at the repo root, if it exists.
- `docs/adr/`, and read ADRs that touch the area being worked on.

If these files do not exist, proceed silently. Do not flag their absence or suggest creating them upfront. The `/domain-modeling` skill creates them lazily when terms or decisions are resolved.

## File structure

This repository uses the single-context layout:

```
/
├── GLOSSARY.md
├── docs/adr/
│   ├── 0001-example.md
│   └── 0002-example.md
└── src/
```

## Use the glossary's vocabulary

When output names a domain concept, use the term defined in `GLOSSARY.md`. Do not drift to synonyms the glossary explicitly avoids.

If a needed concept is not in the glossary, reconsider whether the project already uses different language or note a real gap for `/domain-modeling`.

## Flag ADR conflicts

If an output contradicts an existing ADR, surface it explicitly rather than silently overriding it.
