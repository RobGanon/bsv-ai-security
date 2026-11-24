# Issue tracker: GitHub

Issues and specs for this repo live as GitHub issues. Use the `gh` CLI for all operations.

## Conventions

- **Create an issue**: `gh issue create --title "..." --body "..."`
- **Read an issue**: `gh issue view <number> --json number,title,body,labels,comments`
- **List issues**: `gh issue list --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'`
- **Make an issue a sub-issue**: use `gh issue create --parent <parent> ...` or `gh issue edit <parent> --add-sub-issue <child>` with `gh` 2.94+. Older `gh` can use the sub-issues REST API. Without sub-issues, put `Part of #<parent>` at the top of the child body.
- **Blocking**: use GitHub native issue dependencies when available. With `gh` 2.94+, use `gh issue create --blocked-by <n>,<n> ...` or `gh issue edit <child> --add-blocked-by <blocker>`. Otherwise, put `Blocked by: #<n>, #<n>` at the top of the child body.
- **Count open blockers**: `gh api repos/<owner>/<repo>/issues/<n> --jq .issue_dependencies_summary.blocked_by`
- **Comment**: `gh issue comment <number> --body "..."`
- **Apply / remove labels**: `gh issue edit <number> --add-label "..."` / `--remove-label "..."`
- **Close**: comment with `gh issue comment <number> --body "..."`, then `gh issue close <number>`.

Infer the repo from `git remote -v`; `gh` does this automatically inside the clone.

File issues only into the user's own repo. Never file into `mattpocock/skills` unless the user owns it. In a fork, check `gh repo view --json nameWithOwner` before the first issue creation and confirm the target if it is not the user's repo.

## Pull requests as a triage surface

**PRs as a request surface: no.**

External PRs are not a triage request queue for this repository.

## When a skill says "publish to the issue tracker"

Create a GitHub issue.

## When a skill says "fetch the relevant ticket"

Read the issue as described in the conventions above.
