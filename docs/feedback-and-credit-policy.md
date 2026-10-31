# Tester feedback and credit policy

This policy covers how testing feedback reaches the project during
the research preview, and how contributors are credited. It applies
from the `v0.4.0-preview` tag onward. Nothing here promises payment.

## 1. Private feedback first

During the research preview, feedback starts private. A tester
cannot always tell a security flaw from an ordinary bug before
reporting it, so a public report could disclose a vulnerability
before there is a fix.

### Two intake paths (do not merge them)

**A. Security reports — private, always.**

- Channel: GitHub private vulnerability reporting on the public
  repo:
  [Report a vulnerability](https://github.com/RobGanon/bsv-ai-security/security/advisories/new).
- What it is for: anything that could weaken verification, signing,
  journaling, anchoring, or key handling — including a suspected
  bypass, a forgery, or a key-handling flaw.
- Notification: the maintainer is notified on arrival via GitHub
  admin notifications.
- Triage: the maintainer acknowledges, reproduces, fixes, and only
  then discloses — with the reporter's consent on wording and on
  whether they are credited, and under what name.
- Never: a security report is never copied to a public issue, a
  public discussion, or a social post before a fix exists, and
  never with the reporter's private details attached.

**B. General testing feedback — private tester repository.**

- Channel: the private, invite-only repository
  [bsv-ai-security-testers](https://github.com/RobGanon/bsv-ai-security-testers)
  (the link works only for invited testers). Testers are invited
  as they arrive; the repository starts empty.
- What it is for: bugs that are not security issues, install
  problems, unclear docs, UX friction, and feature requests.
- Notification: the maintainer is notified on arrival via GitHub
  notifications.
- Triage: the maintainer moves an item to the public repo only when
  it is ready to be public (reproduced, not a security issue,
  reporter consent where credit is involved). Until then it stays
  private.
- What testers are told up front: "Report here first. Do not post
  security findings publicly. You will hear back after triage;
  response time is best-effort."

### Response time

All reports — security and general — are handled best-effort, with
no promised response time. This replaces the earlier 7-day
acknowledgement promise for security reports.

### What the feedback area is NOT

- Not a support desk with a promised response time.
- Not a bounty program. There is no payment for reports.
- Not a public issue tracker with a private front door. Public
  issues remain for public, triaged work only.

### Preview-phase note

Private-first applies during the research preview. A switch to
standard public issues for general feedback is to be revisited at
beta, once independent review exists.

## 2. Credit — who gets it, and what it means

### What credit is

- Attribution only: a name/handle, listed for a verified
  contribution, in the places that helper approved.
- Credit is NOT payment, NOT employment, NOT endorsement, and NOT
  a claim that the helper speaks for the project.

### Who qualifies

- A person who made a verified contribution: a merged fix, a
  reproduced test report, an independent review, a substantial
  docs/tester-guide contribution, or equivalent — with evidence
  linked (PR number, report, review, or commit).
- The helper must approve being credited, using the name/handle
  they choose. No one is listed without approval. Anonymous
  contribution stays anonymous.
- AI reporters are not listed for credit without the maintainer's
  explicit direction on that specific case.

### Where credit appears — approval is per venue

- Approval to be credited in the repo (e.g. Issue #4 list,
  SECURITY.md, release notes) does NOT cover broader venues
  (e.g. a product announcement, a website, a social post).
- Each broader venue needs its own confirmation with that helper,
  covering that venue specifically.

### No self-service

- No one adds themselves to the credit list — not by PR, not by
  issue, not by message. Entries are added by the maintainer
  after verifying the contribution and the approval.
- A contribution alone does not auto-qualify: low-quality,
  duplicate, or unverifiable reports do not earn a listing, and
  the maintainer decides that case by case.

### Current list

None yet — no helper has approved credit yet.

## 3. Credit maintenance — including removal

This is the part that protects the list from abuse. It is stated
from day one, so a later removal is the policy working, not a
surprise.

### The maintainer may amend or remove an entry when:

- The contribution is shown to be false, misattributed, or
  someone else's work claimed as one's own.
- The listing was obtained by gaming: duplicate reports,
  low-quality spam aimed at the list, or coordinated attempts
  to inflate credit.
- The credited person misuses the listing: implying endorsement,
  employment, or authority over the project; using it to
  solicit payment or access; or harassing maintainers or
  other contributors in connection with it.
- The person asks to be removed, or withdraws their approval
  for a venue (removal from that venue; repo entries are
  handled the same way unless the person says otherwise).
- The entry is simply wrong (wrong name, wrong contribution,
  wrong link) — corrected, not treated as abuse.

### Removal process (maintainer-only, recorded, not public shaming)

1. The maintainer decides, on the evidence, that an entry meets a
   ground above. No vote, no public trial.
2. The entry is removed or amended in every venue the maintainer
   controls (repo list, release notes, website copy). Venues the
   maintainer does not control (e.g. a reposted announcement) are
   noted as best-effort.
3. The reason is recorded privately (date, ground, evidence
   link). The public record shows only that the entry was
   removed/amended — no public accusation, no naming of
   private details, unless the maintainer separately decides a
   public explanation is warranted.
4. A removed person may re-earn credit only with a new, verified
   contribution and a fresh approval, at the maintainer's
   discretion. Removal is not a ban from contributing, unless the
   maintainer separately decides that.

### What removal does NOT do

- It does not erase history: merged code, fixed issues, and
  public records of a contribution stay as they are. Only the
  credit listing changes.
- It does not retroactively un-credit a release that already
  shipped with the name in it — shipped artifacts are not
  rewritten. Future listings and venues are corrected.
- It does not create a payment obligation in either direction.
