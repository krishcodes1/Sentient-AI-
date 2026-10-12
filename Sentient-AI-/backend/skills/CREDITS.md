# Credits for the bundled skills

Where the method of each bundled skill came from. Every SKILL.md and reference
file in this folder is original text written for Crawler AI on 2026-10-12; no
text was copied from any source below. Each skill takes a method (the order of
the steps, what to check, where to stop) and rewrites it for Crawler's own
tools and approval rules.

Why it exists: a reviewer reading a skill should be able to see what it was
modelled on and check that nothing was copied, and the project keeps a record
of the ideas it borrowed. The design is in
`docs/superpowers/specs/2026-10-12-muse-skills-and-goals-design.md` (§7).

A note on Muse: Meta's public pages describe what Muse's built-in skills do,
but not their text. Some method details below (the goal intake order, the
coverage line of wide research, the planning-first rule for travel, the
draft-first rule for email) were also learned from public write-ups of those
skills and from an unofficial community mirror of the skill files. That
mirror has no licence, so it was read for ideas only and nothing was copied
from it.

Meta pages referred to below:

- Meta Help Center, "How Muse works with skills":
  https://www.meta.com/help/artificial-intelligence/2797651547267109/
- Meta Newsroom, "Introducing Muse" (2026-09-08, updated 2026-09-30):
  https://about.fb.com/news/2026/09/introducing-muse
- Meta Newsroom, "Introducing Muse for Small Business" (2026-09-29):
  https://about.fb.com/news/2026/09/introducing-muse-small-business/
- Meta AI research blog, "How We Built Safety Into Muse" (2026-09-08):
  https://research.meta.ai/blog/security-and-safety-for-ai-agents-our-approach-with-muse

## goals

- Method: Muse's Goals tab and its `goals` skill: understand the goal, save
  exactly one record, then offer help; one question per intake turn; verify
  the record before saying it is saved; a small first milestone; check-ins
  only with the user's agreement; watch for deadlines and conflicts between
  goals; ask at the target date whether to complete or extend.
- Sources: the Meta Help Center page and the launch post above.
- Changed for Crawler: the `goals.*` tools and their store; check-ins through
  `schedule.create` (approval card) or `reminders.create`; Canvas and study
  progress for school goals; the no-advice rules for money and health goals.
- Original text written for Crawler AI; no text copied. 2026-10-12.

## wide-research

- Method: Muse's `wide-research` skill: clean the input list, fix one small
  output schema, research each item independently, retry failures once, and
  report coverage and gaps.
- Sources: the Meta Help Center page (compiling research) and the launch
  post.
- Changed for Crawler: no subagents; one `web.research` call per item;
  every value dated and cited; no profiles of private people.
- Original text written for Crawler AI; no text copied. 2026-10-12.

## travel-planning

- Method: Muse's `travel-planning` and `booking` skills: planning is the
  default and booking needs the user's opt-in; reuse known context before
  asking; check the calendar across the trip; keep one itinerary; a compact
  final review before any commitment; report a booking only after a
  confirmation.
- Sources: the launch post (booking travel), the Help Center page, and the
  safety post (checkout approvals).
- Changed for Crawler: `web.*`, `browser.read` and calendar reads; booking
  handed to the shopping skill, so payment goes only through
  `browser.checkout` with the owner's stored card, spending caps and approval
  card; Canvas deadlines for students.
- Original text written for Crawler AI; no text copied. 2026-10-12.

## shopping

- Method: Muse's `shopping` skill: settle the attributes that make a product
  correct before searching; verify product pages; filter by constraints and
  price; lead with the recommendation; discovery never touches a cart; buy
  only on request after a final review.
- Sources: the launch post (shopping and checkout) and the safety post
  (single-use cards, approval of the exact purchase).
- Changed for Crawler: `web.*` and `browser.read` / `browser.act`; payment only
  through `browser.checkout` and its caps.
- Original text written for Crawler AI; no text copied. 2026-10-12.

## meal-planner

- Method: the examples in Meta's launch post: turning a saved recipe into a
  grocery list, and planning a dinner party around guests' dietary needs.
  Muse has no dedicated skill for this; the playbook is new.
- Sources: the launch post.
- Changed for Crawler: `web.fetch_page` and `video.transcript` (videos that
  publish captions) for recipes, `memory.remember` only for the user's own
  preferences, invitations left as drafts, no profiles of guests.
- Original text written for Crawler AI; no text copied. 2026-10-12.

## inbox-triage

- Method: "Muse for Small Business": flag the emails that need a reply and
  draft answers. The draft-first, recipient and failed-send rules follow
  Muse's Gmail skill, learned as described in the note on Muse above.
- Sources: the Small Business post and the safety post.
- Changed for Crawler: Gmail and Outlook reads, `create_draft` only; sending
  is the user's separate request on an approval card.
- Original text written for Crawler AI; no text copied. 2026-10-12.

## school-week-planner

- Method: Muse's goals-to-plan flow (launch post), applied to a student's
  week.
- Sources: the launch post.
- Changed for Crawler: Canvas, calendar, study and goals tools; tutor mode;
  no graded work done for the student.
- Original text written for Crawler AI; no text copied. 2026-10-12.

## skill-vetter

- Method: the four-step review (source, content, reach, risk), the red-flag
  list, the risk scale, the report format and "paranoia is a feature" from
  `skill-vetter` by spclaudehome (ClawHub, v1.0.0), as summarised in
  `docs/superpowers/specs/2026-09-25-skills-design.md` §9.2.
- Source: https://clawhub.ai/spclaudehome/skills/skill-vetter
- Changed for Crawler: the facts come from `skills.scan_report`; red flags are
  described in words; no "safe to install" verdict; only the owner's switch
  in Settings changes anything.
- Original text written for Crawler AI; no text copied, so the original's
  licence (as listed on its ClawHub page) does not apply to this file.
  2026-10-12.

## github

- Method: `github` by steipete (ClawHub, v1.0.0): always name the owner and
  repository; triage CI as checks, then the run, then the failed logs; facts
  before prose (2026-09-25 spec §9.3).
- Source: https://clawhub.ai/steipete/skills/github
- Changed for Crawler: every `gh` command mapped to a `github.*` read; sign-in
  left to the connector; writes drafted first and decided by their approval
  cards; no "keep going until merged" rule.
- Original text written for Crawler AI; no text copied, so the original's
  licence (as listed on its ClawHub page) does not apply to this file.
  2026-10-12.

## google-workspace

- Method: `gog` by steipete (ClawHub, v1.0.0): Gmail, Calendar, Drive,
  Contacts, Sheets and Docs coverage; confirm before sending mail or creating
  events; structured output first (2026-09-25 spec §9.5).
- Source: https://clawhub.ai/steipete/skills/gog
- Changed for Crawler: `google_workspace.*` actions, plus the Microsoft 365
  equivalents (`microsoft.*`); sign-in left to the connector; sends, shares,
  deletions and cleared ranges decided by approval cards.
- Original text written for Crawler AI; no text copied, so the original's
  licence (as listed on its ClawHub page) does not apply to this file.
  2026-10-12.
