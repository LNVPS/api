# Incremental Work Tracking

Work files track the state of multi-increment tasks so any agent or human can resume without losing context. See
`AGENTS.md` for when a work file is required.

## File Location and Naming

```
work/<short-slug>.md
```

Examples:

- `work/coverage-lnvps-api-admin.md`
- `work/import-order-audit.md`
- `work/api-changelog-sync.md`

## File Structure

```markdown
# <Title>

**Status:** in-progress | blocked | complete
**Started:** YYYY-MM-DD
**Last updated:** YYYY-MM-DD

## Goal

One or two sentences describing what done looks like.

## Findings

Anything discovered so far that informs remaining work.
Keep this updated as you learn more.

## Tasks

- [x] Completed step
- [ ] Pending step
- [ ] Another pending step

## Notes

Optional. Blockers, decisions made, links to relevant files.
```

## Workflow

1. **Create the file** at the start of the first session, with all known tasks listed.
2. **Update tasks in real time** — mark `[x]` as each step finishes, add new tasks as they are discovered.
3. **Update "Last updated"** and "Findings" at the end of each session.
4. **Set Status to `complete`** and add a brief summary under Findings when all tasks are done.

## Picking Up Existing Work

When resuming a task:

1. Read the work file first.
2. Re-read only the files listed in Findings / Notes — do not re-scan the whole codebase.
3. **Re-evaluate the remaining tasks** against the current state of the codebase. Code may have changed since the file
   was last updated. Add any newly discovered tasks before proceeding, and remove or mark cancelled any tasks that are
   no longer relevant.
4. Continue from the first unchecked task.
5. Update the file as you go.

## Closing Out

When all tasks are checked off, set `Status: complete`. Work files are **not deleted** — they serve as a record of what
was done and why.
