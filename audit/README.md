# Audit database

`audit.sqlite` is the shared store for the security audit (it is gitignored by
`*.sqlite`; `schema.sql` recreates it). Several agents work on it at once.

## Connecting

Every connection must set:

```sql
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
```

The database is in WAL mode, so readers never block writers. Keep write
transactions short.

## Protocol

1. **Register** once: `INSERT OR IGNORE INTO agents(name, scope) VALUES ('<you>', '<files>');`
2. **Check before filing**: `SELECT id, title FROM findings WHERE file = ? AND line BETWEEN ? - 10 AND ? + 10;`
   If one already covers it, add a note to it instead of a new finding.
3. **File** a finding: one row per defect, paths repo-relative, `line = 0` for a
   whole-file issue. `failure_scenario` must be concrete (input/state, then the
   bad outcome). `UNIQUE(file, line, title)` rejects exact repeats.
4. **Claim** before verifying or fixing someone else's finding, atomically:
   `UPDATE findings SET claimed_by = '<you>' WHERE id = ? AND claimed_by IS NULL;`
   then check `changes()` is 1. Clear `claimed_by` when done.
5. **Verify / dispute** with a note (`kind` = `verify`, `dispute`, `fix` or
   `comment`), then move the status: `confirmed`, `disputed`, `fixed`,
   `wontfix`, or `duplicate` (which requires `duplicate_of`).

## Useful queries

```sql
SELECT * FROM triage;                                   -- open work, worst first
SELECT * FROM findings WHERE updated_at > '2026-11-12T00:00:00Z';  -- what changed
SELECT n.created_at, n.author, n.kind, n.body FROM notes n WHERE finding_id = ?;
SELECT severity, status, COUNT(*) FROM findings GROUP BY 1, 2;
```

## Vocabularies

- `severity`: `high`, `medium`, `low`, `style`
- `category`: `overflow`, `underflow`, `cast`, `panic`, `unbounded-alloc`,
  `memory`, `logic`, `concurrency`, `auth`, `timing`, `injection`,
  `secret-leak`, `dos`, `newtype`, `type-design`, `unidiomatic`, `config`,
  `ci`, `other`
- `status`: `open`, `confirmed`, `disputed`, `duplicate`, `fixed`, `wontfix`
