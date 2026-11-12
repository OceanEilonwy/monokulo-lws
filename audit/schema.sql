-- Shared store for the security audit. Several agents read and write it at
-- once, so it runs in WAL mode; every connection should also set
--   PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;

PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS agents (
    name       TEXT PRIMARY KEY,           -- e.g. 'scanner-auditor', 'lead'
    scope      TEXT NOT NULL,              -- files or topic this agent covers
    started_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE IF NOT EXISTS findings (
    id               INTEGER PRIMARY KEY,
    file             TEXT NOT NULL,        -- repo-relative path
    line             INTEGER NOT NULL CHECK (line >= 0),   -- 0 = whole file
    end_line         INTEGER CHECK (end_line IS NULL OR end_line >= line),
    severity         TEXT NOT NULL CHECK (severity IN ('high','medium','low','style')),
    category         TEXT NOT NULL CHECK (category IN (
                         'overflow','underflow','cast','panic','unbounded-alloc',
                         'memory','logic','concurrency','auth','timing','injection',
                         'secret-leak','dos','newtype','type-design','unidiomatic',
                         'config','ci','other')),
    title            TEXT NOT NULL,        -- one line, the claim
    detail           TEXT NOT NULL DEFAULT '',
    failure_scenario TEXT NOT NULL DEFAULT '',  -- concrete input/state -> bad outcome
    fix              TEXT NOT NULL DEFAULT '',  -- suggested remedy
    reporter         TEXT NOT NULL REFERENCES agents(name),
    status           TEXT NOT NULL DEFAULT 'open' CHECK (status IN (
                         'open','confirmed','disputed','duplicate','fixed','wontfix')),
    duplicate_of     INTEGER REFERENCES findings(id),
    claimed_by       TEXT REFERENCES agents(name),  -- agent currently verifying/fixing it
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    CHECK ((status = 'duplicate') = (duplicate_of IS NOT NULL)),
    UNIQUE (file, line, title)
);

CREATE INDEX IF NOT EXISTS findings_file   ON findings(file, line);
CREATE INDEX IF NOT EXISTS findings_status ON findings(status, severity);

-- Discussion on a finding: verification results, disputes, fix notes.
CREATE TABLE IF NOT EXISTS notes (
    id         INTEGER PRIMARY KEY,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    author     TEXT NOT NULL REFERENCES agents(name),
    kind       TEXT NOT NULL CHECK (kind IN ('comment','verify','dispute','fix')),
    body       TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE INDEX IF NOT EXISTS notes_finding ON notes(finding_id);

CREATE TRIGGER IF NOT EXISTS findings_touch AFTER UPDATE ON findings
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE findings SET updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = NEW.id;
END;

-- A note touches its finding, so "what changed since X" is one query.
CREATE TRIGGER IF NOT EXISTS notes_touch AFTER INSERT ON notes
BEGIN
    UPDATE findings SET updated_at = NEW.created_at WHERE id = NEW.finding_id;
END;

CREATE VIEW IF NOT EXISTS triage AS
SELECT f.id, f.severity, f.status, f.category, f.file || ':' || f.line AS location,
       f.title, f.reporter, f.claimed_by,
       (SELECT COUNT(*) FROM notes n WHERE n.finding_id = f.id) AS notes
FROM findings f
WHERE f.status NOT IN ('duplicate','fixed','wontfix')
ORDER BY CASE f.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END,
         f.file, f.line;
