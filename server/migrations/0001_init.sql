CREATE TABLE submitters (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE tokens (
  id INTEGER PRIMARY KEY,
  submitter_id INTEGER NOT NULL REFERENCES submitters (id),
  kind TEXT NOT NULL CHECK (kind IN ('user', 'agent')),
  token_sha256 TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE cves (
  cve_id TEXT PRIMARY KEY,
  submitter_id INTEGER NOT NULL REFERENCES submitters (id),
  state TEXT NOT NULL CHECK (state IN ('reserved', 'in_review', 'published')),
  record TEXT,
  note TEXT,
  reserved_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  published_at TEXT
);

CREATE TABLE proposals (
  id TEXT PRIMARY KEY,
  submitter_id INTEGER NOT NULL REFERENCES submitters (id),
  token_id INTEGER NOT NULL REFERENCES tokens (id),
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  body TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  decided_at TEXT
);

CREATE TABLE audit (
  id INTEGER PRIMARY KEY,
  ts TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  actor TEXT,
  actor_kind TEXT CHECK (actor_kind IN ('cna_user', 'submitter', 'agent')),
  token_id INTEGER,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  status INTEGER NOT NULL,
  body_sha256 TEXT,
  proposal_id TEXT
);

CREATE INDEX audit_actor_ts ON audit (actor, ts);

CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit
BEGIN
  SELECT RAISE(ABORT, 'audit is insert-only');
END;

CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit
BEGIN
  SELECT RAISE(ABORT, 'audit is insert-only');
END;
