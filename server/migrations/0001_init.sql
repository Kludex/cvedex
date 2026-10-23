CREATE TABLE submitters (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  disabled_at TEXT
);

CREATE TABLE tokens (
  id INTEGER PRIMARY KEY,
  submitter_id INTEGER NOT NULL REFERENCES submitters (id),
  kind TEXT NOT NULL CHECK (kind IN ('user', 'agent')),
  token_sha256 TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  last_used_at TEXT,
  revoked_at TEXT
);

CREATE TABLE cves (
  cve_id TEXT PRIMARY KEY,
  submitter_id INTEGER NOT NULL REFERENCES submitters (id),
  state TEXT NOT NULL
    CHECK (state IN ('reserved', 'in_review', 'publishing', 'published', 'rejected')),
  action TEXT CHECK (action IN ('publish', 'reject')),
  record TEXT,
  revision INTEGER NOT NULL DEFAULT 0,
  published_revision INTEGER,
  note TEXT,
  reserved_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  published_at TEXT
);

CREATE TABLE revisions (
  cve_id TEXT NOT NULL REFERENCES cves (cve_id),
  revision INTEGER NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('publish', 'reject')),
  record TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  PRIMARY KEY (cve_id, revision)
);

CREATE TRIGGER cves_revision AFTER UPDATE OF revision ON cves
BEGIN
  INSERT INTO revisions (cve_id, revision, action, record)
  VALUES (NEW.cve_id, NEW.revision, NEW.action, NEW.record);
END;

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

CREATE INDEX proposals_pending ON proposals (submitter_id, status);

-- A row is written before the request runs and gets its status when it ends. A NULL status means
-- the request never finished, so its outcome is unknown.
CREATE TABLE audit (
  id INTEGER PRIMARY KEY,
  ts TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  actor TEXT NOT NULL,
  actor_kind TEXT NOT NULL CHECK (actor_kind IN ('cna_user', 'submitter', 'agent')),
  token_id INTEGER,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  status INTEGER,
  body_sha256 TEXT,
  proposal_id TEXT
);

CREATE INDEX audit_actor_ts ON audit (actor, ts);

CREATE TRIGGER audit_no_update BEFORE UPDATE OF id, ts, actor, actor_kind, token_id, method, path,
  body_sha256 ON audit
BEGIN
  SELECT RAISE(ABORT, 'audit is insert-only');
END;

CREATE TRIGGER audit_status_once BEFORE UPDATE OF status, proposal_id ON audit
WHEN OLD.status IS NOT NULL
BEGIN
  SELECT RAISE(ABORT, 'audit is insert-only');
END;

CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit
BEGIN
  SELECT RAISE(ABORT, 'audit is insert-only');
END;
