//! Fixed, deliberately unexecuted DDL for the exact repository-proof step.
//! Ordinary create/open/migration paths do not reference these constants.

/// Repository table and immutable identity trigger for control 2 -> 3.
pub const CONTROL_TABLES: &str = r#"CREATE TABLE repository_metadata_grants (
  grant_id TEXT NOT NULL PRIMARY KEY
    CHECK(length(grant_id) BETWEEN 1 AND 128 AND grant_id NOT GLOB '*[^A-Za-z0-9_-]*'),
  worktree_locator TEXT NOT NULL
    CHECK(length(CAST(worktree_locator AS BLOB)) BETWEEN 1 AND 8192),
  worktree_identity TEXT NOT NULL CHECK(length(worktree_identity)=72),
  gitdir_name TEXT NOT NULL CHECK(gitdir_name='.git'),
  gitdir_identity TEXT NOT NULL CHECK(length(gitdir_identity)=72),
  authorization_revision INTEGER NOT NULL CHECK(authorization_revision>=1),
  enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
  authorization_seq INTEGER NOT NULL CHECK(authorization_seq>=1),
  denial_seq INTEGER NOT NULL CHECK(denial_seq>=1),
  denial_token TEXT NOT NULL
    CHECK(length(denial_token) BETWEEN 1 AND 128 AND denial_token NOT GLOB '*[^A-Za-z0-9_-]*'),
  accepted_revision INTEGER,
  accepted_observation_id TEXT,
  accepted_snapshot_blake3 BLOB,
  accepted_value_revision BLOB,
  accepted_denial_token TEXT,
  accepted_control_seq INTEGER,
  UNIQUE(worktree_identity,gitdir_identity),
  CHECK(
    (accepted_revision IS NULL AND accepted_observation_id IS NULL
      AND accepted_snapshot_blake3 IS NULL AND accepted_value_revision IS NULL
      AND accepted_denial_token IS NULL AND accepted_control_seq IS NULL)
    OR
    (accepted_revision IS NOT NULL AND accepted_revision>=1
      AND accepted_revision<=authorization_revision
      AND accepted_observation_id IS NOT NULL
      AND length(accepted_observation_id) BETWEEN 1 AND 128
      AND accepted_observation_id NOT GLOB '*[^A-Za-z0-9_-]*'
      AND accepted_snapshot_blake3 IS NOT NULL
      AND typeof(accepted_snapshot_blake3)='blob' AND length(accepted_snapshot_blake3)=32
      AND accepted_value_revision IS NOT NULL
      AND typeof(accepted_value_revision)='blob' AND length(accepted_value_revision)=32
      AND accepted_denial_token IS NOT NULL
      AND length(accepted_denial_token) BETWEEN 1 AND 128
      AND accepted_denial_token NOT GLOB '*[^A-Za-z0-9_-]*'
      AND accepted_control_seq IS NOT NULL AND accepted_control_seq>=1)
  )
);
CREATE TRIGGER repository_metadata_grant_identity_immutable
BEFORE UPDATE OF grant_id,worktree_locator,worktree_identity,gitdir_name,gitdir_identity
ON repository_metadata_grants
WHEN NEW.grant_id<>OLD.grant_id OR NEW.worktree_locator<>OLD.worktree_locator
  OR NEW.worktree_identity<>OLD.worktree_identity OR NEW.gitdir_name<>OLD.gitdir_name
  OR NEW.gitdir_identity<>OLD.gitdir_identity
BEGIN SELECT RAISE(ABORT,'immutable repository grant identity'); END;"#;

/// Three repository tables, indexes and immutable receipt triggers for catalog 22 -> 23.
pub const CATALOG_TABLES: &str = r#"CREATE TABLE repository_metadata_receipts (
  observation_id TEXT NOT NULL PRIMARY KEY
    CHECK(length(observation_id) BETWEEN 1 AND 128 AND observation_id NOT GLOB '*[^A-Za-z0-9_-]*'),
  grant_id TEXT NOT NULL
    CHECK(length(grant_id) BETWEEN 1 AND 128 AND grant_id NOT GLOB '*[^A-Za-z0-9_-]*'),
  authorization_revision INTEGER NOT NULL CHECK(authorization_revision>=1),
  observation_seq INTEGER NOT NULL CHECK(observation_seq>=1),
  denial_token TEXT NOT NULL
    CHECK(length(denial_token) BETWEEN 1 AND 128 AND denial_token NOT GLOB '*[^A-Za-z0-9_-]*'),
  resolution TEXT NOT NULL CHECK(resolution IN ('resolved','absent','unresolved')),
  snapshot_blake3 BLOB,
  snapshot_size_bytes INTEGER,
  value_revision BLOB,
  repo_slug TEXT,
  reason TEXT,
  cycle_seq INTEGER NOT NULL CHECK(cycle_seq>=1),
  worker_boot_id TEXT NOT NULL CHECK(length(worker_boot_id) BETWEEN 1 AND 128),
  started_control_seq INTEGER NOT NULL CHECK(started_control_seq>=0),
  policy_epoch INTEGER NOT NULL CHECK(policy_epoch>=0 AND policy_epoch<=started_control_seq),
  catalog_incarnation TEXT NOT NULL CHECK(length(catalog_incarnation) BETWEEN 1 AND 128),
  published INTEGER NOT NULL CHECK(published IN (0,1)),
  observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms>=0),
  committed_generation INTEGER,
  committed_at_ms INTEGER,
  UNIQUE(grant_id,observation_seq),
  UNIQUE(grant_id,observation_id),
  CHECK((snapshot_blake3 IS NULL AND snapshot_size_bytes IS NULL)
    OR (snapshot_blake3 IS NOT NULL AND typeof(snapshot_blake3)='blob'
      AND length(snapshot_blake3)=32 AND snapshot_size_bytes IS NOT NULL
      AND snapshot_size_bytes BETWEEN 0 AND 65536)),
  CHECK((resolution='resolved' AND snapshot_blake3 IS NOT NULL
      AND value_revision IS NOT NULL AND typeof(value_revision)='blob'
      AND length(value_revision)=32 AND repo_slug IS NOT NULL
      AND length(CAST(repo_slug AS BLOB)) BETWEEN 1 AND 512 AND reason IS NULL)
    OR (resolution='absent' AND snapshot_blake3 IS NOT NULL
      AND value_revision IS NOT NULL AND typeof(value_revision)='blob'
      AND length(value_revision)=32 AND repo_slug IS NULL AND reason IS NULL)
    OR (resolution='unresolved' AND value_revision IS NULL AND repo_slug IS NULL
      AND reason IS NOT NULL AND length(reason) BETWEEN 1 AND 64
      AND reason NOT GLOB '*[^a-z_]*' AND published=0)),
  CHECK((published=0 AND committed_generation IS NULL AND committed_at_ms IS NULL)
    OR (published=1 AND resolution IN ('resolved','absent')
      AND committed_generation IS NOT NULL AND committed_generation>=0
      AND committed_at_ms IS NOT NULL AND committed_at_ms>=observed_at_ms))
);
CREATE TABLE repository_metadata_heads (
  grant_id TEXT NOT NULL PRIMARY KEY,
  authorization_revision INTEGER NOT NULL CHECK(authorization_revision>=1),
  last_observation_seq INTEGER NOT NULL CHECK(last_observation_seq>=1),
  last_attempt_id TEXT NOT NULL,
  last_published_id TEXT,
  FOREIGN KEY(grant_id,last_attempt_id)
    REFERENCES repository_metadata_receipts(grant_id,observation_id),
  FOREIGN KEY(grant_id,last_published_id)
    REFERENCES repository_metadata_receipts(grant_id,observation_id)
);
CREATE TABLE source_repository_proofs (
  proof_id TEXT NOT NULL PRIMARY KEY
    CHECK(length(proof_id) BETWEEN 1 AND 128 AND proof_id NOT GLOB '*[^A-Za-z0-9_-]*'),
  source_id TEXT NOT NULL REFERENCES source_bindings(source_id),
  source_revision_id TEXT NOT NULL REFERENCES source_revision_receipts(revision_id),
  session_id TEXT NOT NULL CHECK(length(CAST(session_id AS BLOB)) BETWEEN 1 AND 256),
  proof_ordinal INTEGER NOT NULL CHECK(proof_ordinal>=0),
  origin TEXT NOT NULL CHECK(origin IN ('transcript','metadata')),
  resolution TEXT NOT NULL CHECK(resolution IN
    ('missing','resolved','ambiguous','unusable','absent','unresolved','denied')),
  source_snapshot_blake3 BLOB NOT NULL
    CHECK(typeof(source_snapshot_blake3)='blob' AND length(source_snapshot_blake3)=32),
  anchor_kind TEXT,
  anchor_start INTEGER,
  anchor_end INTEGER,
  repo_slug TEXT,
  grant_id TEXT,
  authorization_revision INTEGER,
  metadata_observation_id TEXT REFERENCES repository_metadata_receipts(observation_id),
  metadata_value_revision BLOB,
  reason TEXT,
  UNIQUE(source_revision_id,session_id,proof_ordinal),
  CHECK((resolution='resolved' AND repo_slug IS NOT NULL
      AND length(CAST(repo_slug AS BLOB)) BETWEEN 1 AND 512)
    OR (resolution<>'resolved' AND repo_slug IS NULL)),
  CHECK((reason IS NULL) OR (length(reason) BETWEEN 1 AND 64 AND reason NOT GLOB '*[^a-z_]*')),
CHECK (
  (origin='transcript' AND (
    (resolution='missing'
      AND anchor_kind IS NULL AND anchor_start IS NULL AND anchor_end IS NULL)
    OR
    (resolution='resolved'
      AND typeof(anchor_kind)='text' AND anchor_kind='repository'
      AND typeof(anchor_start)='integer' AND typeof(anchor_end)='integer'
      AND anchor_start>=0 AND anchor_end>anchor_start)
    OR
    (resolution IN ('ambiguous','unusable') AND (
      (anchor_kind IS NULL AND anchor_start IS NULL AND anchor_end IS NULL)
      OR
      (typeof(anchor_kind)='text' AND anchor_kind='repository'
        AND typeof(anchor_start)='integer' AND typeof(anchor_end)='integer'
        AND anchor_start>=0 AND anchor_end>anchor_start)
    ))
  ))
  OR
  (origin='metadata'
    AND typeof(anchor_kind)='text' AND anchor_kind='cwd_pair'
    AND typeof(anchor_start)='integer' AND typeof(anchor_end)='integer'
    AND anchor_start>=0 AND anchor_end>anchor_start)
),
  CHECK((origin='transcript' AND resolution IN ('missing','resolved','ambiguous','unusable')
      AND grant_id IS NULL AND authorization_revision IS NULL
      AND metadata_observation_id IS NULL AND metadata_value_revision IS NULL)
    OR (origin='metadata' AND resolution IN ('resolved','absent','unresolved','denied')
      AND grant_id IS NOT NULL AND length(grant_id) BETWEEN 1 AND 128
      AND grant_id NOT GLOB '*[^A-Za-z0-9_-]*'
      AND authorization_revision IS NOT NULL AND authorization_revision>=1
      AND ((resolution IN ('resolved','absent') AND metadata_observation_id IS NOT NULL
          AND metadata_value_revision IS NOT NULL AND typeof(metadata_value_revision)='blob'
          AND length(metadata_value_revision)=32)
        OR (resolution IN ('unresolved','denied') AND metadata_value_revision IS NULL))))
);
CREATE INDEX repository_metadata_receipts_grant_revision
  ON repository_metadata_receipts(grant_id,authorization_revision,observation_seq);
CREATE INDEX source_repository_proofs_source_session
  ON source_repository_proofs(source_revision_id,session_id,proof_ordinal);
CREATE INDEX source_repository_proofs_grant
  ON source_repository_proofs(grant_id,authorization_revision,source_id,source_revision_id);
CREATE INDEX source_repository_proofs_observation
  ON source_repository_proofs(metadata_observation_id);
CREATE INDEX source_repository_proofs_session
  ON source_repository_proofs(session_id,source_revision_id);
CREATE TRIGGER repository_metadata_receipt_immutable
BEFORE UPDATE ON repository_metadata_receipts
BEGIN SELECT RAISE(ABORT,'immutable repository observation'); END;
CREATE TRIGGER source_repository_proof_immutable
BEFORE UPDATE ON source_repository_proofs
BEGIN SELECT RAISE(ABORT,'immutable repository proof'); END;"#;

/// Added only by the future catalog component transaction.
pub const CATALOG_RECEIPT_COLUMN: &str = r#"ALTER TABLE catalog_meta ADD COLUMN repository_transition_receipt BLOB
  CHECK(repository_transition_receipt IS NULL OR
    (typeof(repository_transition_receipt)='blob'
      AND length(repository_transition_receipt) BETWEEN 1 AND 8192));"#;

/// Added only by the future control component transaction.
pub const CONTROL_RECEIPT_COLUMN: &str = r#"ALTER TABLE control_meta ADD COLUMN repository_transition_receipt BLOB
  CHECK(repository_transition_receipt IS NULL OR
    (typeof(repository_transition_receipt)='blob'
      AND length(repository_transition_receipt) BETWEEN 1 AND 8192));"#;
