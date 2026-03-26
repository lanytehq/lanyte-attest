use std::fs;
use std::path::Path;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::{AttestError, AttestPaths, AttestationClaims, Result};

const STATUS_ACTIVE: &str = "active";
const STATUS_ENDED: &str = "ended";
const STATUS_REVOKED: &str = "revoked";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Active,
    Ended,
    Revoked,
    Expired,
}

impl SessionState {
    fn as_db_str(self) -> Option<&'static str> {
        match self {
            Self::Active => Some(STATUS_ACTIVE),
            Self::Ended => Some(STATUS_ENDED),
            Self::Revoked => Some(STATUS_REVOKED),
            Self::Expired => None,
        }
    }

    fn as_status_str(self) -> &'static str {
        match self {
            Self::Active => STATUS_ACTIVE,
            Self::Ended => STATUS_ENDED,
            Self::Revoked => STATUS_REVOKED,
            Self::Expired => "expired",
        }
    }
}

#[derive(Debug)]
pub struct SessionRegistry {
    conn: Connection,
}

#[derive(Debug)]
struct SessionRow {
    jti: String,
    status: SessionState,
    exp: u64,
}

impl SessionRegistry {
    pub fn open(paths: &AttestPaths) -> Result<Self> {
        Self::open_db_path(&paths.sessions_db_path)
    }

    pub fn open_db_path(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            let paths = AttestPaths::from_root(parent.to_path_buf());
            paths.ensure_root_dir()?;
        }

        ensure_registry_file_ready(path)?;
        let conn = Connection::open(path)?;
        let registry = Self { conn };
        registry.init()?;
        Ok(registry)
    }

    pub fn open_db_path_read_only(path: &Path) -> Result<Self> {
        ensure_registry_file_ready_read_only(path)?;
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        Ok(Self { conn })
    }

    fn init(&self) -> Result<()> {
        self.conn.execute_batch(
            "BEGIN;
             CREATE TABLE IF NOT EXISTS sessions (
               jti TEXT PRIMARY KEY,
               sid TEXT NOT NULL,
               token_hash TEXT NOT NULL UNIQUE,
               issuer TEXT NOT NULL,
               subject TEXT NOT NULL,
               role TEXT NOT NULL,
               scope TEXT NOT NULL,
               ctx_hash TEXT NOT NULL,
               iat INTEGER NOT NULL,
               exp INTEGER NOT NULL,
               status TEXT NOT NULL CHECK(status IN ('active','ended','revoked')),
               created_at INTEGER NOT NULL,
               ended_at INTEGER,
               revoked_at INTEGER
             );
             CREATE INDEX IF NOT EXISTS idx_sessions_sid ON sessions (sid);
             CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions (status);
             COMMIT;",
        )?;
        Ok(())
    }

    pub fn record_session(
        &self,
        claims: &AttestationClaims,
        token_hash: &str,
        now: u64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO sessions (
                jti, sid, token_hash, issuer, subject, role, scope, ctx_hash, iat, exp, status, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                claims.jti,
                claims.sid,
                token_hash,
                claims.iss,
                claims.sub,
                claims.role,
                claims.scope,
                claims.ctx_hash,
                claims.iat as i64,
                claims.exp as i64,
                STATUS_ACTIVE,
                now as i64,
            ],
        )?;
        Ok(())
    }

    pub fn require_usable_session(
        &self,
        claims: &AttestationClaims,
        now: u64,
        action: &'static str,
    ) -> Result<()> {
        let row = self.lookup(&claims.jti)?;
        let state = canonical_state(row.status, row.exp, now);
        if state == SessionState::Active {
            return Ok(());
        }

        Err(AttestError::SessionNotUsable {
            jti: row.jti,
            status: state.as_status_str(),
            action,
        })
    }

    pub fn session_state(&self, jti: &str, now: u64) -> Result<SessionState> {
        let row = self.lookup(jti)?;
        Ok(canonical_state(row.status, row.exp, now))
    }

    pub fn end_session(&self, jti: &str, now: u64) -> Result<()> {
        self.transition(jti, now, STATUS_ENDED, "end")
    }

    pub fn revoke_session(&self, jti: &str, now: u64) -> Result<()> {
        self.transition(jti, now, STATUS_REVOKED, "revoke")
    }

    fn transition(
        &self,
        jti: &str,
        now: u64,
        target: &'static str,
        action: &'static str,
    ) -> Result<()> {
        let row = self.lookup(jti)?;
        let state = canonical_state(row.status, row.exp, now);
        if state != SessionState::Active {
            return Err(AttestError::SessionNotUsable {
                jti: row.jti,
                status: state.as_status_str(),
                action,
            });
        }

        let (timestamp_col, target_state) = match target {
            STATUS_ENDED => ("ended_at", SessionState::Ended),
            STATUS_REVOKED => ("revoked_at", SessionState::Revoked),
            _ => {
                return Err(AttestError::Validation(
                    "unsupported session transition".into(),
                ))
            }
        };

        let sql = format!("UPDATE sessions SET status = ?1, {timestamp_col} = ?2 WHERE jti = ?3");
        self.conn
            .execute(&sql, params![target_state.as_db_str(), now as i64, jti])?;
        Ok(())
    }

    fn lookup(&self, jti: &str) -> Result<SessionRow> {
        let row = self
            .conn
            .query_row(
                "SELECT jti, status, exp FROM sessions WHERE jti = ?1",
                params![jti],
                |row| {
                    let status: String = row.get(1)?;
                    Ok(SessionRow {
                        jti: row.get(0)?,
                        status: parse_db_status(&status),
                        exp: row.get::<_, i64>(2)? as u64,
                    })
                },
            )
            .optional()?;

        row.ok_or_else(|| AttestError::SessionNotFound {
            jti: jti.to_string(),
        })
    }
}

pub fn token_hash(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let mut out = String::from("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn parse_db_status(status: &str) -> SessionState {
    match status {
        STATUS_ACTIVE => SessionState::Active,
        STATUS_ENDED => SessionState::Ended,
        STATUS_REVOKED => SessionState::Revoked,
        _ => SessionState::Revoked,
    }
}

fn canonical_state(status: SessionState, exp: u64, now: u64) -> SessionState {
    if matches!(status, SessionState::Revoked | SessionState::Ended) {
        return status;
    }
    if exp <= now {
        return SessionState::Expired;
    }
    SessionState::Active
}

fn ensure_registry_file_ready(path: &Path) -> Result<()> {
    if !path.exists() {
        create_registry_file(path)?;
        return Ok(());
    }

    ensure_existing_registry_file_ready(path)
}

fn ensure_registry_file_ready_read_only(path: &Path) -> Result<()> {
    if !path.exists() {
        return Err(AttestError::MissingRevocationRegistry(path.to_path_buf()));
    }

    ensure_existing_registry_file_ready(path)
}

fn ensure_existing_registry_file_ready(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(AttestError::ExpectedFilePath(path.to_path_buf()));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let actual = metadata.permissions().mode() & 0o777;
        if actual != 0o600 {
            return Err(AttestError::InsecureFilePermissions {
                path: path.to_path_buf(),
                actual,
                required: 0o600,
            });
        }
    }

    Ok(())
}

fn create_registry_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
    }

    #[cfg(not(unix))]
    {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{token_hash, SessionRegistry};
    use crate::{AttestError, AttestPaths, AttestationClaims};

    fn fixture_claims() -> AttestationClaims {
        AttestationClaims {
            iss: "lanyte-attest".to_string(),
            sub: "3leapsdave".to_string(),
            sid: "123e4567-e89b-12d3-a456-426614174000".to_string(),
            role: "devlead".to_string(),
            scope: "lanytehq/core-runtime".to_string(),
            iat: 1_740_000_000,
            exp: 1_740_028_800,
            jti: "123e4567-e89b-12d3-a456-426614174001".to_string(),
            ctx_hash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
        }
    }

    #[test]
    fn records_and_allows_active_session() {
        let dir = tempdir().expect("temp dir");
        let paths = AttestPaths::from_root(dir.path().join("attest"));
        let registry = SessionRegistry::open(&paths).expect("registry open");
        let claims = fixture_claims();

        registry
            .record_session(&claims, &token_hash("token"), claims.iat)
            .expect("record session");
        registry
            .require_usable_session(&claims, claims.iat + 1, "verify")
            .expect("active session should be usable");
    }

    #[test]
    fn rejects_ended_session_via_canonical_path() {
        let dir = tempdir().expect("temp dir");
        let paths = AttestPaths::from_root(dir.path().join("attest"));
        let registry = SessionRegistry::open(&paths).expect("registry open");
        let claims = fixture_claims();

        registry
            .record_session(&claims, &token_hash("token"), claims.iat)
            .expect("record session");
        registry
            .end_session(&claims.jti, claims.iat + 10)
            .expect("end session");

        let err = registry
            .require_usable_session(&claims, claims.iat + 11, "verify")
            .expect_err("ended session must fail");
        assert!(matches!(
            err,
            AttestError::SessionNotUsable {
                status: "ended",
                ..
            }
        ));
    }

    #[test]
    fn rejects_revoked_session_via_canonical_path() {
        let dir = tempdir().expect("temp dir");
        let paths = AttestPaths::from_root(dir.path().join("attest"));
        let registry = SessionRegistry::open(&paths).expect("registry open");
        let claims = fixture_claims();

        registry
            .record_session(&claims, &token_hash("token"), claims.iat)
            .expect("record session");
        registry
            .revoke_session(&claims.jti, claims.iat + 10)
            .expect("revoke session");

        let err = registry
            .require_usable_session(&claims, claims.iat + 11, "verify")
            .expect_err("revoked session must fail");
        assert!(matches!(
            err,
            AttestError::SessionNotUsable {
                status: "revoked",
                ..
            }
        ));
    }

    #[test]
    fn rejects_expired_session_via_canonical_path() {
        let dir = tempdir().expect("temp dir");
        let paths = AttestPaths::from_root(dir.path().join("attest"));
        let registry = SessionRegistry::open(&paths).expect("registry open");
        let claims = fixture_claims();

        registry
            .record_session(&claims, &token_hash("token"), claims.iat)
            .expect("record session");

        let err = registry
            .require_usable_session(&claims, claims.exp, "verify")
            .expect_err("expired session must fail");
        assert!(matches!(
            err,
            AttestError::SessionNotUsable {
                status: "expired",
                ..
            }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn creates_registry_file_with_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("temp dir");
        let paths = AttestPaths::from_root(dir.path().join("attest"));
        let _registry = SessionRegistry::open(&paths).expect("registry open");

        let mode = std::fs::metadata(&paths.sessions_db_path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_insecure_registry_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("temp dir");
        let paths = AttestPaths::from_root(dir.path().join("attest"));
        let _registry = SessionRegistry::open(&paths).expect("registry open");
        std::fs::set_permissions(
            &paths.sessions_db_path,
            std::fs::Permissions::from_mode(0o644),
        )
        .expect("chmod insecure db");

        let err = SessionRegistry::open(&paths).expect_err("insecure db perms must fail");
        assert!(matches!(
            err,
            AttestError::InsecureFilePermissions {
                required: 0o600,
                ..
            }
        ));
    }
}
