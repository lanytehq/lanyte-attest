use std::path::{Path, PathBuf};

use seclusor_crypto::SigningPublicKey;

use crate::{
    load_trust_config, AttestPaths, AttestationClaims, Result, SessionRegistry, SessionState,
    VerificationPolicy,
};

pub type PublicKey = SigningPublicKey;
pub type ValidatedClaims = AttestationClaims;
pub type RevocationStatus = SessionState;

pub fn default_public_key_path() -> Result<PathBuf> {
    Ok(AttestPaths::resolve_trusted_verify()?.public_key_path)
}

pub fn default_sessions_db_path() -> Result<PathBuf> {
    Ok(AttestPaths::resolve_trusted_verify()?.sessions_db_path)
}

pub fn load_public_key(path: Option<&Path>) -> Result<PublicKey> {
    match path {
        Some(path) => crate::load_public_key_from_path(path),
        None => crate::load_public_key(&AttestPaths::resolve_trusted_verify()?),
    }
}

pub fn policy_from_current_time() -> Result<VerificationPolicy> {
    let mut policy = VerificationPolicy::from_current_time()?;
    policy.expected_issuer = Some(resolve_expected_issuer()?);
    Ok(policy)
}

pub fn resolve_expected_issuer() -> Result<String> {
    Ok(load_trust_config(&AttestPaths::resolve_trusted_verify()?)?.issuer)
}

pub fn validate_token(
    token: &str,
    public_key: &PublicKey,
    policy: &VerificationPolicy,
) -> Result<ValidatedClaims> {
    crate::verify_attestation_token(token, public_key, policy)
}

pub fn check_revocation(jti: &str, sessions_db_path: Option<&Path>) -> Result<RevocationStatus> {
    check_revocation_at_time(
        jti,
        sessions_db_path,
        crate::token::current_unix_seconds_for_verify()?,
    )
}

pub fn check_revocation_at_time(
    jti: &str,
    sessions_db_path: Option<&Path>,
    now: u64,
) -> Result<RevocationStatus> {
    let registry = match sessions_db_path {
        Some(path) => SessionRegistry::open_db_path_read_only(path)?,
        None => SessionRegistry::open_db_path_read_only(&default_sessions_db_path()?)?,
    };
    registry.session_state(jti, now)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tempfile::tempdir;

    use super::{
        check_revocation_at_time, default_public_key_path, default_sessions_db_path,
        policy_from_current_time, resolve_expected_issuer,
    };
    use crate::{
        write_trust_config, AttestError, AttestPaths, AttestationClaims, SessionRegistry,
        SessionState,
    };

    static ENV_LOCK: Mutex<()> = Mutex::new(());

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
    fn default_verify_paths_resolve_inside_attest_home() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let dir = tempdir().expect("temp dir");
        std::env::set_var("HOME", dir.path());
        std::env::set_var("LANYTE_ATTEST_HOME", dir.path().join("attacker-root"));
        let trusted_paths = AttestPaths::resolve_trusted_verify().expect("trusted paths");
        write_trust_config(&trusted_paths, None).expect("trust config");

        let public_key_path = default_public_key_path().expect("public key path");
        let sessions_db_path = default_sessions_db_path().expect("sessions db path");

        assert_eq!(
            public_key_path,
            dir.path().join(".lanyte/attest/signing-key.pub")
        );
        assert_eq!(
            sessions_db_path,
            dir.path().join(".lanyte/attest/sessions.db")
        );

        std::env::remove_var("LANYTE_ATTEST_HOME");
        std::env::remove_var("HOME");
    }

    #[test]
    fn resolve_expected_issuer_uses_env_override() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let dir = tempdir().expect("temp dir");
        std::env::set_var("HOME", dir.path());
        let trusted_paths = AttestPaths::resolve_trusted_verify().expect("trusted paths");
        write_trust_config(&trusted_paths, Some("lanyte-dev.local")).expect("trust config");

        let issuer = resolve_expected_issuer().expect("issuer should resolve");
        assert_eq!(issuer, "lanyte-dev.local");

        std::env::remove_var("HOME");
    }

    #[test]
    fn policy_from_current_time_sets_default_issuer() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let dir = tempdir().expect("temp dir");
        std::env::set_var("HOME", dir.path());
        let trusted_paths = AttestPaths::resolve_trusted_verify().expect("trusted paths");
        write_trust_config(&trusted_paths, None).expect("trust config");

        let policy = policy_from_current_time().expect("policy should resolve");
        assert_eq!(policy.expected_issuer.as_deref(), Some("lanyte-attest"));

        std::env::remove_var("HOME");
    }

    #[test]
    fn check_revocation_reports_active_state() {
        let dir = tempdir().expect("temp dir");
        let paths = AttestPaths::from_root(dir.path().join("attest"));
        let registry = SessionRegistry::open(&paths).expect("registry open");
        let claims = fixture_claims();

        registry
            .record_session(&claims, "sha256:test", claims.iat)
            .expect("record session");

        let status =
            check_revocation_at_time(&claims.jti, Some(&paths.sessions_db_path), claims.iat + 1)
                .expect("revocation check");
        assert_eq!(status, SessionState::Active);
    }

    #[test]
    fn check_revocation_reports_missing_session() {
        let dir = tempdir().expect("temp dir");
        let paths = AttestPaths::from_root(dir.path().join("attest"));
        let _registry = SessionRegistry::open(&paths).expect("registry open");
        let err = check_revocation_at_time(
            "123e4567-e89b-12d3-a456-426614174001",
            Some(&paths.sessions_db_path),
            1_740_000_001,
        )
        .expect_err("missing session must fail");

        assert!(matches!(err, AttestError::SessionNotFound { .. }));
    }

    #[test]
    fn check_revocation_fails_read_only_when_registry_missing() {
        let dir = tempdir().expect("temp dir");
        let paths = AttestPaths::from_root(dir.path().join("attest"));

        let err = check_revocation_at_time(
            "123e4567-e89b-12d3-a456-426614174001",
            Some(&paths.sessions_db_path),
            1_740_000_001,
        )
        .expect_err("missing registry must fail");

        assert!(
            matches!(err, AttestError::MissingRevocationRegistry(path) if path == paths.sessions_db_path)
        );
    }
}
