#[cfg(feature = "cli")]
mod cli;
mod error;
mod key_material;
mod naming;
mod paths;
mod session_registry;
mod token;
mod trust;
pub mod verify;

#[cfg(feature = "cli")]
use std::env;
#[cfg(feature = "cli")]
use std::process::Command as ProcessCommand;

#[cfg(feature = "cli")]
use uuid::Uuid;
#[cfg(feature = "cli")]
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "cli")]
pub use cli::{BeginArgs, Cli, Command, KeygenArgs, RevokeArgs, VerifyArgs};
pub use error::{AttestError, Result};
#[cfg(feature = "issue")]
pub use key_material::{generate_key_material, load_secret_key, write_key_material};
pub use key_material::{load_public_key, load_public_key_from_path};
pub use naming::{validate_instance_name, validate_role_slug, validate_scope_path};
pub use paths::AttestPaths;
pub use session_registry::{token_hash, SessionRegistry, SessionState};
#[cfg(feature = "issue")]
pub use token::mint_attestation_token;
pub use token::{verify_attestation_token, AttestationClaims, VerificationPolicy};
#[cfg(feature = "issue")]
pub use trust::write_trust_config;
pub use trust::{load_trust_config, TrustConfig};

#[cfg(feature = "cli")]
pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Keygen(args) => {
            let paths = resolve_keygen_paths(&args)?;
            keygen(args, &paths)
        }
        Command::Begin(args) => {
            let paths = AttestPaths::resolve()?;
            begin(args, &paths)
        }
        Command::Verify(args) => {
            let paths = AttestPaths::resolve()?;
            verify_command(args, &paths)
        }
        Command::End => {
            let paths = AttestPaths::resolve()?;
            end(&paths)
        }
        Command::Revoke(args) => {
            let paths = AttestPaths::resolve()?;
            revoke(args, &paths)
        }
    }
}

#[cfg(feature = "cli")]
fn resolve_keygen_paths(args: &KeygenArgs) -> Result<AttestPaths> {
    if let Some(output) = &args.output {
        if output.as_os_str().is_empty() {
            return Err(AttestError::Validation("--output must not be empty".into()));
        }
        Ok(AttestPaths::from_root(output.clone()))
    } else {
        AttestPaths::resolve()
    }
}

#[cfg(feature = "cli")]
fn keygen(_args: KeygenArgs, paths: &AttestPaths) -> Result<()> {
    log::info!("resolved attest root: {}", paths.root_dir.display());

    let mut passphrase = prompt_new_passphrase()?;
    let key_material = generate_key_material(&passphrase);
    passphrase.zeroize();

    let key_material = key_material?;

    write_trust_config(paths, _args.issuer.as_deref())?;
    write_key_material(paths, &key_material)
}

#[cfg(feature = "cli")]
fn begin(_args: BeginArgs, paths: &AttestPaths) -> Result<()> {
    log::info!("resolved attest root: {}", paths.root_dir.display());

    validate_role_slug(&_args.role)?;
    validate_scope_path(&_args.scope)?;

    let ttl_input = _args.ttl.clone();
    let issuer = load_trust_config(paths)?.issuer;
    let subject = resolve_subject(_args.supervisor);
    let ttl_seconds = parse_ttl_seconds(ttl_input.as_deref())?;
    let now = current_unix_seconds()?;
    let exp = now.checked_add(ttl_seconds).ok_or_else(|| {
        AttestError::InvalidTtl(ttl_input.unwrap_or_else(|| ttl_seconds.to_string()))
    })?;

    let mut passphrase = prompt_passphrase("Passphrase: ")?;
    let secret_key = load_secret_key(paths, &passphrase);
    passphrase.zeroize();
    let secret_key = secret_key?;

    let claims = AttestationClaims {
        iss: issuer,
        sub: subject,
        sid: Uuid::new_v4().to_string(),
        role: _args.role,
        scope: _args.scope,
        iat: now,
        exp,
        jti: Uuid::new_v4().to_string(),
        ctx_hash: compute_ctx_hash(now),
    };
    let token = Zeroizing::new(mint_attestation_token(&secret_key, &claims)?);
    let registry = SessionRegistry::open(paths)?;
    let hashed_token = token_hash(&token);
    registry.record_session(&claims, &hashed_token, now)?;

    eprintln!("session started: {}", hashed_token);

    if !_args.exec.is_empty() {
        let status = ProcessCommand::new(&_args.exec[0])
            .args(&_args.exec[1..])
            .env("LANYTE_SESSION_TOKEN", &token)
            .status()?;

        if let Some(code) = status.code() {
            if code == 0 {
                return Ok(());
            }
            return Err(AttestError::ChildProcessFailed(code));
        }
        return Err(AttestError::ChildProcessTerminated);
    }

    println!("export LANYTE_SESSION_TOKEN='{}'", token.as_str());
    Ok(())
}

#[cfg(feature = "cli")]
fn verify_command(_args: VerifyArgs, _paths: &AttestPaths) -> Result<()> {
    let public_key_path = verify::default_public_key_path()?;
    let sessions_db_path = verify::default_sessions_db_path()?;
    log::info!(
        "resolved verify paths: public_key={} sessions_db={}",
        public_key_path.display(),
        sessions_db_path.display()
    );

    let token = Zeroizing::new(_args.token);
    let public_key = verify::load_public_key(None)?;
    let mut policy = verify::policy_from_current_time()?;
    if _args.expected_issuer.is_some() {
        policy.expected_issuer = _args.expected_issuer;
    }
    policy.expected_role = _args.expected_role;
    policy.expected_scope = _args.expected_scope;

    let claims = verify::validate_token(&token, &public_key, &policy)?;
    let state = verify::check_revocation_at_time(&claims.jti, None, policy.now)?;
    if state != SessionState::Active {
        return Err(AttestError::SessionNotUsable {
            jti: claims.jti.clone(),
            status: match state {
                SessionState::Active => "active",
                SessionState::Ended => "ended",
                SessionState::Revoked => "revoked",
                SessionState::Expired => "expired",
            },
            action: "verify",
        });
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&claims)
            .map_err(|err| AttestError::Validation(err.to_string()))?
    );
    Ok(())
}

#[cfg(feature = "cli")]
fn end(paths: &AttestPaths) -> Result<()> {
    log::info!("resolved attest root: {}", paths.root_dir.display());

    let token = Zeroizing::new(
        env::var("LANYTE_SESSION_TOKEN").map_err(|_| AttestError::MissingSessionToken)?,
    );
    let now = current_unix_seconds()?;
    let public_key = verify::load_public_key(None)?;
    let policy = verify::policy_from_current_time()?;
    let claims = verify::validate_token(&token, &public_key, &policy)?;
    let registry = SessionRegistry::open(paths)?;
    registry.end_session(&claims.jti, now)?;
    println!("unset LANYTE_SESSION_TOKEN");
    Ok(())
}

#[cfg(feature = "cli")]
fn revoke(_args: RevokeArgs, paths: &AttestPaths) -> Result<()> {
    log::info!("resolved attest root: {}", paths.root_dir.display());

    let _ =
        Uuid::parse_str(&_args.jti).map_err(|_| AttestError::InvalidUuidClaim { claim: "jti" })?;
    let registry = SessionRegistry::open(paths)?;
    registry.revoke_session(&_args.jti, current_unix_seconds()?)
}

#[cfg(feature = "cli")]
fn resolve_subject(supervisor: Option<String>) -> String {
    supervisor
        .or_else(|| env::var("USER").ok())
        .unwrap_or_else(|| "unknown-supervisor".to_string())
}

#[cfg(feature = "cli")]
fn parse_ttl_seconds(ttl: Option<&str>) -> Result<u64> {
    const DEFAULT_TTL_SECONDS: u64 = 8 * 60 * 60;

    let Some(ttl) = ttl else {
        return Ok(DEFAULT_TTL_SECONDS);
    };
    if ttl.is_empty() {
        return Err(AttestError::InvalidTtl(ttl.to_string()));
    }

    let (value, multiplier) = match ttl.chars().last() {
        Some('s') => (&ttl[..ttl.len() - 1], 1_u64),
        Some('m') => (&ttl[..ttl.len() - 1], 60_u64),
        Some('h') => (&ttl[..ttl.len() - 1], 60_u64 * 60),
        Some('d') => (&ttl[..ttl.len() - 1], 60_u64 * 60 * 24),
        Some(ch) if ch.is_ascii_digit() => (ttl, 1_u64),
        _ => return Err(AttestError::InvalidTtl(ttl.to_string())),
    };

    if value.is_empty() {
        return Err(AttestError::InvalidTtl(ttl.to_string()));
    }

    let amount = value
        .parse::<u64>()
        .map_err(|_| AttestError::InvalidTtl(ttl.to_string()))?;
    amount
        .checked_mul(multiplier)
        .ok_or_else(|| AttestError::InvalidTtl(ttl.to_string()))
}

#[cfg(feature = "cli")]
fn compute_ctx_hash(now: u64) -> String {
    use sha2::{Digest, Sha256};

    // This claim is reserved for future context-binding enforcement. Consumers currently validate
    // only its structural shape, not its runtime contents.
    let cwd = env::current_dir()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "unknown-cwd".to_string());
    let material = format!("cwd={cwd}\nstarted_at={now}\n");
    let digest = Sha256::digest(material.as_bytes());
    let mut out = String::from("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

#[cfg(feature = "cli")]
fn current_unix_seconds() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| AttestError::Validation(err.to_string()))?
        .as_secs())
}

#[cfg(feature = "cli")]
fn prompt_new_passphrase() -> Result<String> {
    let mut passphrase = prompt_passphrase("Passphrase: ")?;
    if passphrase.is_empty() {
        passphrase.zeroize();
        return Err(AttestError::Validation(
            "passphrase must not be empty".into(),
        ));
    }

    let mut confirm = rpassword::prompt_password("Confirm passphrase: ")?;
    if passphrase != confirm {
        passphrase.zeroize();
        confirm.zeroize();
        return Err(AttestError::Validation("passphrases do not match".into()));
    }

    confirm.zeroize();
    Ok(passphrase)
}

#[cfg(feature = "cli")]
fn prompt_passphrase(prompt: &str) -> Result<String> {
    Ok(rpassword::prompt_password(prompt)?)
}

#[cfg(all(test, feature = "cli"))]
mod tests {
    use std::path::PathBuf;
    use std::sync::Mutex;

    use crate::{AttestError, AttestPaths, KeygenArgs};

    use super::{compute_ctx_hash, parse_ttl_seconds, resolve_keygen_paths};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn keygen_uses_explicit_output_root() {
        let args = KeygenArgs {
            output: Some(PathBuf::from("/tmp/lanyte-attest-test")),
            issuer: None,
        };

        let paths = resolve_keygen_paths(&args).expect("output override should resolve");
        assert_eq!(paths.root_dir, PathBuf::from("/tmp/lanyte-attest-test"));
    }

    #[test]
    fn keygen_rejects_empty_output_root() {
        let args = KeygenArgs {
            output: Some(PathBuf::new()),
            issuer: None,
        };

        let err = resolve_keygen_paths(&args).expect_err("empty output should fail");
        assert!(matches!(err, AttestError::Validation(_)));
    }

    #[test]
    fn keygen_falls_back_to_default_paths() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let dir = tempfile::tempdir().expect("temp dir");
        std::env::set_var("LANYTE_ATTEST_HOME", dir.path().join("attest-home"));

        let args = KeygenArgs {
            output: None,
            issuer: None,
        };
        let paths = resolve_keygen_paths(&args).expect("default paths should resolve");
        assert_eq!(
            paths,
            AttestPaths::from_root(dir.path().join("attest-home"))
        );

        std::env::remove_var("LANYTE_ATTEST_HOME");
    }

    #[test]
    fn parses_default_ttl() {
        assert_eq!(parse_ttl_seconds(None).expect("default ttl"), 8 * 60 * 60);
    }

    #[test]
    fn parses_hour_ttl() {
        assert_eq!(parse_ttl_seconds(Some("2h")).expect("ttl"), 2 * 60 * 60);
    }

    #[test]
    fn rejects_invalid_ttl() {
        let err = parse_ttl_seconds(Some("oops")).expect_err("invalid ttl must fail");
        assert!(matches!(err, AttestError::InvalidTtl(_)));
    }

    #[test]
    fn rejects_oversized_ttl() {
        let err =
            parse_ttl_seconds(Some("18446744073709551615d")).expect_err("oversized ttl must fail");
        assert!(matches!(err, AttestError::InvalidTtl(_)));
    }

    #[test]
    fn ctx_hash_has_expected_shape() {
        let hash = compute_ctx_hash(1_740_000_000);
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), 71);
    }

    #[test]
    fn verify_surface_resolves_issuer_override() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let dir = tempfile::tempdir().expect("temp dir");
        std::env::set_var("HOME", dir.path());
        let paths = AttestPaths::resolve_trusted_verify().expect("trusted paths");
        crate::write_trust_config(&paths, Some("lanyte-dev.local")).expect("trust config");

        let issuer = crate::verify::resolve_expected_issuer().expect("issuer should resolve");
        assert_eq!(issuer, "lanyte-dev.local");

        std::env::remove_var("HOME");
    }
}
