use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
#[cfg(feature = "issue")]
use seclusor_crypto::{sign, signature_to_bytes, SigningSecretKey};
use seclusor_crypto::{signature_from_bytes, verify, SigningPublicKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::naming::{validate_instance_name, validate_role_slug, validate_scope_path};
use crate::{AttestError, Result};

const JWT_TYP: &str = "JWT";
const JWT_ALG: &str = "EdDSA";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationClaims {
    pub iss: String,
    pub sub: String,
    pub sid: String,
    pub role: String,
    pub scope: String,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
    pub ctx_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationPolicy {
    pub now: u64,
    pub expected_issuer: Option<String>,
    pub expected_role: Option<String>,
    pub expected_scope: Option<String>,
}

impl VerificationPolicy {
    pub fn from_current_time() -> Result<Self> {
        Ok(Self {
            now: current_unix_seconds_for_verify()?,
            expected_issuer: None,
            expected_role: None,
            expected_scope: None,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct AttestationHeader {
    alg: String,
    typ: String,
}

#[cfg(feature = "issue")]
pub fn mint_attestation_token(
    secret_key: &SigningSecretKey,
    claims: &AttestationClaims,
) -> Result<String> {
    claims.validate()?;

    let header = AttestationHeader {
        alg: JWT_ALG.to_string(),
        typ: JWT_TYP.to_string(),
    };

    let header_json =
        serde_json::to_vec(&header).map_err(|err| AttestError::Validation(err.to_string()))?;
    let claims_json =
        serde_json::to_vec(claims).map_err(|err| AttestError::Validation(err.to_string()))?;
    let encoded_header = URL_SAFE_NO_PAD.encode(header_json);
    let encoded_claims = URL_SAFE_NO_PAD.encode(claims_json);
    let signing_input = format!("{encoded_header}.{encoded_claims}");

    let signature = sign(secret_key, signing_input.as_bytes())?;
    let encoded_signature = URL_SAFE_NO_PAD.encode(signature_to_bytes(&signature));

    Ok(format!("{signing_input}.{encoded_signature}"))
}

pub fn verify_attestation_token(
    token: &str,
    public_key: &SigningPublicKey,
    policy: &VerificationPolicy,
) -> Result<AttestationClaims> {
    let mut segments = token.split('.');
    let header_segment = segments.next().ok_or(AttestError::InvalidTokenFormat)?;
    let claims_segment = segments.next().ok_or(AttestError::InvalidTokenFormat)?;
    let signature_segment = segments.next().ok_or(AttestError::InvalidTokenFormat)?;
    if segments.next().is_some() {
        return Err(AttestError::InvalidTokenFormat);
    }

    if header_segment.is_empty() {
        return Err(AttestError::EmptyTokenSegment("header"));
    }
    if claims_segment.is_empty() {
        return Err(AttestError::EmptyTokenSegment("claims"));
    }
    if signature_segment.is_empty() {
        return Err(AttestError::EmptyTokenSegment("signature"));
    }

    let header: AttestationHeader =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_segment)?)
            .map_err(|err| AttestError::Validation(err.to_string()))?;
    if header.alg != JWT_ALG {
        return Err(AttestError::InvalidTokenAlgorithm);
    }
    if header.typ != JWT_TYP {
        return Err(AttestError::InvalidTokenType);
    }

    let claims: AttestationClaims =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims_segment)?)
            .map_err(|err| AttestError::Validation(err.to_string()))?;
    claims.validate()?;

    let signature_bytes = URL_SAFE_NO_PAD.decode(signature_segment)?;
    let signature = signature_from_bytes(&signature_bytes)?;
    let signing_input = format!("{header_segment}.{claims_segment}");
    verify(public_key, signing_input.as_bytes(), &signature)?;

    if claims.exp <= policy.now {
        return Err(AttestError::TokenExpired {
            exp: claims.exp,
            now: policy.now,
        });
    }
    if claims.iat > policy.now {
        return Err(AttestError::TokenIssuedInFuture {
            iat: claims.iat,
            now: policy.now,
        });
    }
    if let Some(expected) = &policy.expected_issuer {
        if &claims.iss != expected {
            return Err(AttestError::IssuerMismatch {
                expected: expected.clone(),
                actual: claims.iss.clone(),
            });
        }
    }
    if let Some(expected) = &policy.expected_role {
        if &claims.role != expected {
            return Err(AttestError::RoleMismatch {
                expected: expected.clone(),
                actual: claims.role.clone(),
            });
        }
    }
    if let Some(expected) = &policy.expected_scope {
        if &claims.scope != expected {
            return Err(AttestError::ScopeMismatch {
                expected: expected.clone(),
                actual: claims.scope.clone(),
            });
        }
    }

    Ok(claims)
}

impl AttestationClaims {
    pub fn validate(&self) -> Result<()> {
        validate_instance_name(&self.iss)?;
        validate_role_slug(&self.role)?;
        validate_scope_path(&self.scope)?;

        if self.sub.trim().is_empty() {
            return Err(AttestError::Validation("sub must not be empty".into()));
        }
        validate_uuid_claim(&self.sid, "sid")?;
        validate_uuid_claim(&self.jti, "jti")?;
        validate_ctx_hash(&self.ctx_hash)?;
        if self.exp <= self.iat {
            return Err(AttestError::Validation(
                "exp must be greater than iat".into(),
            ));
        }

        Ok(())
    }
}

pub(crate) fn current_unix_seconds_for_verify() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| AttestError::Validation(err.to_string()))?
        .as_secs())
}

fn validate_uuid_claim(value: &str, claim: &'static str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(AttestError::Validation(format!(
            "{claim} must not be empty"
        )));
    }

    Uuid::parse_str(value).map_err(|_| AttestError::InvalidUuidClaim { claim })?;
    Ok(())
}

fn validate_ctx_hash(value: &str) -> Result<()> {
    let digest = value
        .strip_prefix("sha256:")
        .ok_or(AttestError::InvalidContextHash)?;
    if digest.len() != 64 || !digest.chars().all(|ch| matches!(ch, '0'..='9' | 'a'..='f')) {
        return Err(AttestError::InvalidContextHash);
    }
    Ok(())
}

#[cfg(all(test, feature = "issue"))]
mod tests {
    use seclusor_crypto::generate_signing_keypair;

    use super::{
        mint_attestation_token, verify_attestation_token, AttestationClaims, VerificationPolicy,
    };
    use crate::AttestError;

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

    fn fixture_policy() -> VerificationPolicy {
        VerificationPolicy {
            now: 1_740_000_001,
            expected_issuer: Some("lanyte-attest".to_string()),
            expected_role: Some("devlead".to_string()),
            expected_scope: Some("lanytehq/core-runtime".to_string()),
        }
    }

    #[test]
    fn mint_and_verify_round_trip() {
        let keypair = generate_signing_keypair().expect("keypair");
        let claims = fixture_claims();
        let token = mint_attestation_token(keypair.secret_key(), &claims).expect("mint token");

        let decoded = verify_attestation_token(&token, keypair.public_key(), &fixture_policy())
            .expect("verify token");
        assert_eq!(decoded, claims);
    }

    #[test]
    fn rejects_tampered_signature() {
        let keypair = generate_signing_keypair().expect("keypair");
        let token =
            mint_attestation_token(keypair.secret_key(), &fixture_claims()).expect("mint token");
        let mut tampered = token;
        tampered.push('x');

        let err = verify_attestation_token(&tampered, keypair.public_key(), &fixture_policy())
            .expect_err("tampered token must fail");
        assert!(matches!(
            err,
            AttestError::Crypto(_) | AttestError::Base64(_)
        ));
    }

    #[test]
    fn rejects_expired_token() {
        let keypair = generate_signing_keypair().expect("keypair");
        let mut claims = fixture_claims();
        claims.exp = claims.iat;
        let err = mint_attestation_token(keypair.secret_key(), &claims)
            .expect_err("invalid claims should fail before mint");
        assert!(matches!(err, AttestError::Validation(_)));
    }

    #[test]
    fn rejects_token_when_policy_time_is_past_expiry() {
        let keypair = generate_signing_keypair().expect("keypair");
        let claims = fixture_claims();
        let token = mint_attestation_token(keypair.secret_key(), &claims).expect("mint token");
        let mut policy = fixture_policy();
        policy.now = claims.exp;

        let err = verify_attestation_token(&token, keypair.public_key(), &policy)
            .expect_err("expired token must fail");
        assert!(matches!(err, AttestError::TokenExpired { .. }));
    }

    #[test]
    fn rejects_role_mismatch() {
        let keypair = generate_signing_keypair().expect("keypair");
        let token =
            mint_attestation_token(keypair.secret_key(), &fixture_claims()).expect("mint token");
        let mut policy = fixture_policy();
        policy.expected_role = Some("devrev".to_string());

        let err = verify_attestation_token(&token, keypair.public_key(), &policy)
            .expect_err("role mismatch must fail");
        assert!(matches!(err, AttestError::RoleMismatch { .. }));
    }

    #[test]
    fn rejects_scope_mismatch() {
        let keypair = generate_signing_keypair().expect("keypair");
        let token =
            mint_attestation_token(keypair.secret_key(), &fixture_claims()).expect("mint token");
        let mut policy = fixture_policy();
        policy.expected_scope = Some("lanytehq/agent-intel".to_string());

        let err = verify_attestation_token(&token, keypair.public_key(), &policy)
            .expect_err("scope mismatch must fail");
        assert!(matches!(err, AttestError::ScopeMismatch { .. }));
    }

    #[test]
    fn rejects_issuer_mismatch() {
        let keypair = generate_signing_keypair().expect("keypair");
        let token =
            mint_attestation_token(keypair.secret_key(), &fixture_claims()).expect("mint token");
        let mut policy = fixture_policy();
        policy.expected_issuer = Some("lanyte-attest.dev".to_string());

        let err = verify_attestation_token(&token, keypair.public_key(), &policy)
            .expect_err("issuer mismatch must fail");
        assert!(matches!(err, AttestError::IssuerMismatch { .. }));
    }

    #[test]
    fn rejects_future_issued_token() {
        let keypair = generate_signing_keypair().expect("keypair");
        let mut claims = fixture_claims();
        claims.iat += 60;
        claims.exp += 60;
        let token = mint_attestation_token(keypair.secret_key(), &claims).expect("mint token");

        let err = verify_attestation_token(&token, keypair.public_key(), &fixture_policy())
            .expect_err("future-issued token must fail");
        assert!(matches!(err, AttestError::TokenIssuedInFuture { .. }));
    }

    #[test]
    fn rejects_non_uuid_sid() {
        let keypair = generate_signing_keypair().expect("keypair");
        let mut claims = fixture_claims();
        claims.sid = "not-a-uuid".to_string();

        let err = mint_attestation_token(keypair.secret_key(), &claims)
            .expect_err("invalid sid must fail");
        assert!(matches!(
            err,
            AttestError::InvalidUuidClaim { claim: "sid" }
        ));
    }

    #[test]
    fn rejects_non_uuid_jti() {
        let keypair = generate_signing_keypair().expect("keypair");
        let mut claims = fixture_claims();
        claims.jti = "not-a-uuid".to_string();

        let err = mint_attestation_token(keypair.secret_key(), &claims)
            .expect_err("invalid jti must fail");
        assert!(matches!(
            err,
            AttestError::InvalidUuidClaim { claim: "jti" }
        ));
    }

    #[test]
    fn rejects_invalid_ctx_hash_shape() {
        let keypair = generate_signing_keypair().expect("keypair");
        let mut claims = fixture_claims();
        claims.ctx_hash = "sha256:DEADBEEF".to_string();

        let err = mint_attestation_token(keypair.secret_key(), &claims)
            .expect_err("invalid ctx_hash must fail");
        assert!(matches!(err, AttestError::InvalidContextHash));
    }
}
