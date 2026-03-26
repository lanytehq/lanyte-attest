use std::fs;

use serde::{Deserialize, Serialize};

use crate::{validate_instance_name, AttestError, AttestPaths, Result};

const DEFAULT_ISSUER: &str = "lanyte-attest";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustConfig {
    pub issuer: String,
}

impl Default for TrustConfig {
    fn default() -> Self {
        Self {
            issuer: DEFAULT_ISSUER.to_string(),
        }
    }
}

impl TrustConfig {
    pub fn validate(&self) -> Result<()> {
        validate_instance_name(&self.issuer)
    }
}

#[cfg(feature = "issue")]
pub fn write_trust_config(paths: &AttestPaths, issuer: Option<&str>) -> Result<TrustConfig> {
    paths.ensure_root_dir()?;
    if paths.trust_config_path.exists() {
        return load_trust_config(paths);
    }

    let config = TrustConfig {
        issuer: issuer.unwrap_or(DEFAULT_ISSUER).to_string(),
    };
    config.validate()?;

    let raw = toml::to_string(&config).map_err(|err| AttestError::Validation(err.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&paths.trust_config_path)?;
        use std::io::Write as _;
        file.write_all(raw.as_bytes())?;
        file.flush()?;
    }

    #[cfg(not(unix))]
    {
        fs::write(&paths.trust_config_path, raw)?;
    }

    Ok(config)
}

pub fn load_trust_config(paths: &AttestPaths) -> Result<TrustConfig> {
    if !paths.trust_config_path.exists() {
        return Err(AttestError::MissingTrustConfig(
            paths.trust_config_path.clone(),
        ));
    }

    let raw = fs::read_to_string(&paths.trust_config_path)?;
    let config: TrustConfig =
        toml::from_str(&raw).map_err(|err| AttestError::Validation(err.to_string()))?;
    config.validate()?;
    Ok(config)
}

#[cfg(all(test, feature = "issue"))]
mod tests {
    use tempfile::tempdir;

    use super::{load_trust_config, write_trust_config};
    use crate::{AttestError, AttestPaths};

    #[test]
    fn writes_default_trust_config() {
        let dir = tempdir().expect("temp dir");
        let paths = AttestPaths::from_root(dir.path().join("attest"));

        let config = write_trust_config(&paths, None).expect("trust config should write");
        assert_eq!(config.issuer, "lanyte-attest");

        let loaded = load_trust_config(&paths).expect("trust config should load");
        assert_eq!(loaded.issuer, "lanyte-attest");
    }

    #[test]
    fn writes_custom_issuer() {
        let dir = tempdir().expect("temp dir");
        let paths = AttestPaths::from_root(dir.path().join("attest"));

        let config = write_trust_config(&paths, Some("lanyte-dev.local"))
            .expect("trust config should write");
        assert_eq!(config.issuer, "lanyte-dev.local");
    }

    #[test]
    fn rejects_missing_trust_config() {
        let dir = tempdir().expect("temp dir");
        let paths = AttestPaths::from_root(dir.path().join("attest"));

        let err = load_trust_config(&paths).expect_err("missing config must fail");
        assert!(matches!(err, AttestError::MissingTrustConfig(_)));
    }
}
