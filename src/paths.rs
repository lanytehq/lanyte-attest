use std::env;
use std::fs;
use std::path::PathBuf;

use crate::{AttestError, Result};

const DEFAULT_ROOT_REL: &str = ".lanyte/attest";
const PRIVATE_KEY_FILE: &str = "signing-key.age";
const PUBLIC_KEY_FILE: &str = "signing-key.pub";
const SESSIONS_DB_FILE: &str = "sessions.db";
const TRUST_CONFIG_FILE: &str = "trust.toml";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestPaths {
    pub root_dir: PathBuf,
    pub private_key_path: PathBuf,
    pub public_key_path: PathBuf,
    pub sessions_db_path: PathBuf,
    pub trust_config_path: PathBuf,
}

impl AttestPaths {
    pub fn resolve() -> Result<Self> {
        let root_dir = if let Some(path) = env::var_os("LANYTE_ATTEST_HOME") {
            let root_dir = PathBuf::from(path);
            if root_dir.as_os_str().is_empty() {
                return Err(AttestError::EmptyEnvVar("LANYTE_ATTEST_HOME"));
            }
            root_dir
        } else {
            resolve_home_root()?
        };

        Ok(Self::from_root(root_dir))
    }

    pub fn resolve_trusted_verify() -> Result<Self> {
        Ok(Self::from_root(resolve_home_root()?))
    }

    pub fn from_root(root_dir: PathBuf) -> Self {
        Self {
            private_key_path: root_dir.join(PRIVATE_KEY_FILE),
            public_key_path: root_dir.join(PUBLIC_KEY_FILE),
            sessions_db_path: root_dir.join(SESSIONS_DB_FILE),
            trust_config_path: root_dir.join(TRUST_CONFIG_FILE),
            root_dir,
        }
    }

    pub fn ensure_root_dir(&self) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

            if let Some(parent) = self.root_dir.parent() {
                fs::create_dir_all(parent)?;
            }

            if self.root_dir.exists() {
                let metadata = fs::metadata(&self.root_dir)?;
                if !metadata.is_dir() {
                    return Err(AttestError::RootPathNotDirectory(self.root_dir.clone()));
                }
                let mode = metadata.permissions().mode() & 0o777;
                if mode != 0o700 {
                    return Err(AttestError::InsecureDirectoryPermissions {
                        path: self.root_dir.clone(),
                        actual: mode,
                    });
                }
            } else {
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700);
                builder.create(&self.root_dir)?;
                fs::set_permissions(&self.root_dir, fs::Permissions::from_mode(0o700))?;
            }
        }

        #[cfg(not(unix))]
        {
            fs::create_dir_all(&self.root_dir)?;
        }

        Ok(())
    }
}

fn resolve_home_root() -> Result<PathBuf> {
    let home = env::var_os("HOME").ok_or(AttestError::MissingHome)?;
    let home = PathBuf::from(home);
    if home.as_os_str().is_empty() {
        return Err(AttestError::EmptyEnvVar("HOME"));
    }
    Ok(home.join(DEFAULT_ROOT_REL))
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::path::PathBuf;
    use std::sync::Mutex;

    use tempfile::tempdir;

    use super::AttestPaths;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn resolves_from_attest_home_override() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let dir = tempdir().expect("temp dir");
        let root = dir.path().join("custom-attest");

        env::set_var("LANYTE_ATTEST_HOME", &root);
        env::remove_var("HOME");

        let paths = AttestPaths::resolve().expect("paths should resolve");
        assert_eq!(paths.root_dir, root);
        assert_eq!(
            paths.private_key_path,
            paths.root_dir.join("signing-key.age")
        );
        assert_eq!(
            paths.public_key_path,
            paths.root_dir.join("signing-key.pub")
        );
        assert_eq!(paths.sessions_db_path, paths.root_dir.join("sessions.db"));

        env::remove_var("LANYTE_ATTEST_HOME");
    }

    #[test]
    fn resolves_from_home_by_default() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let dir = tempdir().expect("temp dir");

        env::remove_var("LANYTE_ATTEST_HOME");
        env::set_var("HOME", dir.path());

        let paths = AttestPaths::resolve().expect("paths should resolve");
        assert_eq!(paths.root_dir, dir.path().join(".lanyte/attest"));

        env::remove_var("HOME");
    }

    #[test]
    fn trusted_verify_ignores_attest_home_override() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let dir = tempdir().expect("temp dir");

        env::set_var("HOME", dir.path());
        env::set_var("LANYTE_ATTEST_HOME", dir.path().join("attacker-root"));

        let paths = AttestPaths::resolve_trusted_verify().expect("trusted verify paths");
        assert_eq!(paths.root_dir, dir.path().join(".lanyte/attest"));

        env::remove_var("LANYTE_ATTEST_HOME");
        env::remove_var("HOME");
    }

    #[test]
    fn rejects_empty_attest_home_override() {
        let _guard = ENV_LOCK.lock().expect("env lock");

        env::set_var("LANYTE_ATTEST_HOME", "");
        env::set_var("HOME", "/tmp/ignored-home");

        let err = AttestPaths::resolve().expect_err("empty override must fail");
        assert!(matches!(
            err,
            crate::AttestError::EmptyEnvVar("LANYTE_ATTEST_HOME")
        ));

        env::remove_var("LANYTE_ATTEST_HOME");
        env::remove_var("HOME");
    }

    #[test]
    fn rejects_empty_home() {
        let _guard = ENV_LOCK.lock().expect("env lock");

        env::remove_var("LANYTE_ATTEST_HOME");
        env::set_var("HOME", "");

        let err = AttestPaths::resolve().expect_err("empty home must fail");
        assert!(matches!(err, crate::AttestError::EmptyEnvVar("HOME")));

        env::remove_var("HOME");
    }

    #[test]
    fn creates_root_directory() {
        let dir = tempdir().expect("temp dir");
        let root = dir.path().join("nested").join("attest");
        let paths = AttestPaths::from_root(PathBuf::from(&root));

        assert!(!root.exists());
        paths.ensure_root_dir().expect("root dir should be created");
        assert!(root.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn creates_root_directory_with_0700_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("temp dir");
        let root = dir.path().join("secure-attest");
        let paths = AttestPaths::from_root(root.clone());

        paths.ensure_root_dir().expect("root dir should be created");

        let mode = std::fs::metadata(&root)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_existing_root_directory_with_insecure_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("temp dir");
        let root = dir.path().join("insecure-attest");
        std::fs::create_dir(&root).expect("create insecure dir");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))
            .expect("chmod insecure dir");

        let paths = AttestPaths::from_root(root.clone());
        let err = paths
            .ensure_root_dir()
            .expect_err("insecure permissions must fail");

        assert!(matches!(
            err,
            crate::AttestError::InsecureDirectoryPermissions { path, actual }
            if path == root && actual == 0o755
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_existing_root_path_when_it_is_a_file() {
        let dir = tempdir().expect("temp dir");
        let root = dir.path().join("not-a-dir");
        std::fs::write(&root, b"x").expect("create file");

        let paths = AttestPaths::from_root(root.clone());
        let err = paths
            .ensure_root_dir()
            .expect_err("file path must be rejected");

        assert!(matches!(err, crate::AttestError::RootPathNotDirectory(path) if path == root));
    }
}
