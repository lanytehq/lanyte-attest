use std::fs;
use std::path::Path;

#[cfg(feature = "issue")]
use std::fs::File;
#[cfg(feature = "issue")]
use std::io::Write;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use seclusor_crypto::{signing_public_key_from_bytes, SigningPublicKey};

#[cfg(feature = "issue")]
use seclusor_crypto::{
    decrypt_with_passphrase, encrypt_with_passphrase, generate_signing_keypair,
    signing_public_key_to_bytes, signing_secret_key_from_bytes, signing_secret_key_to_bytes,
    SigningSecretKey,
};

#[cfg(feature = "issue")]
use zeroize::Zeroize;

use crate::{AttestError, AttestPaths, Result};

#[cfg(feature = "issue")]
pub struct StoredKeyMaterial {
    encrypted_secret_key: Vec<u8>,
    public_key_b64: String,
}

#[cfg(feature = "issue")]
impl StoredKeyMaterial {
    fn new(encrypted_secret_key: Vec<u8>, public_key_b64: String) -> Self {
        Self {
            encrypted_secret_key,
            public_key_b64,
        }
    }
}

#[cfg(feature = "issue")]
pub fn generate_key_material(passphrase: &str) -> Result<StoredKeyMaterial> {
    if passphrase.is_empty() {
        return Err(AttestError::Validation(
            "passphrase must not be empty".into(),
        ));
    }

    let keypair = generate_signing_keypair()?;
    let public_key_b64 = BASE64_STANDARD.encode(signing_public_key_to_bytes(keypair.public_key()));

    let mut secret_key_bytes = signing_secret_key_to_bytes(keypair.secret_key()).to_vec();
    let encrypted_secret_key = encrypt_with_passphrase(&secret_key_bytes, passphrase)?;
    secret_key_bytes.zeroize();

    Ok(StoredKeyMaterial::new(encrypted_secret_key, public_key_b64))
}

#[cfg(feature = "issue")]
pub fn write_key_material(paths: &AttestPaths, key_material: &StoredKeyMaterial) -> Result<()> {
    paths.ensure_root_dir()?;

    write_private_key_file(&paths.private_key_path, &key_material.encrypted_secret_key)?;

    let public_result = write_public_key_file(&paths.public_key_path, &key_material.public_key_b64);
    if let Err(err) = public_result {
        let _ = fs::remove_file(&paths.private_key_path);
        return Err(err);
    }

    Ok(())
}

#[cfg(feature = "issue")]
pub fn load_secret_key(paths: &AttestPaths, passphrase: &str) -> Result<SigningSecretKey> {
    ensure_file_ready(&paths.private_key_path, true)?;
    let ciphertext = fs::read(&paths.private_key_path)?;
    let mut plaintext = decrypt_with_passphrase(&ciphertext, passphrase)?;
    let secret_key = signing_secret_key_from_bytes(&plaintext)?;
    plaintext.zeroize();
    Ok(secret_key)
}

pub fn load_public_key(paths: &AttestPaths) -> Result<SigningPublicKey> {
    load_public_key_from_path(&paths.public_key_path)
}

pub fn load_public_key_from_path(path: &Path) -> Result<SigningPublicKey> {
    ensure_file_ready(path, false)?;
    let encoded = fs::read_to_string(path)?;
    let encoded = encoded.trim();
    if encoded.is_empty() {
        return Err(AttestError::Validation("public key file is empty".into()));
    }

    let raw = BASE64_STANDARD.decode(encoded)?;
    Ok(signing_public_key_from_bytes(&raw)?)
}

#[cfg(feature = "issue")]
fn write_private_key_file(path: &Path, ciphertext: &[u8]) -> Result<()> {
    let mut file = create_new_file(path, true)?;
    if let Err(err) = file.write_all(ciphertext).and_then(|_| file.flush()) {
        let _ = fs::remove_file(path);
        return Err(err.into());
    }
    Ok(())
}

#[cfg(feature = "issue")]
fn write_public_key_file(path: &Path, public_key_b64: &str) -> Result<()> {
    let mut file = create_new_file(path, false)?;
    if let Err(err) = writeln!(file, "{public_key_b64}").and_then(|_| file.flush()) {
        let _ = fs::remove_file(path);
        return Err(err.into());
    }
    Ok(())
}

#[cfg(feature = "issue")]
fn create_new_file(path: &Path, private: bool) -> Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let mode = if private { 0o600 } else { 0o644 };
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)
            .map_err(|err| map_create_error(path, err))
    }

    #[cfg(not(unix))]
    {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|err| map_create_error(path, err))
    }
}

#[cfg(feature = "issue")]
fn map_create_error(path: &Path, err: std::io::Error) -> AttestError {
    if err.kind() == std::io::ErrorKind::AlreadyExists {
        AttestError::KeyMaterialAlreadyExists(path.to_path_buf())
    } else {
        err.into()
    }
}

fn ensure_file_ready(path: &Path, private: bool) -> Result<()> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(AttestError::ExpectedFilePath(path.to_path_buf()));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let actual = metadata.permissions().mode() & 0o777;
        let required = if private { 0o600 } else { 0o644 };
        if actual != required {
            return Err(AttestError::InsecureFilePermissions {
                path: path.to_path_buf(),
                actual,
                required,
            });
        }
    }

    Ok(())
}

#[cfg(all(test, feature = "issue"))]
mod tests {
    use seclusor_crypto::{sign, verify};
    use tempfile::tempdir;

    use super::{generate_key_material, load_public_key, load_secret_key, write_key_material};
    use crate::{AttestError, AttestPaths};

    #[test]
    fn generates_and_roundtrips_key_material() {
        let dir = tempdir().expect("temp dir");
        let paths = AttestPaths::from_root(dir.path().join("attest"));
        let key_material = generate_key_material("correct horse battery staple")
            .expect("key material should generate");

        write_key_material(&paths, &key_material).expect("key material should write");

        let secret_key = load_secret_key(&paths, "correct horse battery staple")
            .expect("secret key should load");
        let public_key = load_public_key(&paths).expect("public key should load");

        let signature = sign(&secret_key, b"attest-message").expect("sign should succeed");
        verify(&public_key, b"attest-message", &signature).expect("verify should succeed");
    }

    #[test]
    fn rejects_overwriting_existing_key_material() {
        let dir = tempdir().expect("temp dir");
        let paths = AttestPaths::from_root(dir.path().join("attest"));
        let key_material =
            generate_key_material("test-passphrase").expect("key material should generate");

        write_key_material(&paths, &key_material).expect("first write should succeed");
        let err = write_key_material(&paths, &key_material).expect_err("second write must fail");

        assert!(matches!(err, AttestError::KeyMaterialAlreadyExists(_)));
    }

    #[test]
    fn rejects_empty_public_key_file() {
        let dir = tempdir().expect("temp dir");
        let paths = AttestPaths::from_root(dir.path().join("attest"));
        paths.ensure_root_dir().expect("root dir should be created");
        std::fs::write(&paths.public_key_path, "\n").expect("empty public key file");

        let err = load_public_key(&paths).expect_err("empty public key must fail");
        assert!(matches!(err, AttestError::Validation(_)));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_insecure_private_key_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("temp dir");
        let paths = AttestPaths::from_root(dir.path().join("attest"));
        let key_material = generate_key_material("correct horse battery staple")
            .expect("key material should generate");

        write_key_material(&paths, &key_material).expect("key material should write");
        std::fs::set_permissions(
            &paths.private_key_path,
            std::fs::Permissions::from_mode(0o644),
        )
        .expect("chmod insecure key file");

        let err = match load_secret_key(&paths, "correct horse battery staple") {
            Ok(_) => panic!("insecure private key perms must fail"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            AttestError::InsecureFilePermissions {
                required: 0o600,
                ..
            }
        ));
    }
}
