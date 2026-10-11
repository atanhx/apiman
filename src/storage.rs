use crate::crypto::{
    decrypt_with_key, derive_key, encrypt_with_key, extract_salt, generate_salt, CryptoError,
    SALT_LEN,
};
use crate::vault::Vault;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::Path;
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum StorageError {
    Io(std::io::Error),
    Crypto(CryptoError),
    Serialization(serde_json::Error),
    VaultNotFound,
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "File I/O error: {e}"),
            Self::Crypto(e) => write!(f, "Cryptographic error: {e}"),
            Self::Serialization(e) => write!(f, "Vault data serialization error: {e}"),
            Self::VaultNotFound => write!(f, "Vault file not found. Run 'apiman init' first"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<CryptoError> for StorageError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e)
    }
}

pub fn save_vault(
    vault: &Vault,
    key: &[u8; 32],
    salt: &[u8; SALT_LEN],
    path: &Path,
) -> Result<(), StorageError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.exists() {
        fs::create_dir_all(parent)?;
    }

    let json_bytes = vault.to_json_bytes()?;
    let envelope = encrypt_with_key(key, salt, &json_bytes)?;

    let mut temp = tempfile::Builder::new()
        .prefix("vault-tmp-")
        .tempfile_in(parent)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        let _ = fs::set_permissions(temp.path(), perms);
    }

    temp.write_all(&envelope)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|e| e.error)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        let _ = fs::set_permissions(path, perms);
    }

    Ok(())
}

pub fn load_vault_with_key(
    key: &[u8; 32],
    path: &Path,
) -> Result<(Vault, [u8; SALT_LEN]), StorageError> {
    if !path.exists() {
        return Err(StorageError::VaultNotFound);
    }

    let envelope = fs::read(path)?;
    let salt = extract_salt(&envelope)?;
    let decrypted = decrypt_with_key(key, &envelope)?;
    let vault = Vault::from_json_bytes(&decrypted)?;

    Ok((vault, salt))
}

pub fn load_vault_with_password(
    password: &str,
    path: &Path,
) -> Result<(Vault, Zeroizing<[u8; 32]>, [u8; SALT_LEN]), StorageError> {
    if !path.exists() {
        return Err(StorageError::VaultNotFound);
    }

    let envelope = fs::read(path)?;
    let salt = extract_salt(&envelope)?;
    let key = derive_key(password, &salt)?;
    let decrypted = decrypt_with_key(&key, &envelope)?;
    let vault = Vault::from_json_bytes(&decrypted)?;

    Ok((vault, key, salt))
}

pub fn init_vault(
    password: &str,
    path: &Path,
) -> Result<(Vault, Zeroizing<[u8; 32]>, [u8; SALT_LEN]), StorageError> {
    let salt = generate_salt();
    let key = derive_key(password, &salt)?;
    let vault = Vault::new();

    save_vault(&vault, &key, &salt, path)?;
    Ok((vault, key, salt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::SecretString;

    #[test]
    fn test_storage_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");

        let password = "test-master-password";
        let (mut vault, key, salt) = init_vault(password, &vault_path).unwrap();

        vault.set(
            "KEY".to_string(),
            SecretString::new("val"),
            None,
            vec![],
            None,
        );
        save_vault(&vault, &key, &salt, &vault_path).unwrap();

        // Reload with password
        let (loaded, key2, _) = load_vault_with_password(password, &vault_path).unwrap();
        assert_eq!(key.as_slice(), key2.as_slice());
        assert_eq!(loaded.get("KEY", None).unwrap().value.expose_secret(), "val");

        // Reload with key
        let (loaded2, _) = load_vault_with_key(&key, &vault_path).unwrap();
        assert_eq!(loaded2.get("KEY", None).unwrap().value.expose_secret(), "val");
    }
}
