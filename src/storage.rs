use crate::crypto::{
    CryptoError, KeyParams, decrypt_with_key, derive_key, encrypt_with_key, extract_params,
};
use crate::vault::Vault;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum StorageError {
    Io(std::io::Error),
    Crypto(CryptoError),
    Serialization(serde_json::Error),
    VaultNotFound,
    Busy,
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "File I/O error: {e}"),
            Self::Crypto(e) => write!(f, "{e}"),
            Self::Serialization(e) => write!(f, "Vault data serialization error: {e}"),
            Self::VaultNotFound => write!(f, "Vault file not found. Run 'apiman init' first"),
            Self::Busy => write!(
                f,
                "Vault is busy (another apiman process holds the write lock)"
            ),
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

impl StorageError {
    pub fn is_wrong_key(&self) -> bool {
        matches!(self, Self::Crypto(CryptoError::DecryptionFailed))
    }
}

pub fn vault_dir(path: &Path) -> PathBuf {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    if dir.exists() {
        return Ok(());
    }
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

/// Advisory lock serialising read-modify-write cycles on a vault. The lock is
/// taken on the vault's directory because the vault file itself is replaced
/// atomically on every save. Released on drop.
pub struct VaultLock {
    _dir: fs::File,
}

pub fn lock_vault(path: &Path) -> Result<VaultLock, StorageError> {
    let dir = vault_dir(path);
    ensure_private_dir(&dir)?;
    let file = fs::File::open(&dir)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc == 0 {
                break;
            }
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(code) if code == libc::EWOULDBLOCK || code == libc::EINTR => {
                    if Instant::now() >= deadline {
                        return Err(StorageError::Busy);
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                _ => return Err(err.into()),
            }
        }
    }
    Ok(VaultLock { _dir: file })
}

/// Cheap fingerprint used to notice that another process rewrote the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultSignature {
    ino: u64,
    len: u64,
    modified: Option<SystemTime>,
}

pub fn vault_signature(path: &Path) -> Option<VaultSignature> {
    let meta = fs::metadata(path).ok()?;
    #[cfg(unix)]
    let ino = {
        use std::os::unix::fs::MetadataExt;
        meta.ino()
    };
    #[cfg(not(unix))]
    let ino = 0;
    Some(VaultSignature {
        ino,
        len: meta.len(),
        modified: meta.modified().ok(),
    })
}

pub fn save_vault(
    vault: &Vault,
    key: &[u8; 32],
    params: &KeyParams,
    path: &Path,
) -> Result<(), StorageError> {
    let parent = vault_dir(path);
    ensure_private_dir(&parent)?;

    let json_bytes = vault.to_json_bytes()?;
    let envelope = encrypt_with_key(key, params, &json_bytes)?;

    // tempfile creates the file 0600 with O_EXCL, so the ciphertext is never
    // briefly world-readable and a planted symlink cannot redirect the write.
    let mut temp = tempfile::Builder::new()
        .prefix(".apiman-vault-")
        .tempfile_in(&parent)?;
    temp.write_all(&envelope)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|e| e.error)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

pub fn load_vault_with_key(
    key: &[u8; 32],
    path: &Path,
) -> Result<(Vault, KeyParams), StorageError> {
    if !path.exists() {
        return Err(StorageError::VaultNotFound);
    }

    let envelope = fs::read(path)?;
    let params = extract_params(&envelope)?;
    let decrypted = decrypt_with_key(key, &envelope)?;
    let vault = Vault::from_json_bytes(&decrypted)?;

    Ok((vault, params))
}

pub fn load_vault_with_password(
    password: &str,
    path: &Path,
) -> Result<(Vault, Zeroizing<[u8; 32]>, KeyParams), StorageError> {
    if !path.exists() {
        return Err(StorageError::VaultNotFound);
    }

    let envelope = fs::read(path)?;
    let params = extract_params(&envelope)?;
    let key = derive_key(password, &params)?;
    let decrypted = decrypt_with_key(&key, &envelope)?;
    let vault = Vault::from_json_bytes(&decrypted)?;

    Ok((vault, key, params))
}

pub fn init_vault(
    password: &str,
    path: &Path,
) -> Result<(Vault, Zeroizing<[u8; 32]>, KeyParams), StorageError> {
    let params = KeyParams::generate();
    let key = derive_key(password, &params)?;
    let vault = Vault::new();

    save_vault(&vault, &key, &params, path)?;
    Ok((vault, key, params))
}

pub fn rekey_vault(
    vault: &Vault,
    new_password: &str,
    path: &Path,
) -> Result<(Zeroizing<[u8; 32]>, KeyParams), StorageError> {
    let params = KeyParams::generate();
    let new_key = derive_key(new_password, &params)?;
    save_vault(vault, &new_key, &params, path)?;
    Ok((new_key, params))
}
