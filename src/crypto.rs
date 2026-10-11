use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

pub const MAGIC: &[u8; 8] = b"APIMAN01";
pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const HEADER_LEN: usize = MAGIC.len() + SALT_LEN + NONCE_LEN; // 8 + 32 + 24 = 64 bytes

#[derive(Debug)]
pub enum CryptoError {
    InvalidMagic,
    DataTooShort,
    KeyDerivationFailed(String),
    DecryptionFailed,
    EncryptionFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "Invalid vault format or header"),
            Self::DataTooShort => write!(f, "Encrypted vault file is corrupted or truncated"),
            Self::KeyDerivationFailed(e) => write!(f, "Key derivation failed: {e}"),
            Self::DecryptionFailed => {
                write!(f, "Authentication failed: invalid password or tampered vault")
            }
            Self::EncryptionFailed => write!(f, "Encryption operation failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn derive_key(password: &str, salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let params = Params::new(65536, 3, 4, Some(32))
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    Ok(key)
}

pub fn encrypt_with_key(
    key: &[u8; 32],
    salt: &[u8; SALT_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut envelope = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    envelope.extend_from_slice(MAGIC);
    envelope.extend_from_slice(salt);
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);

    Ok(envelope)
}

pub fn decrypt_with_key(
    key: &[u8; 32],
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if envelope.len() < HEADER_LEN {
        return Err(CryptoError::DataTooShort);
    }

    if &envelope[0..MAGIC.len()] != MAGIC {
        return Err(CryptoError::InvalidMagic);
    }

    let nonce_start = MAGIC.len() + SALT_LEN;
    let nonce_bytes = &envelope[nonce_start..nonce_start + NONCE_LEN];
    let ciphertext = &envelope[HEADER_LEN..];

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let nonce = XNonce::from_slice(nonce_bytes);

    let mut decrypted = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let res = Zeroizing::new(decrypted.clone());
    decrypted.zeroize();
    Ok(res)
}

pub fn extract_salt(envelope: &[u8]) -> Result<[u8; SALT_LEN], CryptoError> {
    if envelope.len() < HEADER_LEN {
        return Err(CryptoError::DataTooShort);
    }
    if &envelope[0..MAGIC.len()] != MAGIC {
        return Err(CryptoError::InvalidMagic);
    }

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&envelope[MAGIC.len()..MAGIC.len() + SALT_LEN]);
    Ok(salt)
}

pub fn encrypt_vault(
    password: &str,
    plaintext: &[u8],
) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), CryptoError> {
    let salt = generate_salt();
    let key = derive_key(password, &salt)?;
    let envelope = encrypt_with_key(&key, &salt, plaintext)?;
    Ok((envelope, key))
}

pub fn decrypt_vault(
    password: &str,
    envelope: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, Zeroizing<[u8; 32]>), CryptoError> {
    let salt = extract_salt(envelope)?;
    let key = derive_key(password, &salt)?;
    let plaintext = decrypt_with_key(&key, envelope)?;
    Ok((plaintext, key))
}
