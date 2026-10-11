use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::RngCore;
use rand::rngs::OsRng;
use std::fmt;
use zeroize::Zeroizing;

/// Legacy format: MAGIC | salt | nonce | ciphertext, fixed KDF params, no AAD.
pub const MAGIC_V1: &[u8; 8] = b"APIMAN01";
/// Current format: MAGIC | m_cost | t_cost | p_cost (u32 LE) | salt | nonce | ciphertext.
/// The whole header is bound to the ciphertext as AEAD associated data.
pub const MAGIC_V2: &[u8; 8] = b"APIMAN02";
pub const MAGIC: &[u8; 8] = MAGIC_V2;
pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
const V1_HEADER_LEN: usize = 8 + SALT_LEN + NONCE_LEN;
const V2_HEADER_LEN: usize = 8 + 12 + SALT_LEN + NONCE_LEN;
pub const MIN_PASSWORD_LEN: usize = 8;

#[derive(Debug)]
pub enum CryptoError {
    InvalidMagic,
    DataTooShort,
    UnsupportedParams(String),
    KeyDerivationFailed(String),
    DecryptionFailed,
    EncryptionFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "Invalid vault format or header"),
            Self::DataTooShort => write!(f, "Encrypted vault file is corrupted or truncated"),
            Self::UnsupportedParams(e) => write!(f, "Unsupported key derivation parameters: {e}"),
            Self::KeyDerivationFailed(e) => write!(f, "Key derivation failed: {e}"),
            Self::DecryptionFailed => {
                write!(
                    f,
                    "Authentication failed: invalid password or tampered vault"
                )
            }
            Self::EncryptionFailed => write!(f, "Encryption operation failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

/// Argon2id, 64 MiB, 3 passes, 4 lanes.
pub const DEFAULT_KDF: KdfParams = KdfParams {
    m_cost: 65536,
    t_cost: 3,
    p_cost: 4,
};

impl KdfParams {
    fn validate(&self) -> Result<(), CryptoError> {
        // Bound what a crafted vault header can make us allocate or spin on.
        if self.m_cost > 4 * 1024 * 1024
            || self.t_cost == 0
            || self.t_cost > 64
            || self.p_cost == 0
            || self.p_cost > 64
        {
            return Err(CryptoError::UnsupportedParams(format!(
                "m={} t={} p={}",
                self.m_cost, self.t_cost, self.p_cost
            )));
        }
        Ok(())
    }
}

/// Everything besides the key that is needed to re-encrypt a vault the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyParams {
    pub salt: [u8; SALT_LEN],
    pub kdf: KdfParams,
}

impl KeyParams {
    pub fn generate() -> Self {
        Self {
            salt: generate_salt(),
            kdf: DEFAULT_KDF,
        }
    }
}

pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn derive_key(password: &str, params: &KeyParams) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    params.kdf.validate()?;
    let argon_params = Params::new(
        params.kdf.m_cost,
        params.kdf.t_cost,
        params.kdf.p_cost,
        Some(32),
    )
    .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), &params.salt, key.as_mut())
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    Ok(key)
}

struct Envelope<'a> {
    params: KeyParams,
    nonce: &'a [u8],
    aad: Option<&'a [u8]>,
    ciphertext: &'a [u8],
}

fn parse_envelope(envelope: &[u8]) -> Result<Envelope<'_>, CryptoError> {
    if envelope.len() < 8 {
        return Err(CryptoError::DataTooShort);
    }
    let magic = &envelope[..8];
    if magic == MAGIC_V2 {
        if envelope.len() < V2_HEADER_LEN {
            return Err(CryptoError::DataTooShort);
        }
        let u32_at = |i: usize| u32::from_le_bytes(envelope[i..i + 4].try_into().unwrap());
        let kdf = KdfParams {
            m_cost: u32_at(8),
            t_cost: u32_at(12),
            p_cost: u32_at(16),
        };
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&envelope[20..20 + SALT_LEN]);
        Ok(Envelope {
            params: KeyParams { salt, kdf },
            nonce: &envelope[20 + SALT_LEN..V2_HEADER_LEN],
            aad: Some(&envelope[..V2_HEADER_LEN]),
            ciphertext: &envelope[V2_HEADER_LEN..],
        })
    } else if magic == MAGIC_V1 {
        if envelope.len() < V1_HEADER_LEN {
            return Err(CryptoError::DataTooShort);
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&envelope[8..8 + SALT_LEN]);
        Ok(Envelope {
            params: KeyParams {
                salt,
                kdf: DEFAULT_KDF,
            },
            nonce: &envelope[8 + SALT_LEN..V1_HEADER_LEN],
            aad: None,
            ciphertext: &envelope[V1_HEADER_LEN..],
        })
    } else {
        Err(CryptoError::InvalidMagic)
    }
}

/// Always writes the current (v2) format.
pub fn encrypt_with_key(
    key: &[u8; 32],
    params: &KeyParams,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let mut envelope = Vec::with_capacity(V2_HEADER_LEN + plaintext.len() + 16);
    envelope.extend_from_slice(MAGIC_V2);
    envelope.extend_from_slice(&params.kdf.m_cost.to_le_bytes());
    envelope.extend_from_slice(&params.kdf.t_cost.to_le_bytes());
    envelope.extend_from_slice(&params.kdf.p_cost.to_le_bytes());
    envelope.extend_from_slice(&params.salt);
    envelope.extend_from_slice(&nonce_bytes);

    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::EncryptionFailed)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &envelope,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;

    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

pub fn decrypt_with_key(
    key: &[u8; 32],
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let env = parse_envelope(envelope)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::DecryptionFailed)?;
    let nonce = XNonce::from_slice(env.nonce);
    let decrypted = match env.aad {
        Some(aad) => cipher.decrypt(
            nonce,
            Payload {
                msg: env.ciphertext,
                aad,
            },
        ),
        None => cipher.decrypt(nonce, env.ciphertext),
    }
    .map_err(|_| CryptoError::DecryptionFailed)?;
    Ok(Zeroizing::new(decrypted))
}

pub fn extract_params(envelope: &[u8]) -> Result<KeyParams, CryptoError> {
    parse_envelope(envelope).map(|e| e.params)
}

pub fn validate_new_password(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!(
            "Master password must be at least {MIN_PASSWORD_LEN} characters"
        ));
    }
    Ok(())
}
