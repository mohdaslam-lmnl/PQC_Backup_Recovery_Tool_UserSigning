use thiserror::Error;

/// Unified error type for the enc_app application.
#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum AppError {
    #[error("KEM key generation failed")]
    KemKeygenFailed,

    #[error("KEM encapsulation failed: {0}")]
    KemEncapsulationFailed(String),

    #[error("KEM decapsulation failed: {0}")]
    KemDecapsulationFailed(String),

    #[error("AES encryption failed: {0}")]
    AesEncryptionFailed(String),

    #[error("AES decryption failed: {0}")]
    AesDecryptionFailed(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("Base64 decoding failed: {0}")]
    Base64DecodeFailed(#[from] base64::DecodeError),

    #[error("JSON serialization/deserialization failed: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength { expected: usize, actual: usize },

    #[error("UTF-8 decoding failed: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    #[error("Shamir sharding failed: {0}")]
    ShardingFailed(String),

    #[error("Recovery failed: {0}")]
    RecoveryFailed(String),

    #[error("Dilithium signing failed: {0}")]
    DilithiumSignFailed(String),

    #[error("Dilithium verification failed: {0}")]
    DilithiumVerifyFailed(String),

    #[error("Shard {index}: {detail}")]
    ShardError { index: u8, detail: String },
}

pub type Result<T> = std::result::Result<T, AppError>;
