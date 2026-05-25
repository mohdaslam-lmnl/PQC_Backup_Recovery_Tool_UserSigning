use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::errors::{AppError, Result};

/// Derive the AES key used to encrypt backup file contents from the random DEK
/// material and the user-supplied passphrase.
///
/// HKDF-SHA256 with correct role assignment:
///   - IKM  = `dek`                   (random 256-bit high-entropy material from shards)
///   - Salt = SHA-256(passphrase)      (user passphrase hashed to a fixed-length salt)
///   - Info = "backup-file-encryption" (context label)
///
/// At backup: random `dek` is generated; passphrase + dek → file key → encrypts file.
/// At recovery: `dek` is reconstructed by combining shards and decrypting with the
/// ML-KEM-derived key; passphrase + dek → same file key → decrypts file.
pub fn derive_backup_file_key(dek: &[u8; 32], passphrase: &str) -> Result<Zeroizing<[u8; 32]>> {
    if passphrase.is_empty() {
        return Err(AppError::InvalidInput(
            "passphrase must not be empty".into(),
        ));
    }
    // Hash the passphrase to a fixed-length (32-byte) HKDF salt.
    // This ensures the passphrase plays its correct role in HKDF extract regardless
    // of passphrase length, and provides proper domain separation.
    let salt = Sha256::digest(passphrase.as_bytes());
    // IKM = dek (the random 256-bit material — high entropy, correct HKDF IKM role).
    let hk = Hkdf::<Sha256>::new(Some(&salt), dek);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(b"backup-file-encryption", &mut *key)
        .map_err(|e| AppError::KeyDerivationFailed(e.to_string()))?;
    Ok(key)
}

/// Derive a 256-bit AES key from a shared secret using HKDF-SHA256.
/// The returned key is wrapped in `Zeroizing` for automatic secure erasure.
pub fn derive_key(shared_secret: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(b"aes-key-wrapping", &mut *key)
        .map_err(|e| AppError::KeyDerivationFailed(e.to_string()))?;
    Ok(key)
}

/// Encrypt plaintext using AES-256-GCM with a random nonce.
/// Returns (ciphertext_with_tag, nonce).
pub fn encrypt(aes_key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
    let cipher = Aes256Gcm::new_from_slice(aes_key)
        .map_err(|e| AppError::AesEncryptionFailed(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|e| AppError::AesEncryptionFailed(e.to_string()))?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypt ciphertext using AES-256-GCM.
pub fn decrypt(aes_key: &[u8; 32], ciphertext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(aes_key)
        .map_err(|e| AppError::AesDecryptionFailed(e.to_string()))?;

    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| AppError::AesDecryptionFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_roundtrip() {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);

        let plaintext = b"The quick brown fox jumps over the lazy dog";
        let (ct, nonce) = encrypt(&key, plaintext).expect("encrypt failed");
        let recovered = decrypt(&key, &ct, &nonce).expect("decrypt failed");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_aes_decrypt_wrong_key_fails() {
        let mut key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        OsRng.fill_bytes(&mut key1);
        OsRng.fill_bytes(&mut key2);

        let (ct, nonce) = encrypt(&key1, b"secret").expect("encrypt failed");
        let result = decrypt(&key2, &ct, &nonce);
        assert!(result.is_err(), "decrypt with wrong key must fail");
    }

    #[test]
    fn test_derive_key_deterministic() {
        let secret = b"test-shared-secret-material-1234";
        let k1 = derive_key(secret).expect("derive failed");
        let k2 = derive_key(secret).expect("derive failed");
        assert_eq!(*k1, *k2, "same input must produce same derived key");
    }

    #[test]
    fn test_backup_file_key_differs_from_dek() {
        let dek = [1u8; 32];
        let file_key = derive_backup_file_key(&dek, "user-passphrase").unwrap();
        assert_ne!(*file_key, dek);
    }

    #[test]
    fn test_backup_file_key_wrong_passphrase_fails_decrypt() {
        let dek = [2u8; 32];
        let k1 = derive_backup_file_key(&dek, "correct").unwrap();
        let k2 = derive_backup_file_key(&dek, "wrong").unwrap();
        assert_ne!(*k1, *k2);
        let (ct, nonce) = encrypt(&k1, b"data").unwrap();
        assert!(decrypt(&k2, &ct, &nonce).is_err());
    }
}