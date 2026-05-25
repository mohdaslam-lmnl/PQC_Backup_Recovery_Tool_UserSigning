use pqcrypto_mlkem::mlkem768::*;
use pqcrypto_traits::kem::{
    PublicKey as _, SecretKey as _, Ciphertext as _, SharedSecret as _,
};

use crate::errors::{AppError, Result};

/// Generate an ML-KEM 768 keypair.
/// Returns (public_key_bytes, secret_key_bytes).
pub fn keygen() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

/// Encapsulate against the given public key.
/// Returns (kem_ciphertext, shared_secret).
pub fn encapsulate_key(pk_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let pk = PublicKey::from_bytes(pk_bytes).map_err(|e| {
        AppError::KemEncapsulationFailed(format!("invalid public key: {e}"))
    })?;

    // NOTE: pqcrypto_mlkem::encapsulate returns (SharedSecret, Ciphertext)
    let (ss, ct) = pqcrypto_mlkem::mlkem768::encapsulate(&pk);

    Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
}

/// Decapsulate the KEM ciphertext using the secret key.
/// Returns the shared secret.
pub fn decapsulate_key(ct_bytes: &[u8], sk_bytes: &[u8]) -> Result<Vec<u8>> {
    let ct = Ciphertext::from_bytes(ct_bytes).map_err(|e| {
        AppError::KemDecapsulationFailed(format!("invalid ciphertext: {e}"))
    })?;
    let sk = SecretKey::from_bytes(sk_bytes).map_err(|e| {
        AppError::KemDecapsulationFailed(format!("invalid secret key: {e}"))
    })?;

    let ss = pqcrypto_mlkem::mlkem768::decapsulate(&ct, &sk);
    Ok(ss.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_roundtrip() {
        let (pk, sk) = keygen();
        let (ct, ss_enc) = encapsulate_key(&pk).expect("encapsulate failed");
        let ss_dec = decapsulate_key(&ct, &sk).expect("decapsulate failed");
        assert_eq!(ss_enc, ss_dec, "shared secrets must match");
        assert_eq!(ct.len(), 1088, "ML-KEM 768 ciphertext must be 1088 bytes");
        assert_eq!(ss_enc.len(), 32, "shared secret must be 32 bytes");
    }

    #[test]
    fn test_encapsulate_invalid_pk() {
        let bad_pk = vec![0u8; 10];
        let result = encapsulate_key(&bad_pk);
        assert!(result.is_err());
    }

    #[test]
    fn test_decapsulate_invalid_ct() {
        let (_, sk) = keygen();
        let bad_ct = vec![0u8; 10];
        let result = decapsulate_key(&bad_ct, &sk);
        assert!(result.is_err());
    }
}