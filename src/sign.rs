//! ML-DSA / CRYSTALS-Dilithium3 detached signatures (`pqcrypto-dilithium`).
use pqcrypto_dilithium::dilithium3::{
    detached_sign, keypair, verify_detached_signature, DetachedSignature, PublicKey, SecretKey,
};
use pqcrypto_traits::sign::{
    DetachedSignature as _, PublicKey as _, SecretKey as _,
};

use crate::errors::{AppError, Result};

/// Generate a Dilithium3 signing keypair (public key, secret key bytes).
pub fn keygen() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

/// Message signed for each shard: Shamir share bytes ‖ ML-KEM shared secret (32 B).
pub fn shard_signing_message(shard_wire_bytes: &[u8], shared_secret: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(shard_wire_bytes.len() + shared_secret.len());
    msg.extend_from_slice(shard_wire_bytes);
    msg.extend_from_slice(shared_secret);
    msg
}

pub fn sign_message(message: &[u8], sk_bytes: &[u8]) -> Result<Vec<u8>> {
    let sk = SecretKey::from_bytes(sk_bytes).map_err(|e| {
        AppError::DilithiumSignFailed(format!("invalid signing secret key: {e}"))
    })?;
    let sig = detached_sign(message, &sk);
    Ok(sig.as_bytes().to_vec())
}

pub fn verify_message(message: &[u8], sig_bytes: &[u8], pk_bytes: &[u8]) -> Result<()> {
    let pk = PublicKey::from_bytes(pk_bytes).map_err(|e| {
        AppError::DilithiumVerifyFailed(format!("invalid signing public key: {e}"))
    })?;
    let sig = DetachedSignature::from_bytes(sig_bytes).map_err(|e| {
        AppError::DilithiumVerifyFailed(format!("invalid signature encoding: {e}"))
    })?;
    verify_detached_signature(&sig, message, &pk).map_err(|e| {
        AppError::DilithiumVerifyFailed(format!("signature check failed: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_shard_message_roundtrip() {
        let (pk, sk) = keygen();
        let shard = b"share-bytes";
        let ss = [7u8; 32];
        let msg = shard_signing_message(shard, &ss);
        let sig = sign_message(&msg, &sk).unwrap();
        verify_message(&msg, &sig, &pk).unwrap();
    }

    #[test]
    fn tampered_shard_bytes_fails() {
        let (pk, sk) = keygen();
        let ss = [1u8; 32];
        let msg = shard_signing_message(b"original", &ss);
        let sig = sign_message(&msg, &sk).unwrap();
        let bad = shard_signing_message(b"tampered", &ss);
        assert!(verify_message(&bad, &sig, &pk).is_err());
    }
}
