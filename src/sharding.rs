//! Shamir Secret Sharing over GF(2^8) via the `sharks` crate.
//!
//! `threshold`-of-`total_shares` splitting: any `threshold` distinct shares
//! recover the secret; fewer than `threshold` reveals no information
//! (information-theoretic).

use sharks::{Share, Sharks};
use std::convert::TryFrom;

use crate::errors::{AppError, Result};

/// Default total shares (CLI / demo backward compatibility).
pub const DEFAULT_TOTAL_SHARES: u8 = 3;

/// Default recovery threshold.
pub const DEFAULT_THRESHOLD: u8 = 2;

/// Validate Shamir parameters before split.
pub fn validate_sharding(threshold: u8, total_shares: u8) -> Result<()> {
    if threshold < 1 {
        return Err(AppError::ShardingFailed(
            "threshold must be at least 1".into(),
        ));
    }
    if total_shares < 1 {
        return Err(AppError::ShardingFailed(
            "total number of shards must be at least 1".into(),
        ));
    }
    if threshold > total_shares {
        return Err(AppError::ShardingFailed(format!(
            "threshold ({threshold}) cannot exceed total shards ({total_shares})"
        )));
    }
    Ok(())
}

/// Split `secret` into `total_shares` Shamir shares with recovery threshold
/// `threshold` (any `threshold` distinct shares reconstruct the secret).
pub fn split_secret(secret: &[u8], threshold: u8, total_shares: u8) -> Result<Vec<Vec<u8>>> {
    validate_sharding(threshold, total_shares)?;

    if secret.is_empty() {
        return Err(AppError::ShardingFailed(
            "cannot shard an empty secret".into(),
        ));
    }

    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(secret);
    let shares: Vec<Share> = dealer.take(total_shares as usize).collect();

    if shares.len() != total_shares as usize {
        return Err(AppError::ShardingFailed(format!(
            "expected {total_shares} shards, generated {}",
            shares.len()
        )));
    }

    Ok(shares.iter().map(Vec::<u8>::from).collect())
}

/// Recover the original secret from at least `threshold` distinct shards.
/// All supplied shards must parse; duplicate x-coordinates are rejected.
pub fn combine_shares(shards: &[Vec<u8>], threshold: u8) -> Result<Vec<u8>> {
    if threshold < 1 {
        return Err(AppError::RecoveryFailed(
            "invalid threshold for reconstruction".into(),
        ));
    }

    if shards.len() < threshold as usize {
        return Err(AppError::RecoveryFailed(format!(
            "at least {threshold} shards are required, got {}",
            shards.len()
        )));
    }

    for (i, s) in shards.iter().enumerate() {
        if s.len() < 2 {
            return Err(AppError::RecoveryFailed(format!(
                "shard #{i} is malformed (too short)"
            )));
        }
    }

    for i in 0..shards.len() {
        for j in (i + 1)..shards.len() {
            if shards[i][0] == shards[j][0] {
                return Err(AppError::RecoveryFailed(
                    "duplicate shard identifiers detected; provide distinct shards".into(),
                ));
            }
        }
    }

    let parsed: std::result::Result<Vec<Share>, &'static str> = shards
        .iter()
        .map(|bytes| Share::try_from(bytes.as_slice()))
        .collect();

    let parsed = parsed.map_err(|e| AppError::RecoveryFailed(format!("invalid shard: {e}")))?;

    let sharks = Sharks(threshold);
    sharks
        .recover(parsed.as_slice())
        .map_err(|e| AppError::RecoveryFailed(format!("secret reconstruction failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_then_combine_with_all_shards() {
        let secret = b"super secret 256-bit material..!";
        let shards = split_secret(secret, 2, 3).expect("split failed");
        assert_eq!(shards.len(), 3);
        let recovered = combine_shares(&shards, 2).expect("recover failed");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_combine_with_threshold_subset() {
        let secret = b"another secret value 12345678901";
        let shards = split_secret(secret, 2, 3).expect("split failed");

        for (i, j) in [(0usize, 1usize), (0, 2), (1, 2)] {
            let subset = vec![shards[i].clone(), shards[j].clone()];
            let recovered = combine_shares(&subset, 2).expect("recover failed");
            assert_eq!(recovered, secret, "subset ({i},{j}) failed to reconstruct");
        }
    }

    #[test]
    fn test_combine_below_threshold_fails() {
        let secret = b"third secret material................";
        let shards = split_secret(secret, 2, 3).expect("split failed");
        let result = combine_shares(&shards[..1], 2);
        assert!(result.is_err(), "1-of-3 must not be accepted");
    }

    #[test]
    fn test_combine_duplicate_shards_rejected() {
        let secret = b"fourth secret material..............";
        let shards = split_secret(secret, 2, 3).expect("split failed");
        let dup = vec![shards[0].clone(), shards[0].clone()];
        let result = combine_shares(&dup, 2);
        assert!(result.is_err(), "duplicate shards must be rejected");
    }

    #[test]
    fn test_split_empty_secret_rejected() {
        let result = split_secret(&[], 2, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_combine_invalid_shard_bytes() {
        let bad = vec![vec![0u8; 0], vec![1u8, 2u8, 3u8]];
        let result = combine_shares(&bad, 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_combine_same_x_coordinate_rejected() {
        let secret = b"x-collision test material........";
        let mut shards = split_secret(secret, 2, 3).expect("split failed");
        shards[1][0] = shards[0][0];
        let result = combine_shares(&shards[..2], 2);
        assert!(result.is_err(), "shards with same x must be rejected");
    }

    #[test]
    fn test_shards_are_distinct() {
        let secret = b"distinct shard test..............";
        let shards = split_secret(secret, 2, 3).expect("split failed");
        assert_ne!(shards[0], shards[1]);
        assert_ne!(shards[0], shards[2]);
        assert_ne!(shards[1], shards[2]);
    }

    #[test]
    fn test_single_shard_reveals_nothing_about_secret() {
        let secret = b"top-secret content @@@@@@@@@@@@@";
        let shards = split_secret(secret, 2, 3).expect("split failed");
        for s in &shards {
            assert_ne!(s.as_slice(), secret.as_slice());
        }
    }

    #[test]
    fn test_threshold_exceeds_total_rejected() {
        assert!(validate_sharding(4, 3).is_err());
    }

    #[test]
    fn test_three_of_five_roundtrip() {
        let secret = b"five-way split test material!!!!!";
        let shards = split_secret(secret, 3, 5).expect("split failed");
        assert_eq!(shards.len(), 5);
        let subset = vec![
            shards[0].clone(),
            shards[2].clone(),
            shards[4].clone(),
        ];
        let recovered = combine_shares(&subset, 3).expect("3-of-5 recover");
        assert_eq!(recovered, secret);
    }
}
