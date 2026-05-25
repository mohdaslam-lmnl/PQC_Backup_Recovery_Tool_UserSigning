mod crypto;
mod errors;
mod kem;
mod server_backup;
mod server_recovery;
mod sharding;
mod sign;
pub mod utils;

use clap::{Parser, Subcommand};
use errors::{AppError, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read};
use zeroize::Zeroizing;

// ─── Data Structures ────────────────────────────────────────────────

/// Parameters required to decrypt a file, excluding the wrapped DEK
/// ciphertext (which is delivered separately as Shamir shards).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EncryptionParams {
    /// ML-KEM ciphertext (base64).
    pub kem_ct: String,
    /// Nonce used when encrypting the AES key (base64).
    pub key_nonce: String,
    /// User data encrypted by the AES key (base64).
    pub ciphertext: String,
    /// Nonce used when encrypting the user data (base64).
    pub msg_nonce: String,
}

/// Non-shard material the user stores alongside shard files (offline backup).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RestPayload {
    pub params: EncryptionParams,
    pub total_shards: u8,
    pub threshold: u8,
    /// ML-KEM 768 public key (base64) used for encapsulation at backup time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encapsulation_key_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_filename: Option<String>,
}

/// A single Shamir shard of the wrapped AES key ciphertext (legacy / internal).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyShard {
    /// 1-based shard index in `[1, total]`.
    pub index: u8,
    /// Total number of shards produced.
    pub total: u8,
    /// Recovery threshold (minimum shards required to reconstruct).
    pub threshold: u8,
    /// Base64-encoded shard payload.
    pub data: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encapsulation_key_b64: Option<String>,
}

/// Self-contained signed shard: embedded crypto material + ML-DSA signature.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SignedKeyShard {
    pub index: u8,
    pub total: u8,
    pub threshold: u8,
    pub data: String,
    pub params: EncryptionParams,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encapsulation_key_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_filename: Option<String>,
    /// Base64-encoded Dilithium3 detached signature over `shard_wire ‖ shared_secret`.
    pub signature: String,
}

/// Full JSON envelope (params + all shards inline). Used by CLI and tests.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ShardedEnvelope {
    pub params: EncryptionParams,
    pub shards: Vec<KeyShard>,
}

/// Output of the signed backup encryption pipeline.
#[derive(Clone, Debug)]
pub struct SignedBackupArtifacts {
    pub signing_public_key_b64: String,
    pub shards: Vec<SignedKeyShard>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum DecryptInput {
    SignedShards(Vec<SignedKeyShard>),
    Full(ShardedEnvelope),
    Rest(RestPayload),
}

// ─── CLI Definition ─────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "enc_app",
    version,
    about = "Post-quantum hybrid encryption (ML-KEM 768 + AES-256-GCM) with configurable Shamir sharding"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate an ML-KEM 768 keypair and write pk.b64 / sk.b64 to the current directory.
    Keygen,

    /// Encrypt plaintext data using a public key.
    Encrypt {
        #[arg(long)]
        pk: String,
        #[arg(long)]
        passphrase: String,
        #[arg(long)]
        data: Option<String>,
        #[arg(long, short)]
        output: Option<String>,
        #[arg(long)]
        shards_dir: Option<String>,
        #[arg(long, default_value_t = sharding::DEFAULT_THRESHOLD)]
        threshold: u8,
        #[arg(long = "total-shares", default_value_t = sharding::DEFAULT_TOTAL_SHARES)]
        total_shares: u8,
    },

    /// Decrypt using a secret key, signing public key, and signed shard files.
    Decrypt {
        #[arg(long)]
        sk: String,
        #[arg(long)]
        passphrase: String,
        #[arg(long = "sign-pk")]
        sign_pk: Option<String>,
        #[arg(long, short)]
        input: Option<String>,
        #[arg(long = "shard", value_name = "PATH", num_args = 0..)]
        shards: Vec<String>,
    },

    Demo,

    /// Start the backup web UI (default port 8081).
    BackupServer {
        #[arg(long, short, default_value_t = 8081)]
        port: u16,
    },

    /// Start the recovery web UI (default port 8082).
    RecoveryServer {
        #[arg(long, short, default_value_t = 8082)]
        port: u16,
    },
}

// ─── Core Logic ───────────────────────────────────────────────────────

fn normalize_encapsulation_key_b64(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

fn ensure_shard_encapsulation_keys_consistent(shards: &[KeyShard]) -> Result<()> {
    let mut expected: Option<String> = None;
    for s in shards {
        if let Some(ref k) = s.encapsulation_key_b64 {
            let n = normalize_encapsulation_key_b64(k);
            match &expected {
                None => expected = Some(n),
                Some(e) if e != &n => {
                    return Err(AppError::InvalidInput(
                        "encapsulation key differs across shard files".into(),
                    ));
                }
                Some(_) => {}
            }
        }
    }
    Ok(())
}

fn ensure_rest_encapsulation_key_matches_shards(rest: &RestPayload, shards: &[KeyShard]) -> Result<()> {
    let Some(ref rk) = rest.encapsulation_key_b64 else {
        return Ok(());
    };
    let rn = normalize_encapsulation_key_b64(rk);
    for s in shards {
        if let Some(ref sk) = s.encapsulation_key_b64 {
            if normalize_encapsulation_key_b64(sk) != rn {
                return Err(AppError::InvalidInput(
                    "shard encapsulation key does not match rest payload".into(),
                ));
            }
        }
    }
    Ok(())
}

/// Encrypt, embed rest material in every shard, and sign each shard with Dilithium3.
pub fn encrypt_signed_backup_artifacts(
    data: &str,
    pk_bytes: &[u8],
    sign_sk_bytes: &[u8],
    sign_pk_bytes: &[u8],
    passphrase: &str,
    threshold: u8,
    total_shares: u8,
    original_filename: Option<String>,
) -> Result<SignedBackupArtifacts> {
    if data.is_empty() {
        return Err(AppError::InvalidInput("data must not be empty".into()));
    }
    sharding::validate_sharding(threshold, total_shares)?;

    let mut dek = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *dek);
    let file_key = crypto::derive_backup_file_key(&dek, passphrase)?;

    let (kem_ct, shared_secret) = kem::encapsulate_key(pk_bytes)?;
    let kek = crypto::derive_key(&shared_secret)?;
    let (enc_aes_key, key_nonce) = crypto::encrypt(&kek, &*dek)?;
    let (ciphertext, msg_nonce) = crypto::encrypt(&*file_key, data.as_bytes())?;

    let shard_bytes = sharding::split_secret(&enc_aes_key, threshold, total_shares)?;
    let encapsulation_key_b64 = utils::b64e(pk_bytes);
    let params = EncryptionParams {
        kem_ct: utils::b64e(&kem_ct),
        key_nonce: utils::b64e(&key_nonce),
        ciphertext: utils::b64e(&ciphertext),
        msg_nonce: utils::b64e(&msg_nonce),
    };

    let signing_public_key_b64 = utils::b64e(sign_pk_bytes);

    let mut shards = Vec::with_capacity(shard_bytes.len());
    for (i, wire_bytes) in shard_bytes.into_iter().enumerate() {
        let message = sign::shard_signing_message(&wire_bytes, &shared_secret);
        let sig = sign::sign_message(&message, sign_sk_bytes)?;
        shards.push(SignedKeyShard {
            index: (i + 1) as u8,
            total: total_shares,
            threshold,
            data: utils::b64e(&wire_bytes),
            params: params.clone(),
            encapsulation_key_b64: Some(encapsulation_key_b64.clone()),
            original_filename: original_filename.clone(),
            signature: utils::b64e(&sig),
        });
    }

    Ok(SignedBackupArtifacts {
        signing_public_key_b64,
        shards,
    })
}

fn shared_secret_for_shard(shard: &SignedKeyShard, kem_sk_bytes: &[u8]) -> Result<Vec<u8>> {
    let kem_ct = utils::b64d(&shard.params.kem_ct).map_err(|e| {
        AppError::ShardError {
            index: shard.index,
            detail: format!("invalid kem_ct in embedded params: {e}"),
        }
    })?;
    kem::decapsulate_key(&kem_ct, kem_sk_bytes).map_err(|e| AppError::ShardError {
        index: shard.index,
        detail: format!(
            "KEM decapsulation failed (wrong decapsulation key or tampered kem_ct): {e}"
        ),
    })
}

/// Verify one signed shard (ML-DSA over shard wire bytes ‖ ML-KEM shared secret).
pub fn verify_signed_shard(
    shard: &SignedKeyShard,
    kem_sk_bytes: &[u8],
    sign_pk_bytes: &[u8],
) -> Result<()> {
    if shard.signature.is_empty() {
        return Err(AppError::ShardError {
            index: shard.index,
            detail: "missing signature".into(),
        });
    }
    let wire = utils::b64d(&shard.data).map_err(|e| AppError::ShardError {
        index: shard.index,
        detail: format!("invalid shard data (base64): {e}"),
    })?;
    let shared_secret = shared_secret_for_shard(shard, kem_sk_bytes)?;
    let message = sign::shard_signing_message(&wire, &shared_secret);
    let sig = utils::b64d(&shard.signature).map_err(|e| AppError::ShardError {
        index: shard.index,
        detail: format!("invalid signature (base64): {e}"),
    })?;
    sign::verify_message(&message, &sig, sign_pk_bytes).map_err(|e| AppError::ShardError {
        index: shard.index,
        detail: format!("ML-DSA signature invalid or shard/shared-secret tampered: {e}"),
    })
}

/// Ensure all signed shards carry identical embedded backup material.
pub fn ensure_signed_shards_consistent(shards: &[SignedKeyShard]) -> Result<()> {
    if shards.is_empty() {
        return Err(AppError::InvalidInput("no shards provided".into()));
    }
    let first = &shards[0];
    for s in shards.iter().skip(1) {
        if s.params != first.params {
            return Err(AppError::InvalidInput(format!(
                "shard {} embedded params do not match shard {}",
                s.index, first.index
            )));
        }
        if s.total != first.total || s.threshold != first.threshold {
            return Err(AppError::InvalidInput(format!(
                "shard {} metadata (total/threshold) does not match shard {}",
                s.index, first.index
            )));
        }
        if s.encapsulation_key_b64 != first.encapsulation_key_b64 {
            return Err(AppError::InvalidInput(format!(
                "shard {} encapsulation key does not match shard {}",
                s.index, first.index
            )));
        }
        if s.original_filename != first.original_filename {
            return Err(AppError::InvalidInput(format!(
                "shard {} original_filename does not match shard {}",
                s.index, first.index
            )));
        }
    }
    Ok(())
}

fn signed_to_key_shards(shards: &[SignedKeyShard]) -> Vec<KeyShard> {
    shards
        .iter()
        .map(|s| KeyShard {
            index: s.index,
            total: s.total,
            threshold: s.threshold,
            data: s.data.clone(),
            encapsulation_key_b64: s.encapsulation_key_b64.clone(),
        })
        .collect()
}

/// Verify every shard signature, then decrypt using embedded params.
pub fn decrypt_from_signed_shards(
    shards: &[SignedKeyShard],
    kem_sk_bytes: &[u8],
    sign_pk_bytes: &[u8],
    passphrase: &str,
) -> Result<String> {
    if shards.is_empty() {
        return Err(AppError::InvalidInput("at least one shard is required".into()));
    }
    ensure_signed_shards_consistent(shards)?;
    let threshold = shards[0].threshold;
    if shards.len() < threshold as usize {
        return Err(AppError::InvalidInput(format!(
            "need at least {threshold} verified shards, got {}",
            shards.len()
        )));
    }
    for s in shards {
        if s.index == 0 || s.index > s.total {
            return Err(AppError::InvalidInput(format!(
                "shard index {} is out of range [1, {}]",
                s.index, s.total
            )));
        }
    }
    for s in shards {
        verify_signed_shard(s, kem_sk_bytes, sign_pk_bytes)?;
    }
    let key_shards = signed_to_key_shards(shards);
    let params = shards[0].params.clone();
    decrypt_with_shards(&params, &key_shards, kem_sk_bytes, passphrase)
}

/// Default 2-of-3 signed encryption (tests, demo).
pub fn encrypt_data_signed(
    data: &str,
    pk_bytes: &[u8],
    sign_pk_bytes: &[u8],
    sign_sk_bytes: &[u8],
    passphrase: &str,
) -> Result<SignedBackupArtifacts> {
    encrypt_signed_backup_artifacts(
        data,
        pk_bytes,
        sign_sk_bytes,
        sign_pk_bytes,
        passphrase,
        sharding::DEFAULT_THRESHOLD,
        sharding::DEFAULT_TOTAL_SHARES,
        None,
    )
}

/// Legacy unsigned envelope (tests only).
pub fn encrypt_data(data: &str, pk_bytes: &[u8], passphrase: &str) -> Result<ShardedEnvelope> {
    if data.is_empty() {
        return Err(AppError::InvalidInput("data must not be empty".into()));
    }
    let (sign_pk, sign_sk) = sign::keygen();
    let signed = encrypt_signed_backup_artifacts(
        data,
        pk_bytes,
        &sign_sk,
        &sign_pk,
        passphrase,
        sharding::DEFAULT_THRESHOLD,
        sharding::DEFAULT_TOTAL_SHARES,
        None,
    )?;
    Ok(ShardedEnvelope {
        params: signed.shards[0].params.clone(),
        shards: signed_to_key_shards(&signed.shards),
    })
}

pub fn decrypt_with_shards(
    params: &EncryptionParams,
    shards: &[KeyShard],
    sk_bytes: &[u8],
    passphrase: &str,
) -> Result<String> {
    if shards.is_empty() {
        return Err(AppError::InvalidInput(
            "at least one key shard is required".into(),
        ));
    }

    ensure_shard_encapsulation_keys_consistent(shards)?;

    let threshold = shards[0].threshold;
    let total = shards[0].total;

    if shards.len() < threshold as usize {
        return Err(AppError::InvalidInput(format!(
            "at least {threshold} key shards are required, got {}",
            shards.len()
        )));
    }

    for s in shards {
        if s.total != total || s.threshold != threshold {
            return Err(AppError::InvalidInput(format!(
                "incompatible shard metadata (expected total={total}, threshold={threshold}; got total={}, threshold={})",
                s.total, s.threshold
            )));
        }
        if s.index == 0 || s.index > total {
            return Err(AppError::InvalidInput(format!(
                "shard index {} is out of range [1, {total}]",
                s.index
            )));
        }
    }

    let raw_shards: std::result::Result<Vec<Vec<u8>>, AppError> =
        shards.iter().map(|s| utils::b64d(&s.data)).collect();
    let raw_shards = raw_shards?;
    let enc_aes_key = sharding::combine_shares(&raw_shards, threshold)?;

    let kem_ct = utils::b64d(&params.kem_ct)?;
    let key_nonce_vec = utils::b64d(&params.key_nonce)?;
    let ciphertext = utils::b64d(&params.ciphertext)?;
    let msg_nonce_vec = utils::b64d(&params.msg_nonce)?;

    let key_nonce: [u8; 12] = key_nonce_vec
        .try_into()
        .map_err(|v: Vec<u8>| AppError::InvalidNonceLength {
            expected: 12,
            actual: v.len(),
        })?;
    let msg_nonce: [u8; 12] = msg_nonce_vec
        .try_into()
        .map_err(|v: Vec<u8>| AppError::InvalidNonceLength {
            expected: 12,
            actual: v.len(),
        })?;

    let shared_secret = kem::decapsulate_key(&kem_ct, sk_bytes)?;
    let kek = crypto::derive_key(&shared_secret)?;
    let dek_vec = Zeroizing::new(crypto::decrypt(&kek, &enc_aes_key, &key_nonce)?);
    let dek: Zeroizing<[u8; 32]> = {
        let len = dek_vec.len();
        let arr: [u8; 32] = (*dek_vec)
            .clone()
            .try_into()
            .map_err(|_| AppError::InvalidKeyLength {
                expected: 32,
                actual: len,
            })?;
        Zeroizing::new(arr)
    };
    let file_key = crypto::derive_backup_file_key(&dek, passphrase)?;

    let plaintext = crypto::decrypt(&*file_key, &ciphertext, &msg_nonce)?;
    String::from_utf8(plaintext).map_err(AppError::Utf8Error)
}

/// Decrypt using a rest payload (params + shard counts) and uploaded shards.
pub fn decrypt_from_rest(
    rest: &RestPayload,
    shards: &[KeyShard],
    sk_bytes: &[u8],
    passphrase: &str,
) -> Result<String> {
    if shards.len() < rest.threshold as usize {
        return Err(AppError::InvalidInput(format!(
            "need at least {} shards (per rest payload), got {}",
            rest.threshold,
            shards.len()
        )));
    }
    for s in shards {
        if s.total != rest.total_shards || s.threshold != rest.threshold {
            return Err(AppError::InvalidInput(
                "shard metadata does not match the rest payload (total_shards / threshold)".into(),
            ));
        }
    }
    ensure_rest_encapsulation_key_matches_shards(rest, shards)?;
    decrypt_with_shards(&rest.params, shards, sk_bytes, passphrase)
}

pub fn decrypt_envelope(
    envelope: &ShardedEnvelope,
    sk_bytes: &[u8],
    passphrase: &str,
) -> Result<String> {
    decrypt_with_shards(&envelope.params, &envelope.shards, sk_bytes, passphrase)
}

// ─── Subcommand Handlers ──────────────────────────────────────────────

fn cmd_keygen() -> Result<()> {
    let (pk, sk) = kem::keygen();
    fs::write("pk.b64", utils::b64e(&pk))?;
    fs::write("sk.b64", utils::b64e(&sk))?;
    eprintln!("✔ Keypair written to pk.b64 and sk.b64");
    Ok(())
}

fn cmd_encrypt(
    pk_path: &str,
    passphrase: &str,
    data: Option<String>,
    output: Option<String>,
    shards_dir: Option<String>,
    threshold: u8,
    total_shares: u8,
) -> Result<()> {
    let pk_b64 = fs::read_to_string(pk_path).map_err(|e| {
        AppError::InvalidInput(format!("cannot read public key file '{pk_path}': {e}"))
    })?;
    let pk = utils::b64d(pk_b64.trim())?;

    let plaintext = match data {
        Some(d) => d,
        None => {
            eprintln!("Reading plaintext from stdin (end with Ctrl+D)...");
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            buf
        }
    };

    let (sign_pk, sign_sk) = sign::keygen();
    let artifacts = encrypt_signed_backup_artifacts(
        &plaintext,
        &pk,
        &sign_sk,
        &sign_pk,
        passphrase,
        threshold,
        total_shares,
        None,
    )?;
    eprintln!(
        "✔ Signing public key (save for recovery): {}",
        artifacts.signing_public_key_b64
    );
    let _ = sign_pk;

    if let Some(dir) = shards_dir {
        let dir_path = std::path::Path::new(&dir);
        if !dir_path.exists() {
            fs::create_dir_all(dir_path)?;
        }
        let basename = output
            .as_deref()
            .and_then(|p| std::path::Path::new(p).file_stem().and_then(|s| s.to_str()))
            .unwrap_or("backup")
            .to_string();
        fs::write(
            dir_path.join(format!("{basename}.sign_pk.b64")),
            &artifacts.signing_public_key_b64,
        )?;
        for s in &artifacts.shards {
            let shard_path = dir_path.join(format!("{basename}.shard{}.json", s.index));
            let shard_json = serde_json::to_string_pretty(s).map_err(AppError::JsonError)?;
            fs::write(&shard_path, shard_json)?;
            eprintln!("✔ Wrote signed shard {}/{}: {}", s.index, s.total, shard_path.display());
        }
    } else if let Some(ref path) = output {
        let json_out = serde_json::to_string_pretty(&artifacts.shards).map_err(AppError::JsonError)?;
        fs::write(path, &json_out)?;
        eprintln!("✔ Signed shards written to {path}");
    } else {
        let json_out = serde_json::to_string_pretty(&artifacts.shards).map_err(AppError::JsonError)?;
        println!("{json_out}");
    }

    Ok(())
}

fn cmd_decrypt(
    sk_path: &str,
    passphrase: &str,
    sign_pk_path: Option<&str>,
    input: Option<String>,
    shard_paths: Vec<String>,
) -> Result<()> {
    let sk_b64 = fs::read_to_string(sk_path).map_err(|e| {
        AppError::InvalidInput(format!("cannot read secret key file '{sk_path}': {e}"))
    })?;
    let sk = utils::b64d(sk_b64.trim())?;

    let sign_pk_bytes = if let Some(p) = sign_pk_path {
        Some(utils::b64d(fs::read_to_string(p)?.trim())?)
    } else {
        None
    };

    if input.is_none() && !shard_paths.is_empty() {
        let shards = load_signed_shards_from_paths(&shard_paths)?;
        let sign_pk = sign_pk_bytes.ok_or_else(|| {
            AppError::InvalidInput("shard-only decrypt requires --sign-pk".into())
        })?;
        let plaintext = decrypt_from_signed_shards(&shards, &sk, &sign_pk, passphrase)?;
        println!("{plaintext}");
        return Ok(());
    }

    let json_input = match input {
        Some(path) => fs::read_to_string(&path)
            .map_err(|e| AppError::InvalidInput(format!("cannot read input file '{path}': {e}")))?,
        None => {
            eprintln!("Reading encrypted JSON from stdin (end with Ctrl+D)...");
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            buf
        }
    };

    let parsed: DecryptInput = serde_json::from_str(&json_input).map_err(AppError::JsonError)?;

    let plaintext = match parsed {
        DecryptInput::SignedShards(mut shards) => {
            if !shard_paths.is_empty() {
                shards = load_signed_shards_from_paths(&shard_paths)?;
            }
            let sign_pk = sign_pk_bytes.ok_or_else(|| {
                AppError::InvalidInput(
                    "signed shard recovery requires --sign-pk (Dilithium public key file)".into(),
                )
            })?;
            decrypt_from_signed_shards(&shards, &sk, &sign_pk, passphrase)?
        }
        DecryptInput::Full(mut envelope) => {
            if !shard_paths.is_empty() {
                let mut loaded = Vec::with_capacity(shard_paths.len());
                for path in &shard_paths {
                    let s = fs::read_to_string(path).map_err(|e| {
                        AppError::InvalidInput(format!("cannot read shard file '{path}': {e}"))
                    })?;
                    let shard: KeyShard = serde_json::from_str(&s).map_err(AppError::JsonError)?;
                    loaded.push(shard);
                }
                envelope.shards = loaded;
            }
            decrypt_envelope(&envelope, &sk, passphrase)?
        }
        DecryptInput::Rest(rest) => {
            if shard_paths.is_empty() {
                return Err(AppError::InvalidInput(
                    "rest payload input requires at least one --shard file".into(),
                ));
            }
            let mut loaded = Vec::with_capacity(shard_paths.len());
            for path in &shard_paths {
                let s = fs::read_to_string(path).map_err(|e| {
                    AppError::InvalidInput(format!("cannot read shard file '{path}': {e}"))
                })?;
                let shard: KeyShard = serde_json::from_str(&s).map_err(AppError::JsonError)?;
                loaded.push(shard);
            }
            decrypt_from_rest(&rest, &loaded, &sk, passphrase)?
        }
    };

    println!("{plaintext}");
    Ok(())
}

fn load_signed_shards_from_paths(paths: &[String]) -> Result<Vec<SignedKeyShard>> {
    let mut loaded = Vec::with_capacity(paths.len());
    for path in paths {
        let s = fs::read_to_string(path).map_err(|e| {
            AppError::InvalidInput(format!("cannot read shard file '{path}': {e}"))
        })?;
        let shard: SignedKeyShard = serde_json::from_str(&s).map_err(AppError::JsonError)?;
        loaded.push(shard);
    }
    Ok(loaded)
}

fn cmd_demo() -> Result<()> {
    println!("═══ ML-KEM 768 + AES-256-GCM + Shamir (configurable) Demo ═══\n");

    let (pk, sk) = kem::keygen();
    println!(
        "✔ Keypair generated (pk: {} bytes, sk: {} bytes)",
        pk.len(),
        sk.len()
    );

    let data = r#"{"name":"Alice","amount":100}"#;
    println!("  Plaintext : {data}");

    let (sign_pk, sign_sk) = sign::keygen();
    let demo_pass = "demo-passphrase";
    let signed = encrypt_data_signed(data, &pk, &sign_pk, &sign_sk, demo_pass)?;
    println!(
        "\n✔ Signed backup (shards: {}, threshold: {})",
        signed.shards.len(),
        signed.shards.first().map(|s| s.threshold).unwrap_or(0)
    );

    let subset = vec![signed.shards[0].clone(), signed.shards[2].clone()];
    for s in &subset {
        verify_signed_shard(s, &sk, &sign_pk)?;
    }
    let decrypted = decrypt_from_signed_shards(&subset, &sk, &sign_pk, demo_pass)?;
    println!("\n✔ Decrypted (using shards #1 and #3): {decrypted}");

    assert_eq!(data, decrypted, "roundtrip mismatch");
    println!("\n✔ Roundtrip verification passed.");
    Ok(())
}

// ─── Main ───────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Keygen => cmd_keygen(),
        Commands::Encrypt {
            pk,
            passphrase,
            data,
            output,
            shards_dir,
            threshold,
            total_shares,
        } => cmd_encrypt(
            &pk,
            &passphrase,
            data,
            output,
            shards_dir,
            threshold,
            total_shares,
        ),
        Commands::Decrypt {
            sk,
            passphrase,
            sign_pk,
            input,
            shards,
        } => cmd_decrypt(&sk, &passphrase, sign_pk.as_deref(), input, shards),
        Commands::Demo => cmd_demo(),
        Commands::BackupServer { port } => {
            if let Err(e) = server_backup::run_server(port).await {
                eprintln!("Backup server error: {e}");
                std::process::exit(1);
            }
            Ok(())
        }
        Commands::RecoveryServer { port } => {
            if let Err(e) = server_recovery::run_server(port).await {
                eprintln!("Recovery server error: {e}");
                std::process::exit(1);
            }
            Ok(())
        }
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

// ─── Integration Tests ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PASS: &str = "test-backup-passphrase";

    #[test]
    fn test_full_roundtrip() {
        let (pk, sk) = kem::keygen();
        let data = "Hello, post-quantum world! 🌍";
        let envelope = encrypt_data(data, &pk, TEST_PASS).expect("encrypt_data failed");
        let decrypted = decrypt_envelope(&envelope, &sk, TEST_PASS).expect("decrypt failed");
        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_roundtrip_large_payload() {
        let (pk, sk) = kem::keygen();
        let data = "A".repeat(100_000);
        let envelope = encrypt_data(&data, &pk, TEST_PASS).expect("encrypt_data failed");
        let decrypted = decrypt_envelope(&envelope, &sk, TEST_PASS).expect("decrypt failed");
        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_empty_data_rejected() {
        let (pk, _) = kem::keygen();
        let result = encrypt_data("", &pk, TEST_PASS);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_passphrase_rejected() {
        let (pk, _) = kem::keygen();
        let result = encrypt_data("x", &pk, "");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_passphrase_fails_decrypt() {
        let (pk, sk) = kem::keygen();
        let envelope = encrypt_data("secret", &pk, "pass-a").unwrap();
        let result = decrypt_envelope(&envelope, &sk, "pass-b");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let (pk1, _sk1) = kem::keygen();
        let (_pk2, sk2) = kem::keygen();
        let data = "secret message";
        let envelope = encrypt_data(data, &pk1, TEST_PASS).expect("encrypt_data failed");
        let result = decrypt_envelope(&envelope, &sk2, TEST_PASS);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (pk, sk) = kem::keygen();
        let mut envelope = encrypt_data("test", &pk, TEST_PASS).expect("encrypt_data failed");

        let mut ct_bytes = utils::b64d(&envelope.params.ciphertext).unwrap();
        ct_bytes[0] ^= 0xFF;
        envelope.params.ciphertext = utils::b64e(&ct_bytes);

        let result = decrypt_envelope(&envelope, &sk, TEST_PASS);
        assert!(result.is_err(), "tampered ciphertext must be rejected");
    }

    #[test]
    fn test_encrypt_produces_three_shards_default() {
        let (pk, _sk) = kem::keygen();
        let envelope = encrypt_data("hello", &pk, TEST_PASS).expect("encrypt_data failed");
        assert_eq!(envelope.shards.len(), sharding::DEFAULT_TOTAL_SHARES as usize);
        for (i, shard) in envelope.shards.iter().enumerate() {
            assert_eq!(shard.index, (i + 1) as u8);
            assert_eq!(shard.total, sharding::DEFAULT_TOTAL_SHARES);
            assert_eq!(shard.threshold, sharding::DEFAULT_THRESHOLD);
            assert!(!shard.data.is_empty());
        }
    }

    #[test]
    fn test_decrypt_with_any_two_of_three_shards() {
        let (pk, sk) = kem::keygen();
        let data = "two-of-three reconstruction";
        let envelope = encrypt_data(data, &pk, TEST_PASS).expect("encrypt_data failed");

        for (i, j) in [(0usize, 1usize), (0, 2), (1, 2)] {
            let subset = vec![envelope.shards[i].clone(), envelope.shards[j].clone()];
            let decrypted = decrypt_with_shards(&envelope.params, &subset, &sk, TEST_PASS)
                .expect("decrypt with 2 shards must succeed");
            assert_eq!(decrypted, data, "subset ({i},{j}) failed");
        }
    }

    #[test]
    fn test_decrypt_with_single_shard_fails() {
        let (pk, sk) = kem::keygen();
        let envelope = encrypt_data("one shard insufficient", &pk, TEST_PASS).expect("encrypt_data failed");
        let only_one = vec![envelope.shards[0].clone()];
        let result = decrypt_with_shards(&envelope.params, &only_one, &sk, TEST_PASS);
        assert!(result.is_err(), "1-of-3 must be rejected");
    }

    #[test]
    fn test_decrypt_with_tampered_shard_fails() {
        let (pk, sk) = kem::keygen();
        let mut envelope = encrypt_data("tamper test", &pk, TEST_PASS).expect("encrypt_data failed");

        let mut bytes = utils::b64d(&envelope.shards[0].data).unwrap();
        let last = bytes.len().saturating_sub(1);
        bytes[last] ^= 0xFF;
        envelope.shards[0].data = utils::b64e(&bytes);

        let subset = vec![envelope.shards[0].clone(), envelope.shards[1].clone()];
        let result = decrypt_with_shards(&envelope.params, &subset, &sk, TEST_PASS);
        assert!(result.is_err(), "tampered shard must cause auth failure");
    }

    #[test]
    fn test_signed_shard_roundtrip_subset() {
        let (pk, sk) = kem::keygen();
        let (sign_pk, sign_sk) = sign::keygen();
        let data = r#"{"k":"v"}"#;
        let art = encrypt_signed_backup_artifacts(
            data,
            &pk,
            &sign_sk,
            &sign_pk,
            TEST_PASS,
            3,
            5,
            Some("doc.json".into()),
        )
        .unwrap();
        let subset = vec![
            art.shards[0].clone(),
            art.shards[2].clone(),
            art.shards[4].clone(),
        ];
        let out = decrypt_from_signed_shards(&subset, &sk, &sign_pk, TEST_PASS).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn test_tampered_shard_signature_fails() {
        let (pk, sk) = kem::keygen();
        let (sign_pk, sign_sk) = sign::keygen();
        let mut art = encrypt_signed_backup_artifacts(
            "tamper",
            &pk,
            &sign_sk,
            &sign_pk,
            TEST_PASS,
            2,
            3,
            None,
        )
        .unwrap();
        art.shards[0].signature = utils::b64e(b"invalid-signature-padding");
        let subset = vec![art.shards[0].clone(), art.shards[1].clone()];
        let result = decrypt_from_signed_shards(&subset, &sk, &sign_pk, TEST_PASS);
        assert!(result.is_err());
    }
}
