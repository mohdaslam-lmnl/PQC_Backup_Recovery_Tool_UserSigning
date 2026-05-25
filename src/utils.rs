use base64::{engine::general_purpose, Engine as _};
use crate::errors::{AppError, Result};

/// Encode bytes to base64 string.
pub fn b64e(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

/// Decode a base64 string to bytes. Returns an error on malformed input.
pub fn b64d(data: &str) -> Result<Vec<u8>> {
    general_purpose::STANDARD
        .decode(data)
        .map_err(AppError::Base64DecodeFailed)
}