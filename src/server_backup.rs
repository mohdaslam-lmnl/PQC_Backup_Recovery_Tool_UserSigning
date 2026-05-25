use actix_cors::Cors;
use actix_files as afs;
use actix_web::{middleware::DefaultHeaders, web, App, HttpResponse, HttpServer};
use serde::Deserialize;

use crate::{encrypt_signed_backup_artifacts, sign, utils};

#[derive(Deserialize)]
struct BackupEncryptRequest {
    /// Base64-encoded ML-KEM 768 public key (encapsulation key).
    public_key_b64: String,
    /// Base64-encoded Dilithium3 signing secret key (from `/api/signing-keygen`).
    signing_secret_key_b64: String,
    /// Base64-encoded Dilithium3 signing public key (same keygen response).
    signing_public_key_b64: String,
    /// JSON file body as a string (will be encrypted).
    plaintext: String,
    /// User passphrase combined with the random DEK to derive the file encryption key.
    #[serde(default)]
    passphrase: Option<String>,
    threshold: u8,
    total_shards: u8,
    #[serde(default)]
    original_filename: Option<String>,
}

async fn api_signing_keygen() -> HttpResponse {
    let (sign_pk, sign_sk) = sign::keygen();
    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "signing_public_key_b64": utils::b64e(&sign_pk),
        "signing_secret_key_b64": utils::b64e(&sign_sk),
    }))
}

async fn api_encrypt(body: web::Json<BackupEncryptRequest>) -> HttpResponse {
    let passphrase = match body
        .passphrase
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    {
        Some(p) => p,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Passphrase is required. Refresh the backup page and enter the backup passphrase in step 3."
            }));
        }
    };

    let pk = match utils::b64d(body.public_key_b64.trim()) {
        Ok(b) => b,
        Err(e) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": format!("Invalid public key (base64): {}", e)
            }));
        }
    };

    let sign_sk = match utils::b64d(body.signing_secret_key_b64.trim()) {
        Ok(b) => b,
        Err(e) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": format!("Invalid signing secret key (base64): {}", e)
            }));
        }
    };

    let sign_pk = match utils::b64d(body.signing_public_key_b64.trim()) {
        Ok(b) => b,
        Err(e) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": format!("Invalid signing public key (base64): {}", e)
            }));
        }
    };

    match encrypt_signed_backup_artifacts(
        &body.plaintext,
        &pk,
        &sign_sk,
        &sign_pk,
        passphrase,
        body.threshold,
        body.total_shards,
        body.original_filename.clone(),
    ) {
        Ok(artifacts) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "signing_public_key_b64": artifacts.signing_public_key_b64,
            "shards": artifacts.shards,
        })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": format!("{}", e)
        })),
    }
}

fn json_config() -> web::JsonConfig {
    web::JsonConfig::default()
        .limit(32 * 1024 * 1024)
        .error_handler(|err, _req| {
            let response = HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": format!("JSON deserialization failed: {}", err),
            }));
            actix_web::error::InternalError::from_response(err, response).into()
        })
}

pub async fn run_server(port: u16) -> std::io::Result<()> {
    eprintln!("EncVault backup tool — http://localhost:{}", port);
    eprintln!("  Serves static files from ./static_backup");

    HttpServer::new(|| {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .wrap(
                DefaultHeaders::new()
                    .add(("Cache-Control", "no-store, no-cache, must-revalidate"))
                    .add(("Pragma", "no-cache")),
            )
            .wrap(cors)
            .app_data(json_config())
            .route("/api/signing-keygen", web::post().to(api_signing_keygen))
            .route("/api/encrypt", web::post().to(api_encrypt))
            .service(
                afs::Files::new("/", "./static_backup")
                    .index_file("index.html")
                    .prefer_utf8(true),
            )
    })
    .bind(format!("0.0.0.0:{}", port))?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http::StatusCode, test, App};
    use serde_json::json;

    use crate::{decrypt_from_signed_shards, kem, utils, SignedKeyShard};

    #[actix_web::test]
    async fn encrypt_preserves_exact_passphrase_bytes() {
        let passphrase = "  padded passphrase  ";
        let plaintext = r#"{"ok":true}"#;
        let (pk, sk) = kem::keygen();
        let (sign_pk, sign_sk) = sign::keygen();

        let app = test::init_service(
            App::new()
                .app_data(json_config())
                .route("/api/encrypt", web::post().to(api_encrypt)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/encrypt")
            .set_json(json!({
                "public_key_b64": utils::b64e(&pk),
                "signing_secret_key_b64": utils::b64e(&sign_sk),
                "signing_public_key_b64": utils::b64e(&sign_pk),
                "plaintext": plaintext,
                "passphrase": passphrase,
                "threshold": 2,
                "total_shards": 3,
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value = test::read_body_json(resp).await;
        let shards: Vec<SignedKeyShard> =
            serde_json::from_value(body["shards"].clone()).expect("valid shard response");

        let decrypted = decrypt_from_signed_shards(&shards[..2], &sk, &sign_pk, passphrase)
            .expect("decrypt with exact passphrase");
        assert_eq!(decrypted, plaintext);

        assert!(
            decrypt_from_signed_shards(&shards[..2], &sk, &sign_pk, passphrase.trim()).is_err(),
            "trimmed passphrase must not decrypt data encrypted with surrounding spaces"
        );
    }

    #[actix_web::test]
    async fn encrypt_rejects_blank_passphrase() {
        let (pk, _) = kem::keygen();
        let (sign_pk, sign_sk) = sign::keygen();

        let app = test::init_service(
            App::new()
                .app_data(json_config())
                .route("/api/encrypt", web::post().to(api_encrypt)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/encrypt")
            .set_json(json!({
                "public_key_b64": utils::b64e(&pk),
                "signing_secret_key_b64": utils::b64e(&sign_sk),
                "signing_public_key_b64": utils::b64e(&sign_pk),
                "plaintext": r#"{"ok":true}"#,
                "passphrase": "   ",
                "threshold": 2,
                "total_shards": 3,
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
