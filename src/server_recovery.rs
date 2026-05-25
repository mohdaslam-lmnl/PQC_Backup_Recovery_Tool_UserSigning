use actix_cors::Cors;
use actix_files as afs;
use actix_web::{middleware::DefaultHeaders, web, App, HttpResponse, HttpServer};
use serde::Deserialize;

use crate::{decrypt_from_signed_shards, verify_signed_shard, utils, SignedKeyShard};

#[derive(Deserialize)]
struct VerifyShardRequest {
    secret_key_b64: String,
    signing_public_key_b64: String,
    shard: SignedKeyShard,
}

#[derive(Deserialize)]
struct RecoveryDecryptRequest {
    secret_key_b64: String,
    signing_public_key_b64: String,
    #[serde(default)]
    passphrase: Option<String>,
    shards: Vec<SignedKeyShard>,
}

async fn api_verify_shard(body: web::Json<VerifyShardRequest>) -> HttpResponse {
    let sk = match utils::b64d(body.secret_key_b64.trim()) {
        Ok(b) => b,
        Err(e) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "valid": false,
                "error": format!("Invalid secret key (base64): {}", e)
            }));
        }
    };
    let sign_pk = match utils::b64d(body.signing_public_key_b64.trim()) {
        Ok(b) => b,
        Err(e) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "valid": false,
                "error": format!("Invalid signing public key (base64): {}", e)
            }));
        }
    };

    match verify_signed_shard(&body.shard, &sk, &sign_pk) {
        Ok(()) => {
            let threshold = body.shard.threshold;
            let total = body.shard.total;
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "valid": true,
                "threshold": threshold,
                "total_shards": total,
                "message": format!(
                    "Shard {} verified. This backup is {threshold}-of-{total}; upload at least {threshold} distinct shard files to decrypt.",
                    body.shard.index
                ),
            }))
        }
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "valid": false,
            "error": format!("{}", e),
        })),
    }
}

async fn api_decrypt(body: web::Json<RecoveryDecryptRequest>) -> HttpResponse {
    let passphrase = match body
        .passphrase
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    {
        Some(p) => p,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Passphrase is required. Refresh the recovery page and enter the same backup passphrase in step 4."
            }));
        }
    };

    let sk = match utils::b64d(body.secret_key_b64.trim()) {
        Ok(b) => b,
        Err(e) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": format!("Invalid secret key (base64): {}", e)
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

    let original_filename = body.shards.first().and_then(|s| s.original_filename.clone());

    match decrypt_from_signed_shards(&body.shards, &sk, &sign_pk, passphrase) {
        Ok(plaintext) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "plaintext": plaintext,
            "original_filename": original_filename,
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
    eprintln!("EncVault recovery tool — http://localhost:{}", port);
    eprintln!("  Serves static files from ./static_recovery");

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
            .route("/api/verify-shard", web::post().to(api_verify_shard))
            .route("/api/decrypt", web::post().to(api_decrypt))
            .service(
                afs::Files::new("/", "./static_recovery")
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

    use crate::{encrypt_signed_backup_artifacts, kem, sign, utils};

    #[actix_web::test]
    async fn decrypt_preserves_exact_passphrase_bytes() {
        let passphrase = "  padded passphrase  ";
        let plaintext = r#"{"ok":true}"#;
        let (pk, sk) = kem::keygen();
        let (sign_pk, sign_sk) = sign::keygen();
        let artifacts = encrypt_signed_backup_artifacts(
            plaintext,
            &pk,
            &sign_sk,
            &sign_pk,
            passphrase,
            2,
            3,
            Some("backup.json".into()),
        )
        .expect("encrypt artifacts");

        let app = test::init_service(
            App::new()
                .app_data(json_config())
                .route("/api/decrypt", web::post().to(api_decrypt)),
        )
        .await;

        let good_req = test::TestRequest::post()
            .uri("/api/decrypt")
            .set_json(json!({
                "secret_key_b64": utils::b64e(&sk),
                "signing_public_key_b64": utils::b64e(&sign_pk),
                "passphrase": passphrase,
                "shards": artifacts.shards[..2].to_vec(),
            }))
            .to_request();

        let good_resp = test::call_service(&app, good_req).await;
        assert_eq!(good_resp.status(), StatusCode::OK);
        let good_body: serde_json::Value = test::read_body_json(good_resp).await;
        assert_eq!(good_body["success"], true);
        assert_eq!(good_body["plaintext"], plaintext);

        let trimmed_req = test::TestRequest::post()
            .uri("/api/decrypt")
            .set_json(json!({
                "secret_key_b64": utils::b64e(&sk),
                "signing_public_key_b64": utils::b64e(&sign_pk),
                "passphrase": passphrase.trim(),
                "shards": artifacts.shards[..2].to_vec(),
            }))
            .to_request();

        let trimmed_resp = test::call_service(&app, trimmed_req).await;
        assert_eq!(trimmed_resp.status(), StatusCode::BAD_REQUEST);
    }

    #[actix_web::test]
    async fn decrypt_rejects_blank_passphrase() {
        let (pk, sk) = kem::keygen();
        let (sign_pk, sign_sk) = sign::keygen();
        let artifacts = encrypt_signed_backup_artifacts(
            r#"{"ok":true}"#,
            &pk,
            &sign_sk,
            &sign_pk,
            "valid-passphrase",
            2,
            3,
            Some("backup.json".into()),
        )
        .expect("encrypt artifacts");

        let app = test::init_service(
            App::new()
                .app_data(json_config())
                .route("/api/decrypt", web::post().to(api_decrypt)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/decrypt")
            .set_json(json!({
                "secret_key_b64": utils::b64e(&sk),
                "signing_public_key_b64": utils::b64e(&sign_pk),
                "passphrase": "   ",
                "shards": artifacts.shards[..2].to_vec(),
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
