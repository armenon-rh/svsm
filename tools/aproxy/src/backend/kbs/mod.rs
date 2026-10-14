// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

use super::*;
use anyhow::Context;
use base64::{
    Engine,
    prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD},
};
use kbs_types::*;
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::Value;

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub mod sample;
pub mod trustee;

pub use sample::SampleKbs;
pub use trustee::TrusteeKbs;

const KBS_API_VERSION: &str = "0.4.0";

pub trait KbsBackend: std::fmt::Debug + Clone + Copy + Send + Sync {
    fn hash_algo(&self) -> HashAlgo;
    fn payload_format(&self) -> PayloadFormat;
    fn get_primary_evidence(
        &self,
        evidence: &AttestationEvidence,
    ) -> anyhow::Result<serde_json::Value>;
}

/// Background worker that periodically refreshes the active session lease on KBS
/// and releases it cleanly on termination.
#[derive(Debug)]
pub struct LeaseRefresher {
    running: Arc<AtomicBool>,
    handle: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl LeaseRefresher {
    pub fn start(
        client: reqwest::blocking::Client,
        url: String,
        resource_id: String,
        session_id: String,
        token: String,
    ) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        let handle = std::thread::spawn(move || {
            let heartbeat_url = format!("{url}/kbs/v0/svsm/heartbeat");
            let release_url = format!("{url}/kbs/v0/svsm/release-lease");
            let payload = serde_json::json!({
                "resource_id": resource_id,
                "session_id": session_id,
            });

            while r.load(Ordering::Relaxed) {
                // Sleep for 25 seconds in 100ms intervals to respond promptly to shutdown
                for _ in 0..250 {
                    if !r.load(Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }

                if !r.load(Ordering::Relaxed) {
                    break;
                }

                log::debug!("Sending lease heartbeat for {resource_id}");
                let _ = client
                    .post(&heartbeat_url)
                    .header("Authorization", format!("Bearer {token}"))
                    .json(&payload)
                    .send();
            }

            log::info!("Releasing session lease for {resource_id}");
            let _ = client
                .post(&release_url)
                .header("Authorization", format!("Bearer {token}"))
                .json(&payload)
                .send();
        });

        Self {
            running,
            handle: std::sync::Mutex::new(Some(handle)),
        }
    }
}

impl Drop for LeaseRefresher {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Ok(mut lock) = self.handle.lock() {
            if let Some(h) = lock.take() {
                let _ = h.join();
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct KbsProtocol<B: KbsBackend> {
    backend: B,
    cached_token: Option<String>,
    lease_refresher: Option<Arc<LeaseRefresher>>,
}

impl<B: KbsBackend> KbsProtocol<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            cached_token: None,
            lease_refresher: None,
        }
    }
}

#[derive(Deserialize, Debug)]
struct TokenResponse {
    pub token: String,
}

impl<B: KbsBackend> AttestationProtocol for KbsProtocol<B> {
    /// KBS servers usually want two components hashed into attestation evidence: the public
    /// components of the TEE key, and a nonce provided in the KBS challenge that is fetched
    /// from the server's /auth endpoint. These must be hased in order.
    ///
    /// Make this request to /auth, gather the nonce, and return this in the negotiation
    /// parameter for SVSM to hash these components in the attestation evidence.
    fn negotiation(
        &mut self,
        http: &mut HttpClient,
        request: NegotiationRequest,
    ) -> anyhow::Result<NegotiationResponse> {
        if request.version != (0, 2, 0) {
            return Err(anyhow::anyhow!("invalid request version"));
        }
        let req = Request {
            version: KBS_API_VERSION.to_string(),
            tee: request.tee,
            extra_params: Value::String("".to_string()), // unused.
        };

        // Fetch challenge containing a nonce from the KBS /auth endpoint.
        let http_resp = http
            .cli
            .post(format!("{}/kbs/v0/auth", http.url))
            .json(&req)
            .send()
            .context("unable to POST to KBS /auth endpoint")?;

        let text = http_resp
            .text()
            .context("unable to convert KBS /auth response to text")?;

        let challenge: Challenge =
            serde_json::from_str(&text).context("unable to convert KBS /auth response to JSON")?;

        let hash_algo = self.backend.hash_algo();
        let payload_format = self.backend.payload_format();

        let resp = NegotiationResponse {
            challenge: BASE64_STANDARD
                .decode(challenge.nonce)
                .context("unable to decode challenge nonce from base64")?,
            hash_algo,
            payload_format,
        };

        Ok(resp)
    }

    /// With the serialized TEE evidence and key, complete the attestation. Serialize the evidence
    /// and send it to the /attest endpoint of the KBS server. Upon a successful attestation, fetch
    /// a secret (identified as "svsm_secret"). If able to successfully fetch the secret, return a
    /// successful AttestationResponse with the secret included.
    fn attestation(
        &mut self,
        http: &mut HttpClient,
        request: AttestationRequest,
    ) -> anyhow::Result<AttestationResponse> {
        let primary_evidence = self.backend.get_primary_evidence(&request.evidence)?;

        // Create a KBS attestation object from the TEE evidence and key.
        let tee_pubkey: kbs_types::TeePubKey = request.key.into();
        let runtime_data_value = if let (Some(nonce), Some(counter)) =
            (request.disk_nonce.as_ref(), request.boot_counter)
        {
            serde_json::json!({
                "version": 1,
                "nonce": BASE64_STANDARD.encode(&request.challenge),
                "tee-pubkey": tee_pubkey,
                "boot_counter": counter,
                "disk_nonce": hex::encode(nonce)
            })
        } else {
            serde_json::json!({
                "nonce": BASE64_STANDARD.encode(&request.challenge),
                "tee-pubkey": tee_pubkey
            })
        };

        let attestation = serde_json::json!({
            "tee_evidence": {
                "primary_evidence": primary_evidence,
                "additional_evidence": ""
            },
            "runtime_data": runtime_data_value
        });

        // Attest TEE evidence at KBS /attest endpoint.
        let http_resp = http
            .cli
            .post(format!("{}/kbs/v0/attest", http.url))
            .json(&attestation)
            .send()
            .context("unable to POST to KBS /attest endpoint")?;

        if http_resp.status() != StatusCode::OK {
            log::warn!("KBS /attest returned {}", http_resp.status());
            return Ok(AttestationResponse {
                success: false,
                secret: None,
                decryption: None,
                token: None,
            });
        }

        // Get the attestation token from the response.
        let token_resp: TokenResponse = serde_json::from_str(
            &http_resp
                .text()
                .context("unable to convert /attest response to text")?,
        )
        .context("unable to convert /attest response to JSON object")?;

        self.cached_token = Some(token_resp.token.clone());

        // Successful attestation. Fetch the secret specified by resource_id (or default).
        let resource_path = request
            .resource_id
            .as_deref()
            .unwrap_or("default/sample/test");

        let http_resp = http
            .cli
            .get(format!("{}/kbs/v0/resource/{}", http.url, resource_path))
            .header("Authorization", format!("Bearer {}", token_resp.token))
            .send()
            .context("unable to GET KBS /resource endpoint")?;

        // Unsuccessful attempt at retrieving secret.
        if http_resp.status() != StatusCode::OK {
            log::warn!("KBS /resource returned {}", http_resp.status());
            return Ok(AttestationResponse {
                success: false,
                secret: None,
                decryption: None,
                token: None,
            });
        }

        let session_id = http_resp
            .headers()
            .get("X-SVSM-Session-ID")
            .and_then(|h| h.to_str().ok())
            .map(String::from);

        if let Some(ref sid) = session_id {
            log::info!("Acquired active session lease '{sid}' for '{resource_path}'");
            let refresher = LeaseRefresher::start(
                http.cli.clone(),
                http.url.clone(),
                resource_path.to_string(),
                sid.clone(),
                token_resp.token.clone(),
            );
            self.lease_refresher = Some(Arc::new(refresher));
        }

        let text = http_resp
            .text()
            .context("unable to read KBS /resource response")?;

        let resp: Response = serde_json::from_str(&text)
            .context("unable to convert KBS /resource response to KBS Response object")?;

        let epk = unwrap_epk(&resp)?;
        let aad = resp
            .protected
            .generate_aad()
            .context("unable to generate AAD")?;

        Ok(AttestationResponse {
            success: true,
            secret: Some(resp.ciphertext),
            decryption: Some(AesGcmData {
                epk,
                wrapped_cek: resp.encrypted_key,
                aad,
                iv: resp.iv,
                tag: resp.tag,
            }),
            token: Some(AttestationToken::Jwt(token_resp.token)),
        })
    }

    fn roll_nonce(
        &mut self,
        http: &mut HttpClient,
        req: RollNonceRequest,
    ) -> anyhow::Result<RollNonceResponse> {
        let Some(token) = &self.cached_token else {
            return Ok(RollNonceResponse {
                success: false,
                error_msg: Some("No cached attestation token found for roll_nonce".into()),
            });
        };

        let roll_url = format!("{}/kbs/v0/svsm/roll-nonce", http.url);
        let payload = serde_json::json!({
            "version": req.version,
            "resource_id": req.resource_id,
            "new_boot_counter": req.new_boot_counter,
            "new_nonce": hex::encode(&req.new_nonce),
        });

        let resp = http
            .cli
            .post(&roll_url)
            .header("Authorization", format!("Bearer {token}"))
            .json(&payload)
            .send()
            .context("unable to POST to /kbs/v0/svsm/roll-nonce")?;

        if resp.status().is_success() {
            log::info!("Successfully rolled anti-replay nonce on KBS");
            Ok(RollNonceResponse {
                success: true,
                error_msg: None,
            })
        } else {
            let status = resp.status();
            let err_body = resp.text().unwrap_or_default();
            log::warn!("KBS /svsm/roll-nonce failed: {status} - {err_body}");
            Ok(RollNonceResponse {
                success: false,
                error_msg: Some(format!("KBS returned status {status}: {err_body}")),
            })
        }
    }
}

fn unwrap_epk(resp: &Response) -> anyhow::Result<EcP256PublicKey> {
    let epk = resp
        .protected
        .other_fields
        .get("epk")
        .context("epk not found")?;

    let _crv = epk
        .get("crv")
        .context("EC crv value not found")?
        .as_str()
        .context("unable to convert EC crv value to string")?;

    let x = BASE64_URL_SAFE_NO_PAD
        .decode(
            epk.get("x")
                .context("EC x value not found")?
                .as_str()
                .context("unable to convert EC x value to string")?,
        )
        .context("unable to decode EC x value from base64")?;

    let y = BASE64_URL_SAFE_NO_PAD
        .decode(
            epk.get("y")
                .context("EC y value not found")?
                .as_str()
                .context("unable to convert EC y value to string")?,
        )
        .context("unable to decode EC y value from base64")?;

    Ok(EcP256PublicKey { x, y })
}
