//! Website-mediated browser approval. Only the CLI retrieves the credential;
//! browsers never connect to a local HTTP listener on this path.
use super::{do_memoria_login_with_key, open_login_url, validate_login_website};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::Duration;

#[derive(Deserialize)]
struct Started {
    login_ticket: String,
    expires_in: u64,
    interval: u64,
}

#[derive(Deserialize)]
struct Polled {
    status: String,
    connection_key: Option<String>,
}

async fn body<T: serde::de::DeserializeOwned>(
    mut response: reqwest::Response,
) -> Result<T, String> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Login response could not be read; run astra login again")?
    {
        if bytes.len() + chunk.len() > 8192 {
            return Err("Login response is too large".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| "Invalid website login response".into())
}

fn verifier() -> String {
    let mut bytes = [0_u8; 32];
    bytes[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    URL_SAFE_NO_PAD.encode(bytes)
}

fn login_url(website: &str, started: &Started) -> Result<String, String> {
    // Do not open arbitrary verification URLs supplied by a response. Keep the
    // existing discovered website as the authority and construct a fixed path.
    validate_login_website(website)?;
    if started.login_ticket.len() > 2048
        || started.login_ticket.is_empty()
        || !started
            .login_ticket
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        || !(1..=300).contains(&started.expires_in)
        || !(1..=10).contains(&started.interval)
    {
        return Err("Invalid website login configuration".into());
    }
    let mut url = url::Url::parse(&format!("{}/connect/astra", website.trim_end_matches('/')))
        .map_err(|_| "Invalid website login URL")?;
    url.query_pairs_mut()
        .append_pair("request", &started.login_ticket)
        .append_pair("cli_version", env!("CARGO_PKG_VERSION"));
    Ok(url.into())
}

pub(super) async fn try_login(
    api: &astra_thin_client::ThinClient,
    profile: Option<&str>,
    website: &str,
) -> Result<Option<String>, String> {
    let (started, client, secret) = match start(website).await? {
        Some(value) => value,
        None => return Ok(None),
    };
    let url = login_url(website, &started)?;
    eprintln!("Open this page to connect Astra:\n{url}");
    open_login_url(&url);
    let key = wait_for_approval(&client, website, &started, &secret).await?;
    // Preserve canonical issuer binding, memory permissions and local storage.
    Ok(Some(do_memoria_login_with_key(api, profile, &key).await?))
}

async fn start(website: &str) -> Result<Option<(Started, reqwest::Client, String)>, String> {
    validate_login_website(website)?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| "Could not initialize website login")?;
    let secret = verifier();
    let response = client
        .post(format!(
            "{}/api/auth/astra/device-login/start",
            website.trim_end_matches('/')
        ))
        .json(&json!({"code_challenge":URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()))}))
        .send()
        .await
        .map_err(|_| "Could not contact the login website; check your connection and retry")?;
    // Only an absent endpoint enables old-server compatibility. Never downgrade
    // on a redirect, rejected request, bad payload, or transport/server failure.
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Err(format!(
            "Website login is unavailable (HTTP {})",
            response.status().as_u16()
        ));
    }
    let started: Started = body(response).await?;
    login_url(website, &started)?;
    Ok(Some((started, client, secret)))
}

async fn wait_for_approval(
    client: &reqwest::Client,
    website: &str,
    started: &Started,
    secret: &str,
) -> Result<String, String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(started.expires_in);
    loop {
        let response = tokio::time::timeout_at(deadline, async {
            let response = client.post(format!("{}/api/auth/astra/device-login/poll", website.trim_end_matches('/')))
                .json(&json!({"login_ticket":started.login_ticket,"code_verifier":secret}))
                .send().await.map_err(|_| "Login result could not be retrieved; run astra login again")?;
            if !response.status().is_success() {
                return Err(format!("Login approval is unavailable, expired or already used (HTTP {}); run astra login again", response.status().as_u16()));
            }
            body::<Polled>(response).await
        }).await.map_err(|_| "Browser login timed out; run astra login again")??;
        match (response.status.as_str(), response.connection_key) {
            ("approved", Some(key)) if !key.is_empty() && key.len() <= 4096 => return Ok(key),
            ("pending", None) => {}
            _ => return Err("Invalid website login response; run astra login again".into()),
        }
        if tokio::time::timeout_at(
            deadline,
            tokio::time::sleep(Duration::from_secs(started.interval)),
        )
        .await
        .is_err()
        {
            return Err("Browser login timed out; run astra login again".into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    fn configuration() -> serde_json::Value {
        json!({"login_ticket":"header.payload.signature", "user_code":"ABCD-EFGH", "expires_in":300, "interval":1})
    }

    #[test]
    fn verification_url_stays_on_discovered_website_and_never_contains_verifier() {
        let started: Started = serde_json::from_value(configuration()).unwrap();
        let secret = verifier();
        assert_eq!(URL_SAFE_NO_PAD.decode(&secret).unwrap().len(), 32);
        assert_ne!(secret, verifier());
        let url = login_url("https://example.com", &started).unwrap();
        let url = url::Url::parse(&url).unwrap();
        assert_eq!(url.origin().ascii_serialization(), "https://example.com");
        assert_eq!(url.path(), "/connect/astra");
        assert!(!url.as_str().contains(&secret));
        assert!(!url.as_str().contains("code_verifier"));
        let mut invalid = configuration();
        invalid["login_ticket"] = json!("https://evil.invalid/\n");
        assert!(
            login_url(
                "https://example.com",
                &serde_json::from_value(invalid).unwrap()
            )
            .is_err()
        );
        let mut without_code = configuration();
        without_code.as_object_mut().unwrap().remove("user_code");
        assert!(
            login_url(
                "https://example.com",
                &serde_json::from_value(without_code).unwrap()
            )
            .is_ok()
        );
        for (field, value) in [
            ("expires_in", 0),
            ("expires_in", 301),
            ("interval", 0),
            ("interval", 11),
        ] {
            let mut invalid = configuration();
            invalid[field] = json!(value);
            assert!(
                login_url(
                    "https://example.com",
                    &serde_json::from_value(invalid).unwrap()
                )
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn start_sends_only_challenge_and_only_404_allows_legacy_callback() {
        for status in [200, 404, 401, 429, 500, 302] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/api/auth/astra/device-login/start"))
                .respond_with(
                    ResponseTemplate::new(status)
                        .set_body_json(configuration())
                        .insert_header("Location", format!("{}/must-not-follow", server.uri())),
                )
                .expect(1)
                .mount(&server)
                .await;
            let result = start(&server.uri()).await;
            match status {
                404 => assert!(result.unwrap().is_none()),
                200 => {
                    let (_, _, secret) = result.unwrap().unwrap();
                    let requests = server.received_requests().await.unwrap();
                    assert_eq!(
                        requests[0].body_json::<serde_json::Value>().unwrap(),
                        json!({"code_challenge": URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()))})
                    );
                }
                _ => assert!(result.is_err()),
            }
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn malformed_start_does_not_fall_back() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not JSON"))
            .mount(&server)
            .await;
        assert!(start(&server.uri()).await.is_err());
    }

    #[tokio::test]
    async fn poll_repeats_only_pending_and_returns_key_only_to_cli() {
        let server = MockServer::start().await;
        let count = Arc::new(AtomicUsize::new(0));
        let counter = count.clone();
        Mock::given(method("POST"))
            .and(path("/api/auth/astra/device-login/poll"))
            .respond_with(move |_: &wiremock::Request| {
                let value = if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                    json!({"status":"pending"})
                } else {
                    json!({"status":"approved","connection_key":"test-only-key"})
                };
                ResponseTemplate::new(200).set_body_json(value)
            })
            .mount(&server)
            .await;
        let started: Started = serde_json::from_value(configuration()).unwrap();
        let secret = verifier();
        let key = wait_for_approval(&reqwest::Client::new(), &server.uri(), &started, &secret)
            .await
            .unwrap();
        assert_eq!(key, "test-only-key");
        assert_eq!(count.load(Ordering::SeqCst), 2);
        for request in server.received_requests().await.unwrap() {
            assert_eq!(
                request.body_json::<serde_json::Value>().unwrap(),
                json!({"login_ticket":started.login_ticket,"code_verifier":secret})
            );
            assert!(!request.url.as_str().contains(&secret));
        }
    }

    #[tokio::test]
    async fn poll_rejects_errors_or_ambiguous_responses_without_replay() {
        for (status, payload) in [
            (409, json!({"error":"used"})),
            (502, json!({})),
            (200, json!({"status":"approved"})),
            (
                200,
                json!({"status":"pending","connection_key":"unexpected"}),
            ),
            (200, json!({"status":"approved","connection_key":""})),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(status).set_body_json(payload))
                .expect(1)
                .mount(&server)
                .await;
            let started = serde_json::from_value(configuration()).unwrap();
            assert!(
                wait_for_approval(
                    &reqwest::Client::new(),
                    &server.uri(),
                    &started,
                    &verifier()
                )
                .await
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn pending_login_is_bounded_by_expiry() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status":"pending"})))
            .expect(1)
            .mount(&server)
            .await;
        let mut started: Started = serde_json::from_value(configuration()).unwrap();
        started.expires_in = 1;
        started.interval = 2;
        let error = wait_for_approval(
            &reqwest::Client::new(),
            &server.uri(),
            &started,
            &verifier(),
        )
        .await
        .unwrap_err();
        assert!(error.contains("timed out"));
    }
}
