use astra_credentials::native::{self, Environment, NativeStore, TokenResponse};
use astra_services::auth::uc::UcDiscovery;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::time::Instant;

const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const EXPIRED: &str = "Device sign-in expired. Run `astra login --device-code` to start again.";

// Deliberately not Debug: the grant secret must never be rendered or logged.
#[derive(Deserialize)]
struct DeviceAuthorization {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    #[serde(default = "default_interval")]
    interval: u64,
}

fn default_interval() -> u64 {
    5
}

fn issuer_endpoint(value: &str, issuer: &str, suffix: &str) -> Result<reqwest::Url, String> {
    let target = native::secure_url(value)?;
    let issuer = native::secure_url(issuer)?;
    if target.origin() != issuer.origin()
        || target.path() != format!("{}{suffix}", issuer.path().trim_end_matches('/'))
        || target.query().is_some()
        || target.fragment().is_some()
    {
        return Err("Invalid UC device sign-in endpoint".into());
    }
    Ok(target)
}

impl DeviceAuthorization {
    fn validate(&self, issuer: &str) -> Result<(), String> {
        issuer_endpoint(&self.verification_uri, issuer, "/device")?;
        if self.device_code.is_empty()
            || self.device_code.len() > 4096
            || !(6..=64).contains(&self.user_code.len())
            || !self
                .user_code
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || self.expires_in == 0
            || self.expires_in > 600
            || self.interval == 0
            || self.interval > self.expires_in
        {
            return Err("Invalid UC device authorization response".into());
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct OAuthError {
    error: String,
}

struct PollPolicy {
    interval: Duration,
    delay: Duration,
}

impl PollPolicy {
    fn new(interval: u64) -> Self {
        let interval = Duration::from_secs(interval);
        Self {
            interval,
            delay: interval,
        }
    }

    fn pending(&mut self) {
        self.delay = self.interval;
    }

    fn slow_down(&mut self) {
        self.interval = self.interval.saturating_add(Duration::from_secs(5));
        self.delay = self.interval;
    }

    fn unavailable(&mut self, retry_after: Option<u64>) {
        self.delay = self.delay.saturating_mul(2).min(Duration::from_secs(60));
        self.delay = self.delay.max(self.interval);
        if let Some(retry_after) = retry_after {
            self.delay = self.delay.max(Duration::from_secs(retry_after.min(600)));
        }
    }
}

async fn poll(
    client: &reqwest::Client,
    environment: &Environment,
    grant: &DeviceAuthorization,
    verifier: &str,
    deadline: Instant,
) -> Result<TokenResponse, String> {
    let mut policy = PollPolicy::new(grant.interval);
    loop {
        let wake = Instant::now() + policy.delay;
        if wake >= deadline {
            tokio::time::sleep_until(deadline).await;
            return Err(EXPIRED.into());
        }
        tokio::time::sleep_until(wake).await;
        let response = tokio::time::timeout_at(
            deadline,
            client
                .post(&environment.token_endpoint)
                .form(&[
                    ("grant_type", DEVICE_GRANT),
                    ("client_id", "astra-cli"),
                    ("device_code", grant.device_code.as_str()),
                    ("code_verifier", verifier),
                ])
                .send(),
        )
        .await
        .map_err(|_| EXPIRED.to_string())?;
        let response = match response {
            Ok(response) => response,
            Err(_) => {
                // The server might have consumed the grant before the response
                // was lost. A later invalid_grant is terminal, never a claim
                // that this machine has signed in or the previous session died.
                policy.unavailable(None);
                continue;
            }
        };
        let status = response.status();
        if status.is_success() {
            // A 2xx may have consumed the grant. Do not replay it after an
            // interrupted/invalid token body or a product bootstrap failure.
            return tokio::time::timeout_at(deadline, native::bounded_json(response))
                .await
                .map_err(|_| EXPIRED.to_string())?;
        }
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse().ok());
            policy.unavailable(retry_after);
            continue;
        }
        let error: OAuthError = tokio::time::timeout_at(deadline, native::bounded_json(response))
            .await
            .map_err(|_| EXPIRED.to_string())??;
        match error.error.as_str() {
            "authorization_pending" => policy.pending(),
            "slow_down" => policy.slow_down(),
            "temporarily_unavailable" => policy.unavailable(None),
            "access_denied" => {
                return Err("Device sign-in was denied. No local session was changed.".into());
            }
            "expired_token" => return Err(EXPIRED.into()),
            _ => {
                return Err(
                    "UC rejected device sign-in. Start again; no local session was changed.".into(),
                );
            }
        }
    }
}

pub(crate) async fn login_device_code(
    api: &astra_thin_client::ThinClient,
    discovery: UcDiscovery,
) -> Result<(), String> {
    let store = NativeStore::new()?;
    store.prepare_for_login()?;
    let (client, environment, endpoint) = super::discover_environment(api, &discovery).await?;
    let endpoint = issuer_endpoint(
        endpoint
            .as_ref()
            .ok_or("Device code sign-in is not enabled on this MOI deployment")?
            .as_str()
            .ok_or("Invalid UC device sign-in discovery")?,
        &environment.issuer,
        "/protocol/openid-connect/auth/device",
    )?;
    let nonce = super::super::browser_code::verifier();
    let verifier = super::super::browser_code::verifier();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let started = Instant::now();
    let wait = async {
        let response = client
            .post(endpoint)
            .form(&[
                ("client_id", "astra-cli"),
                ("scope", discovery.scope.as_str()),
                ("nonce", nonce.as_str()),
                ("code_challenge", challenge.as_str()),
                ("code_challenge_method", "S256"),
            ])
            .send()
            .await
            .map_err(|_| "UC device authorization is unavailable; no local session was changed")?;
        if !response.status().is_success() {
            return Err("UC device authorization was rejected; no local session was changed".into());
        }
        let grant: DeviceAuthorization = native::bounded_json(response).await?;
        grant.validate(&environment.issuer)?;
        eprintln!(
            "Open this page in a browser on another device:\n{}\n\nEnter this code: {}\nCheck the account and permissions, then approve or deny access.\nWaiting for authorization (up to {} seconds). Press Ctrl+C to stop.",
            grant.verification_uri, grant.user_code, grant.expires_in
        );
        poll(
            &client,
            &environment,
            &grant,
            &verifier,
            started + Duration::from_secs(grant.expires_in),
        )
        .await
    };
    let tokens = tokio::select! {
        result = wait => result?,
        signal = tokio::signal::ctrl_c() => {
            signal.map_err(|_| "Could not observe sign-in cancellation")?;
            return Err("Device sign-in stopped. No local session was changed; the pending request will expire.".into());
        }
    };
    // Once credentials have arrived, settle the bounded product bootstrap and
    // publication rather than cancelling across a possible local commit.
    eprintln!("Authorization approved. Completing sign-in...");
    let prepared = tokio::time::timeout(
        Duration::from_secs(60),
        super::prepare(&client, &environment, &tokens, &nonce),
    )
    .await
    .map_err(|_| "UC product sign-in timed out".to_string())
    .and_then(|result| result);
    let (session, bootstrap) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            if !tokens.refresh_token.is_empty() {
                let _ = tokio::time::timeout(
                    Duration::from_secs(2),
                    native::revoke(&environment, &tokens.refresh_token),
                )
                .await;
            }
            return Err(error);
        }
    };
    let (session, bootstrap) = super::publish_prepared_login(&store, session, bootstrap).await?;
    if let Err(error) = super::choose_workspace(&store, &session, bootstrap, None) {
        eprintln!("Workspace not selected: {error}. Use `astra auth workspace` later.");
    }
    Ok(())
}

#[cfg(test)]
mod tests;
