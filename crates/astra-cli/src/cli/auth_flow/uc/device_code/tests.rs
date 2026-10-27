use super::*;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn environment(server: &MockServer) -> Environment {
    let issuer = format!("{}/realms/test", server.uri());
    Environment {
        issuer: issuer.clone(),
        astra_url: server.uri(),
        moi_url: server.uri(),
        authorization_endpoint: format!("{}/authorize", server.uri()),
        token_endpoint: format!("{issuer}/protocol/openid-connect/token"),
        revocation_endpoint: format!("{issuer}/protocol/openid-connect/revoke"),
        jwks_uri: format!("{issuer}/protocol/openid-connect/certs"),
    }
}

fn grant(issuer: &str) -> DeviceAuthorization {
    DeviceAuthorization {
        device_code: "memory-only-grant".into(),
        user_code: "ABCD-EFGH".into(),
        verification_uri: format!("{issuer}/device"),
        expires_in: 600,
        interval: 1,
    }
}

#[test]
fn device_endpoints_cannot_change_origin_or_escape_the_fixed_protocol() {
    let issuer = "https://uc.example.test/api/v1/uc/realms/moi";
    assert!(issuer_endpoint(&format!("{issuer}/device"), issuer, "/device").is_ok());
    for target in [
        "https://other.example.test/api/v1/uc/realms/moi/device",
        "http://uc.example.test/api/v1/uc/realms/moi/device",
        "https://uc.example.test/api/v1/uc/realms/other/device",
        "https://uc.example.test/api/v1/uc/realms/moi/device?user_code=automatic",
        "https://uc.example.test/api/v1/uc/realms/moi/device#fragment",
        "https://user:password@uc.example.test/api/v1/uc/realms/moi/device",
    ] {
        assert!(issuer_endpoint(target, issuer, "/device").is_err());
    }
}

#[test]
fn invalid_device_codes_and_unbounded_lifetimes_are_rejected() {
    let issuer = "https://uc.example.test/realms/moi";
    assert!(grant(issuer).validate(issuer).is_ok());
    for lifetime in [0, 601, u64::MAX] {
        let mut value = grant(issuer);
        value.expires_in = lifetime;
        assert!(value.validate(issuer).is_err());
    }
    for code in ["", "short", "ABCD\nEFGH", "\u{1b}[31mABCD", "https://other.example"] {
        let mut value = grant(issuer);
        value.user_code = code.into();
        assert!(value.validate(issuer).is_err());
    }
    let mut value = grant(issuer);
    value.device_code = "x".repeat(4097);
    assert!(value.validate(issuer).is_err());
    value = grant(issuer);
    value.interval = 0;
    assert!(value.validate(issuer).is_err());
}

#[test]
fn missing_poll_interval_uses_the_rfc_default() {
    let value: DeviceAuthorization = serde_json::from_value(serde_json::json!({
        "device_code": "not-persisted", "user_code": "ABCD-EFGH",
        "verification_uri": "https://uc.example.test/realms/moi/device", "expires_in": 600
    }))
    .unwrap();
    assert_eq!(value.interval, 5);
}

#[test]
fn slowdown_is_permanent_and_connection_backoff_is_bounded() {
    let mut policy = PollPolicy::new(5);
    policy.slow_down();
    assert_eq!(policy.interval, Duration::from_secs(10));
    policy.pending();
    assert_eq!(policy.delay, Duration::from_secs(10));
    policy.unavailable(Some(30));
    assert_eq!(policy.delay, Duration::from_secs(30));
    policy.unavailable(None);
    assert_eq!(policy.delay, Duration::from_secs(60));
    policy.unavailable(Some(u64::MAX));
    assert_eq!(policy.delay, Duration::from_secs(600));
    policy.pending();
    assert_eq!(policy.delay, Duration::from_secs(10));
}

#[tokio::test]
async fn expiry_stops_before_another_poll_request() {
    let server = MockServer::start().await;
    let environment = environment(&server);
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let result = poll(
        &native::http_client().unwrap(),
        &environment,
        &grant(&environment.issuer),
        "private-verifier",
        Instant::now() + Duration::from_millis(20),
    )
    .await;
    assert!(matches!(result, Err(error) if error == EXPIRED));
}

#[tokio::test]
async fn denial_does_not_expose_upstream_text_or_retry() {
    let server = MockServer::start().await;
    let environment = environment(&server);
    Mock::given(method("POST"))
        .and(path("/realms/test/protocol/openid-connect/token"))
        .and(body_string_contains("device_code=memory-only-grant"))
        .and(body_string_contains("code_verifier=private-verifier"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "access_denied", "error_description": "DO_NOT_RENDER_THIS"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let result = poll(
        &native::http_client().unwrap(),
        &environment,
        &grant(&environment.issuer),
        "private-verifier",
        Instant::now() + Duration::from_secs(10),
    )
    .await;
    assert!(matches!(result, Err(error) if error.contains("denied") && !error.contains("DO_NOT_RENDER")));
}

#[tokio::test]
async fn a_successful_but_invalid_token_body_is_not_replayed() {
    let server = MockServer::start().await;
    let environment = environment(&server);
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not JSON"))
        .expect(1)
        .mount(&server)
        .await;
    let result = poll(
        &native::http_client().unwrap(),
        &environment,
        &grant(&environment.issuer),
        "private-verifier",
        Instant::now() + Duration::from_secs(10),
    )
    .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn pending_then_success_submits_the_same_grant_and_verifier() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let server = MockServer::start().await;
    let environment = environment(&server);
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    Mock::given(method("POST"))
        .and(body_string_contains("device_code=memory-only-grant"))
        .and(body_string_contains("code_verifier=private-verifier"))
        .respond_with(move |_: &wiremock::Request| {
            if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(400).set_body_json(serde_json::json!({
                    "error": "authorization_pending"
                }))
            } else {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "test-access", "refresh_token": "test-refresh",
                    "expires_in": 300, "token_type": "Bearer", "id_token": "test-id"
                }))
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    let tokens = poll(
        &native::http_client().unwrap(),
        &environment,
        &grant(&environment.issuer),
        "private-verifier",
        Instant::now() + Duration::from_secs(15),
    )
    .await
    .unwrap();
    assert_eq!(tokens.access_token, "test-access");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn optional_device_metadata_does_not_break_existing_browser_discovery() {
    for extra in [None, Some(serde_json::json!(false)), Some(serde_json::json!("https://other.example.test/device"))] {
        let server = MockServer::start().await;
        let environment = environment(&server);
        let discovery = UcDiscovery {
            issuer: environment.issuer.clone(),
            client_id: "astra-cli".into(),
            moi_api_url: server.uri(),
            scope: "openid profile email astra:user aistudio:user".into(),
            resource: "astra-api".into(),
        };
        let mut metadata = serde_json::json!({
            "issuer": environment.issuer,
            "authorization_endpoint": environment.authorization_endpoint,
            "token_endpoint": environment.token_endpoint,
            "revocation_endpoint": environment.revocation_endpoint,
            "jwks_uri": environment.jwks_uri,
        });
        if let Some(extra) = extra {
            metadata["device_authorization_endpoint"] = extra;
        }
        Mock::given(path("/realms/test/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
            .expect(1)
            .mount(&server)
            .await;
        let api = astra_thin_client::ThinClient::new(&server.uri(), None).unwrap();
        let (_, _, device) = super::super::discover_environment(&api, &discovery).await.unwrap();
        assert!(device.is_none_or(|value| value.as_str().is_none_or(|value| {
            issuer_endpoint(value, &discovery.issuer, "/protocol/openid-connect/auth/device").is_err()
        })));
    }
}
