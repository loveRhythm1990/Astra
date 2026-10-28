//! Real CLI process against synthetic UC/JWT/product endpoints. This does not
//! replace the separate real Keycloak and MOI deployment acceptance gate.
use astra_credentials::native::{Environment, NativeSession, NativeStore, unix_now};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use fs2::FileExt;
use rsa::{pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::process::Stdio;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use tokio::io::AsyncBufReadExt;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Clone, Copy, PartialEq)]
enum Scenario {
    Success,
    BadNonce,
    PrepareFailure,
    CancelPending,
    CancelLock,
    LockTimeout,
    DelayedHeaders,
    CancelHeaders,
    CancelWorkspaceLock,
}

async fn journey(scenario: Scenario) {
    static KEY: LazyLock<rsa::RsaPrivateKey> =
        LazyLock::new(|| rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap());
    let server = MockServer::start().await;
    let origin = server.uri();
    let issuer = format!("{origin}/realms/test");
    let environment = Environment {
        issuer: issuer.clone(),
        astra_url: origin.clone(),
        moi_url: origin.clone(),
        authorization_endpoint: format!("{origin}/authorize"),
        token_endpoint: format!("{issuer}/protocol/openid-connect/token"),
        revocation_endpoint: format!("{issuer}/protocol/openid-connect/revoke"),
        jwks_uri: format!("{issuer}/protocol/openid-connect/certs"),
    };
    let home = tempfile::tempdir().unwrap();
    let auth = home.path().join("auth");
    let store = NativeStore::with_directory(auth.clone());
    store.prepare_for_login().unwrap();
    store
        .publish(NativeSession {
            environment: environment.clone(),
            generation: String::new(),
            subject: "previous-user".into(),
            session_id: "old-session".into(),
            astra_user_id: "previous-astra".into(),
            moi_principal_id: "previous-moi".into(),
            catalog_user_id: "previous-catalog".into(),
            access_token: "old-access".into(),
            refresh_token: "old-refresh".into(),
            expires_at: unix_now().unwrap() + 3600,
            workspace_id: None,
            role_id: None,
            refresh_pending: false,
        })
        .unwrap();
    let before = std::fs::read(auth.join("auth.json")).unwrap();
    let form = Arc::new(Mutex::new(BTreeMap::<String, String>::new()));
    let revoked = Arc::new(Mutex::new(Vec::<String>::new()));
    let held_lock = Arc::new(Mutex::new(None::<std::fs::File>));
    let token_requested = Arc::new(tokio::sync::Notify::new());
    Mock::given(path("/auth/methods"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"uc": {
                "issuer": issuer, "client_id": "astra-cli", "moi_api_url": origin,
                "scope": "openid profile email astra:user aistudio:user", "resource": "astra-api"
            }})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(path("/realms/test/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": issuer, "authorization_endpoint": environment.authorization_endpoint,
            "token_endpoint": environment.token_endpoint, "revocation_endpoint": environment.revocation_endpoint,
            "jwks_uri": environment.jwks_uri,
            "device_authorization_endpoint": format!("{issuer}/protocol/openid-connect/auth/device")
        })))
        .expect(1).mount(&server).await;
    let request_form = form.clone();
    let grant_issuer = issuer.clone();
    Mock::given(method("POST"))
        .and(path("/realms/test/protocol/openid-connect/auth/device"))
        .respond_with(move |request: &wiremock::Request| {
            let parsed = url::form_urlencoded::parse(&request.body).into_owned().collect::<BTreeMap<_, _>>();
            assert_eq!(parsed["client_id"], "astra-cli");
            assert_eq!(parsed["code_challenge_method"], "S256");
            assert!(!parsed["nonce"].is_empty());
            *request_form.lock().unwrap() = parsed;
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "device_code": "synthetic-grant", "user_code": "ABCD-EFGH",
                "verification_uri": format!("{grant_issuer}/device"), "expires_in": if scenario == Scenario::DelayedHeaders { 3 } else { 900 }, "interval": 1
            }))
        }).expect(1).mount(&server).await;
    let token_form = form.clone();
    let token_issuer = issuer.clone();
    let requested = token_requested.clone();
    let der = KEY.to_pkcs1_der().unwrap();
    let encoding = jsonwebtoken::EncodingKey::from_rsa_der(der.as_bytes());
    Mock::given(method("POST"))
        .and(path("/realms/test/protocol/openid-connect/token"))
        .respond_with(move |request: &wiremock::Request| {
            let parsed = url::form_urlencoded::parse(&request.body).into_owned().collect::<BTreeMap<_, _>>();
            assert_eq!(parsed["device_code"], "synthetic-grant");
            assert_eq!(parsed["grant_type"], "urn:ietf:params:oauth:grant-type:device_code");
            let saved = token_form.lock().unwrap();
            assert_eq!(URL_SAFE_NO_PAD.encode(Sha256::digest(parsed["code_verifier"].as_bytes())), saved["code_challenge"]);
            requested.notify_one();
            if scenario == Scenario::CancelPending {
                return ResponseTemplate::new(400).set_body_json(serde_json::json!({"error": "authorization_pending"}));
            }
            let nonce = if scenario == Scenario::BadNonce { "wrong-nonce" } else { &saved["nonce"] };
            let now = unix_now().unwrap();
            let claims = serde_json::json!({"iss": token_issuer, "sub": "new-user", "aud": "astra-cli", "iat": now, "exp": now+300, "nonce": nonce});
            let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
            header.kid = Some("synthetic".into());
            let response = ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "new-access", "refresh_token": "new-refresh", "token_type": "Bearer", "expires_in": 300,
                "id_token": jsonwebtoken::encode(&header, &claims, &encoding).unwrap()
            }));
            if matches!(scenario, Scenario::DelayedHeaders | Scenario::CancelHeaders) {
                // Request consumed, but not even the 200 headers reach the CLI
                // until after the device deadline / SIGINT.
                response.set_delay(Duration::from_secs(4))
            } else {
                response
            }
        }).mount(&server).await;
    Mock::given(path("/realms/test/protocol/openid-connect/certs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"keys": [{
            "kty": "RSA", "alg": "RS256", "use": "sig", "kid": "synthetic",
            "n": URL_SAFE_NO_PAD.encode(KEY.n().to_bytes_be()), "e": URL_SAFE_NO_PAD.encode(KEY.e().to_bytes_be())
        }]}))).mount(&server).await;
    let moi_issuer = issuer.clone();
    let lock_for_bootstrap = held_lock.clone();
    let lock_path = auth.join("auth.lock");
    let workspace_lock_path = lock_path.clone();
    Mock::given(method("POST")).and(path("/auth/cli/bootstrap"))
        .and(header("authorization", "Bearer new-access"))
        .respond_with(move |_: &wiremock::Request| {
            if scenario == Scenario::PrepareFailure {
                return ResponseTemplate::new(503).set_body_json(serde_json::json!({"code":"unavailable", "msg":"Synthetic preparation failure"}));
            }
            if matches!(scenario, Scenario::CancelLock | Scenario::LockTimeout) {
                let lock = std::fs::OpenOptions::new().read(true).write(true).open(&lock_path).unwrap();
                FileExt::try_lock_exclusive(&lock).unwrap();
                *lock_for_bootstrap.lock().unwrap() = Some(lock);
            }
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"code":"OK", "data": {
                "issuer": moi_issuer, "subject":"new-user", "session_id":"new-session",
                "principal_id":"new-moi", "catalog_user_id":"new-catalog", "workspaces": if scenario == Scenario::CancelWorkspaceLock {
                    serde_json::json!([{"id":"test-workspace", "name":"Synthetic workspace", "status":"ACTIVE", "access_status":"accepted"}])
                } else { serde_json::json!([]) },
                "workspace_initialization":{"status":"pending"}
            }}))
        }).mount(&server).await;
    Mock::given(method("POST")).and(path("/auth/uc/bootstrap"))
        .and(header("authorization", "Bearer new-access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": issuer, "subject":"new-user", "session_id":"new-session", "user_id":"new-astra"
        }))).mount(&server).await;
    let revocations = revoked.clone();
    let workspace_lock = held_lock.clone();
    Mock::given(method("POST"))
        .and(path("/realms/test/protocol/openid-connect/revoke"))
        .respond_with(move |request: &wiremock::Request| {
            let parsed = url::form_urlencoded::parse(&request.body)
                .into_owned()
                .collect::<BTreeMap<_, _>>();
            if scenario == Scenario::CancelWorkspaceLock && parsed["token"] == "old-refresh" {
                // Old-session revocation is strictly after login publication.
                let lock = std::fs::OpenOptions::new().read(true).write(true).open(&workspace_lock_path).unwrap();
                FileExt::try_lock_exclusive(&lock).unwrap();
                *workspace_lock.lock().unwrap() = Some(lock);
            }
            revocations.lock().unwrap().push(parsed["token"].clone());
            ResponseTemplate::new(200)
        })
        .mount(&server)
        .await;

    let pty = (scenario == Scenario::CancelWorkspaceLock).then(|| {
        nix::pty::openpty(
            Some(&nix::pty::Winsize {
                ws_row: 30,
                ws_col: 120,
                ws_xpixel: 0,
                ws_ypixel: 0,
            }),
            None,
        )
        .unwrap()
    });
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_astra"));
    command
        .current_dir(home.path())
        .env_clear()
        .env("HOME", home.path())
        .env("MOI_AUTH_DIR", &auth)
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("XDG_CACHE_HOME", home.path().join(".cache"))
        .env("XDG_DATA_HOME", home.path().join(".local/share"))
        .env("TERM", "xterm-256color")
        .args(["--api-url", &origin, "login", "--device-code"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(pty) = &pty {
        command
            .stdin(Stdio::from(pty.slave.try_clone().unwrap()))
            .stdout(Stdio::from(pty.slave.try_clone().unwrap()))
            .stderr(Stdio::from(pty.slave.try_clone().unwrap()));
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let mut child = command.spawn().unwrap();
    drop(command);
    let pid = nix::unistd::Pid::from_raw(child.id().unwrap() as i32);
    let lock_waiting = Arc::new(tokio::sync::Notify::new());
    let waiting = lock_waiting.clone();
    let reader = if let Some(pty) = pty {
        drop(pty.slave);
        tokio::task::spawn_blocking(move || {
            use std::io::{Read, Write};
            let mut master = std::fs::File::from(pty.master);
            let mut bytes = Vec::new();
            let mut buffer = [0; 4096];
            let mut selected = false;
            let mut cursor_offset = 0;
            loop {
                match master.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => bytes.extend_from_slice(&buffer[..count]),
                    Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                    Err(error) => panic!("PTY read failed: {error}"),
                }
                // Answer terminal cursor queries, including split writes.
                while let Some(index) = bytes[cursor_offset..]
                    .windows(4)
                    .position(|v| v == b"\x1b[6n")
                {
                    cursor_offset += index + 4;
                    master.write_all(b"\x1b[1;1R").unwrap();
                }
                let output = String::from_utf8_lossy(&bytes);
                if !selected
                    && output.contains("Select a MOI workspace")
                    && output.contains("Synthetic workspace")
                {
                    selected = true;
                    master.write_all(b"\x1b[B\r").unwrap();
                }
                if output.contains("Waiting to save workspace selection") {
                    waiting.notify_one();
                }
            }
            String::from_utf8_lossy(&bytes).into_owned()
        })
    } else {
        let stderr = child.stderr.take().unwrap();
        tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(stderr).lines();
            let mut output = String::new();
            while let Some(line) = lines.next_line().await.unwrap() {
                if line.contains("Waiting to save sign-in credentials") {
                    waiting.notify_one();
                }
                output.push_str(&line);
                output.push('\n');
            }
            output
        })
    };
    if matches!(
        scenario,
        Scenario::CancelPending
            | Scenario::CancelLock
            | Scenario::CancelHeaders
            | Scenario::CancelWorkspaceLock
    ) {
        let ready = if matches!(scenario, Scenario::CancelPending | Scenario::CancelHeaders) {
            token_requested
        } else {
            lock_waiting
        };
        tokio::time::timeout(Duration::from_secs(15), ready.notified())
            .await
            .unwrap();
        nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGINT).unwrap();
    }
    let status = tokio::time::timeout(Duration::from_secs(20), child.wait())
        .await
        .expect("public login must exit even while the parent still holds auth.lock")
        .unwrap();
    let output = reader.await.unwrap();
    let settled_bytes = std::fs::read(auth.join("auth.json")).unwrap();
    drop(held_lock.lock().unwrap().take());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        std::fs::read(auth.join("auth.json")).unwrap(),
        settled_bytes,
        "no write after command exit"
    );
    assert!(!output.contains("new-refresh") && !output.contains("old-refresh"));
    let token_calls = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|request| request.url.path() == "/realms/test/protocol/openid-connect/token")
        .count();
    if matches!(scenario, Scenario::DelayedHeaders | Scenario::CancelHeaders) {
        assert_eq!(token_calls, 1, "an in-flight grant must not be replayed");
    }
    if matches!(
        scenario,
        Scenario::Success | Scenario::DelayedHeaders | Scenario::CancelWorkspaceLock
    ) {
        assert!(status.success(), "{output}");
        let current = store.current().unwrap();
        assert_eq!(current.subject, "new-user");
        assert_eq!(current.session_id, "new-session");
        assert_eq!(current.moi_principal_id, "new-moi");
        assert_eq!(*revoked.lock().unwrap(), vec!["old-refresh"]);
        if scenario == Scenario::CancelWorkspaceLock {
            assert_eq!(current.workspace_id, None);
            assert!(output.contains("Authentication is complete"), "{output}");
            assert!(output.contains("Workspace not selected"), "{output}");
        }
    } else {
        assert!(!status.success(), "{output}");
        assert_eq!(std::fs::read(auth.join("auth.json")).unwrap(), before);
        if scenario == Scenario::CancelPending {
            assert!(revoked.lock().unwrap().is_empty());
        } else {
            assert_eq!(*revoked.lock().unwrap(), vec!["new-refresh"]);
        }
        if scenario == Scenario::LockTimeout {
            assert!(output.contains("Timed out waiting to publish"));
        }
        if scenario == Scenario::CancelLock {
            assert!(
                output.contains("stopped before credential publication"),
                "{output}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_login_public_success_verifies_nonce_pkce_and_publishes() {
    journey(Scenario::Success).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_login_public_bad_nonce_preserves_previous_session() {
    journey(Scenario::BadNonce).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_login_public_prepare_failure_preserves_previous_session() {
    journey(Scenario::PrepareFailure).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_login_public_pending_can_be_interrupted() {
    journey(Scenario::CancelPending).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_login_public_lock_wait_can_be_interrupted_without_late_commit() {
    journey(Scenario::CancelLock).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_login_public_lock_wait_has_a_deadline() {
    journey(Scenario::LockTimeout).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_login_public_headers_after_deadline_still_settle_once() {
    journey(Scenario::DelayedHeaders).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_login_public_cancel_before_headers_revokes_new_token() {
    journey(Scenario::CancelHeaders).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_login_public_pty_workspace_lock_cancel_keeps_published_login() {
    journey(Scenario::CancelWorkspaceLock).await;
}
