//! Bounded, private refresh diagnostics. Never used to decide credential state.
use super::{NativeSession, NativeStore, private_open, unix_now};
use fs2::FileExt;
use serde::Serialize;
use std::{io::Write, time::Instant};

const MAX_BYTES: u64 = 64 * 1024;

pub(super) struct RotationDiagnostic {
    store: NativeStore,
    operation_id: String,
    environment: String,
    generation: String,
    started: Instant,
}

#[derive(Serialize)]
struct Event<'a> {
    component: &'static str,
    operation: &'static str,
    operation_id: &'a str,
    environment: &'a str,
    generation: &'a str,
    pid: u32,
    timestamp: i64,
    elapsed_ms: u128,
    stage: &'static str,
    reason: &'static str,
    http_status: Option<u16>,
    request_id: Option<&'a str>,
    cause: Option<&'a str>,
}

impl RotationDiagnostic {
    pub(super) fn new(store: &NativeStore, session: &NativeSession) -> Self {
        Self {
            store: store.clone(),
            operation_id: uuid::Uuid::new_v4().to_string(),
            environment: session.environment.key(),
            generation: session.generation.chars().take(128).collect(),
            started: Instant::now(),
        }
    }

    // Callers supply only local classifications/sanitized errors, never token
    // responses, headers other than the bounded request ID, or credentials.
    pub(super) async fn record(
        &self,
        stage: &'static str,
        reason: &'static str,
        http_status: Option<u16>,
        request_id: Option<&str>,
        cause: Option<&str>,
    ) {
        let cause = cause.map(|value| value.chars().take(1024).collect::<String>());
        let event = Event {
            component: "astra-credentials",
            operation: "token_refresh",
            operation_id: &self.operation_id,
            environment: &self.environment,
            generation: &self.generation,
            pid: std::process::id(),
            timestamp: unix_now().unwrap_or_default(),
            elapsed_ms: self.started.elapsed().as_millis(),
            stage,
            reason,
            http_status,
            request_id,
            cause: cause.as_deref(),
        };
        tracing::info!(component = event.component, operation = event.operation,
            operation_id = %event.operation_id, environment = %event.environment,
            generation = %event.generation, pid = event.pid, stage, reason,
            elapsed_ms = %event.elapsed_ms, http_status, request_id, cause = event.cause,
            "native sign-in refresh");
        let Ok(mut line) = serde_json::to_vec(&event) else {
            return;
        };
        line.push(b'\n');
        // Logging is best effort: inability to record diagnostics must not
        // prevent settlement. File I/O stays off the async runtime, and a busy
        // diagnostic writer never delays authentication on a separate lock.
        if let Err(error) = self
            .store
            .blocking(move |store| {
                store.check_dir()?;
                let mut file = private_open(&store.root.join("auth-refresh.jsonl"), true)?;
                match FileExt::try_lock_exclusive(&file) {
                    Ok(()) => (),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                    Err(_) => return Err("cannot lock sign-in diagnostic file".into()),
                }
                if file
                    .metadata()
                    .map_err(|_| "cannot inspect sign-in diagnostics")?
                    .len()
                    + line.len() as u64
                    > MAX_BYTES
                {
                    file.set_len(0)
                        .map_err(|_| "cannot truncate sign-in diagnostics")?;
                }
                use std::io::{Seek, SeekFrom};
                file.seek(SeekFrom::End(0))
                    .map_err(|_| "cannot seek sign-in diagnostics")?;
                file.write_all(&line)
                    .map_err(|_| "cannot write sign-in diagnostics".into())
            })
            .await
        {
            tracing::warn!(component = "astra-credentials", operation = "token_refresh",
                stage = "diagnostics", reason = "diagnostic_write_failed", %error,
                "could not record sign-in diagnostics");
        }
    }
}

pub(super) fn response_request_id(response: &reqwest::Response) -> Option<String> {
    response
        .headers()
        .get("x-request-id")?
        .to_str()
        .ok()
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
        })
        .map(str::to_owned)
}

pub(super) fn transport_cause(error: reqwest::Error) -> String {
    use std::error::Error;
    let error = error.without_url();
    let mut cause = error.to_string();
    let mut source = error.source();
    while let Some(next) = source {
        if cause.len() >= 1024 {
            break;
        }
        cause.push_str(": ");
        cause.extend(next.to_string().chars().take(1024));
        source = next.source();
    }
    cause
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, symlink};

    #[tokio::test]
    async fn default_diagnostics_are_private_bounded_and_do_not_serialize_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let store = NativeStore::with_directory(directory.path().join("auth"));
        store.prepare_for_login().unwrap();
        let diagnostic = RotationDiagnostic {
            store: store.clone(),
            operation_id: "test-operation".into(),
            environment: "environment-digest".into(),
            generation: "generation".into(),
            started: Instant::now(),
        };
        let path = store.root.join("auth-refresh.jsonl");
        let mut file = private_open(&path, true).unwrap();
        file.write_all(&vec![b' '; MAX_BYTES as usize]).unwrap();
        diagnostic
            .record("http", "http_rejected", Some(400), Some("request-1"), None)
            .await;
        let contents = std::fs::read(&path).unwrap();
        let event: serde_json::Value = serde_json::from_slice(&contents).unwrap();
        assert_eq!(event["http_status"], 400);
        assert_eq!(event["request_id"], "request-1");
        assert_eq!(event["reason"], "http_rejected");
        assert!(contents.len() < MAX_BYTES as usize);
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert!(event.get("access_token").is_none());
        assert!(event.get("refresh_token").is_none());

        std::fs::remove_file(&path).unwrap();
        let target = directory.path().join("untouched");
        std::fs::write(&target, "unchanged").unwrap();
        symlink(&target, &path).unwrap();
        diagnostic
            .record("http", "http_rejected", Some(400), None, None)
            .await;
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "unchanged");
    }
}
