//! Persistable, configuration-bound thinking observations. Never probe during
//! model resolution or inference; only explicit model checks perform I/O.
use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ThinkingProbeSnapshot {
    revision: u32,
    identity: String,
    protocol: ThinkingProtocol,
    capability: Option<ThinkingCapability>,
    error: Option<String>,
    observed_at: String,
    #[serde(default)]
    legacy_hint: bool,
}

impl ThinkingProbeSnapshot {
    pub(super) fn result(
        &self,
        identity: &str,
        protocol: ThinkingProtocol,
    ) -> Option<ThinkingProbeResult> {
        (self.revision == ThinkingProtocol::REVISION
            && self.identity == identity
            && self.protocol == protocol)
            .then(|| ThinkingProbeResult {
                capability: self.capability.unwrap_or(ThinkingCapability::None),
                error: self.error.clone(),
            })
    }
    pub(super) fn new(
        identity: String,
        protocol: ThinkingProtocol,
        result: &ThinkingProbeResult,
    ) -> Self {
        Self {
            revision: ThinkingProtocol::REVISION,
            identity,
            protocol,
            capability: result.error.is_none().then_some(result.capability),
            error: result.error.clone(),
            observed_at: chrono::Utc::now().to_rfc3339(),
            legacy_hint: false,
        }
    }

    /// An inconclusive check is not a negative capability observation. Keep
    /// prior knowledge only for exactly the same configuration and protocol.
    pub(super) fn with_previous(
        mut self,
        raw: Option<&str>,
        legacy: Option<ThinkingCapability>,
    ) -> Self {
        // A baseline observation cannot disprove previously known controls.
        if self.error.is_some()
            || (self.protocol == ThinkingProtocol::Unknown
                && self.capability == Some(ThinkingCapability::NativeOnly))
        {
            if let Some(raw) = raw {
                if let Ok(previous) = serde_json::from_str::<Self>(raw)
                    && let Some(capability) = previous.capability(&self.identity, self.protocol)
                {
                    self.capability = Some(capability);
                    self.legacy_hint = previous.legacy_hint;
                }
            } else if let Some(legacy) = legacy {
                self.capability = Some(legacy);
                self.legacy_hint = true;
            }
        }
        self
    }

    pub(super) fn persisted_capability(&self) -> Option<ThinkingCapability> {
        self.capability
    }

    pub(super) fn capability(
        &self,
        identity: &str,
        protocol: ThinkingProtocol,
    ) -> Option<ThinkingCapability> {
        (self.revision == ThinkingProtocol::REVISION
            && self.identity == identity
            && self.protocol == protocol)
            .then_some(self.capability)
            .flatten()
    }
}

/// Hash configuration, not plaintext credentials. Ciphertext generation binds
/// the observation to credential rotation without persisting a key-derived hash.
pub(super) fn probe_identity(
    provider: &str,
    endpoint: &str,
    model: &str,
    encrypted: &str,
    config: &str,
) -> String {
    let serialized = serde_json::to_vec(&(provider, endpoint, model, encrypted, config))
        .expect("string tuple serializes");
    format!("{:x}", Sha256::digest(serialized))
}

pub(super) fn cached_capability(
    raw: Option<&str>,
    identity: &str,
    protocol: ThinkingProtocol,
) -> Option<ThinkingCapability> {
    raw.and_then(|raw| serde_json::from_str::<ThinkingProbeSnapshot>(raw).ok())
        .and_then(|snapshot| snapshot.capability(identity, protocol))
}

/// Binary controls require two-sided observation. Native/effort protocols
/// establish reasoning only, never suppression. An accepted but ignored toggle
/// is not `Both`; absent observable reasoning remains inconclusive.
pub(super) async fn probe_chat_protocol(
    client: &reqwest::Client,
    provider: &str,
    model: &str,
    url: &str,
    key: &str,
    protocol: ThinkingProtocol,
) -> ThinkingProbeResult {
    let unknown = |message: &str| ThinkingProbeResult {
        capability: ThinkingCapability::None,
        error: Some(message.to_string()),
    };
    let mut enabled = serde_json::json!({
        "model": model,
        "messages": [{"role": "user", "content": "Calculate 17 * 23. Reply with the result."}]
    });
    astra_core::model_wire::apply_chat_output_token_limit(&mut enabled, provider, 1024);
    protocol.apply(
        &mut enabled,
        true,
        (protocol == ThinkingProtocol::ReasoningEffort).then_some("low"),
    );
    match send_openai_probe(
        client,
        url,
        key,
        &enabled,
        protocol == ThinkingProtocol::ReasoningEffort,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            return unknown("No observable reasoning in enabled mode; capability remains unknown");
        }
        Err(error) => return unknown(&error),
    }
    if !protocol.can_disable() {
        return ThinkingProbeResult {
            capability: if protocol == ThinkingProtocol::ReasoningEffort {
                ThinkingCapability::EffortOnly
            } else {
                // Observed native reasoning, but no evidence of a toggle.
                ThinkingCapability::NativeOnly
            },
            error: None,
        };
    }
    let mut disabled = enabled;
    protocol.apply(&mut disabled, false, None);
    match send_openai_probe(client, url, key, &disabled, false).await {
        Ok(false) => ThinkingProbeResult {
            capability: ThinkingCapability::Both,
            error: None,
        },
        Ok(true) => unknown(
            "Reasoning remained visible with suppression requested; capability remains unknown",
        ),
        Err(error) => unknown(&error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn strict_toggle_probe_uses_shared_protocol_and_rejects_ignored_controls() {
        use axum::{Json, Router, routing::post};
        use serde_json::json;
        let app = Router::new().route(
            "/chat/completions",
            post(|Json(body): Json<Value>| async move {
                assert!(body.get("temperature").is_none());
                assert!(body.get("enable_thinking").is_none());
                assert_eq!(body["max_completion_tokens"], 1024);
                let mut message = json!({"content":"391"});
                if body["thinking"]["type"] == "enabled" || body["model"] == "ignores-control" {
                    message["reasoning_content"] = json!("multiplication");
                }
                Json(json!({"choices":[{"message":message,"finish_reason":"stop"}]}))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/chat/completions", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let result = probe_chat_protocol(
            &client,
            "openai-compatible",
            "m",
            &url,
            "fixture",
            ThinkingProtocol::Moonshot,
        )
        .await;
        assert_eq!(result.capability, ThinkingCapability::Both);
        assert!(result.error.is_none());
        let result = probe_chat_protocol(
            &client,
            "openai-compatible",
            "ignores-control",
            &url,
            "fixture",
            ThinkingProtocol::Moonshot,
        )
        .await;
        assert!(result.error.is_some());
        server.abort();
    }

    #[tokio::test]
    async fn native_and_effort_probes_do_not_guess_binary_controls() {
        use axum::{Json, Router, routing::post};
        let app = Router::new().route("/chat/completions", post(|Json(body): Json<Value>| async move {
            assert!(body.get("thinking").is_none());
            assert!(body.get("enable_thinking").is_none());
            let mut response = serde_json::json!({"choices":[{"finish_reason":"stop","message":{"content":"391"}}]});
            if body["model"] == "native" {
                assert!(body.get("reasoning_effort").is_none());
                response["choices"][0]["message"]["reasoning_content"] = serde_json::json!("multiply");
            } else if body["model"] == "effort" {
                assert_eq!(body["reasoning_effort"], "low");
                response["usage"] = serde_json::json!({"completion_tokens_details":{"reasoning_tokens":12}});
            }
            Json(response)
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/chat/completions", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        for (model, protocol, expected) in [
            (
                "native",
                ThinkingProtocol::Unknown,
                Some(ThinkingCapability::NativeOnly),
            ),
            (
                "effort",
                ThinkingProtocol::ReasoningEffort,
                Some(ThinkingCapability::EffortOnly),
            ),
            ("inconclusive", ThinkingProtocol::Unknown, None),
        ] {
            let result =
                probe_chat_protocol(&client, "openai", model, &url, "fixture", protocol).await;
            assert_eq!(
                result.error.is_none().then_some(result.capability),
                expected
            );
        }
        server.abort();
    }

    #[test]
    fn inconclusive_probe_preserves_only_matching_knowledge() {
        let protocol = ThinkingProtocol::ThinkingObject;
        let success = ThinkingProbeResult {
            capability: ThinkingCapability::Both,
            error: None,
        };
        let failure = ThinkingProbeResult {
            capability: ThinkingCapability::None,
            error: Some("inconclusive".into()),
        };
        let old = ThinkingProbeSnapshot::new("identity".into(), protocol, &success);
        let raw = serde_json::to_string(&old).unwrap();
        let retained = ThinkingProbeSnapshot::new("identity".into(), protocol, &failure)
            .with_previous(Some(&raw), None);
        assert_eq!(
            retained.capability("identity", protocol),
            Some(ThinkingCapability::Both)
        );
        assert!(
            retained
                .result("identity", protocol)
                .unwrap()
                .error
                .is_some()
        );
        for changed in ["rotated-key", "changed-model"] {
            let invalid = ThinkingProbeSnapshot::new(changed.into(), protocol, &failure)
                .with_previous(Some(&raw), Some(ThinkingCapability::Both));
            assert_eq!(invalid.capability(changed, protocol), None);
        }
        let legacy = ThinkingProbeSnapshot::new("identity".into(), protocol, &failure)
            .with_previous(None, Some(ThinkingCapability::NativeOnly));
        assert!(legacy.legacy_hint);
        assert_eq!(
            legacy.persisted_capability(),
            Some(ThinkingCapability::NativeOnly)
        );
        let malformed = ThinkingProbeSnapshot::new("identity".into(), protocol, &failure)
            .with_previous(Some("invalid"), Some(ThinkingCapability::Both));
        assert_eq!(malformed.persisted_capability(), None);
        let native = ThinkingProbeResult {
            capability: ThinkingCapability::NativeOnly,
            error: None,
        };
        let baseline =
            ThinkingProbeSnapshot::new("identity".into(), ThinkingProtocol::Unknown, &native)
                .with_previous(None, Some(ThinkingCapability::Both));
        assert_eq!(
            baseline.persisted_capability(),
            Some(ThinkingCapability::Both)
        );
        assert!(
            baseline.legacy_hint,
            "baseline must not claim it verified a toggle"
        );
    }

    #[tokio::test]
    async fn invalid_output_and_error_bodies_cannot_become_capabilities_or_leak_secrets() {
        use axum::{Json, Router, routing::post};
        let app = Router::new().route("/chat/completions", post(|Json(body): Json<Value>| async move {
            if body["model"] == "error" {
                return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"fixture-secret"})));
            }
            (StatusCode::OK, Json(serde_json::json!({"choices":[{"finish_reason":"length", "message":{"content":"", "reasoning_content":"thinking"}}]})))
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/chat/completions", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        for model in ["error", "truncated"] {
            let result = probe_chat_protocol(
                &client,
                "openai-compatible",
                model,
                &url,
                "fixture-secret",
                ThinkingProtocol::Moonshot,
            )
            .await;
            assert!(result.error.is_some());
            assert!(!format!("{result:?}").contains("fixture-secret"));
        }
        server.abort();
    }

    #[tokio::test]
    #[ignore = "requires a real paid provider credential in ASTRA_TEST_SUMMARY_CONFIG_FILE"]
    async fn live_thinking_protocol_probe() {
        let path = std::env::var("ASTRA_TEST_SUMMARY_CONFIG_FILE").expect("provider config path");
        let config = std::fs::read_to_string(path).expect("read config");
        let lines: Vec<_> = config
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        assert!(lines.len() >= 3);
        let fields = &lines[lines.len() - 3..];
        let model =
            std::env::var("ASTRA_TEST_SUMMARY_MODEL").unwrap_or_else(|_| fields[2].to_string());
        let protocol = match std::env::var("ASTRA_TEST_THINKING_PROTOCOL") {
            Ok(s) => serde_json::from_value(Value::String(s)).expect("protocol"),
            Err(_) => canonical_thinking_protocol(
                crate::byok_endpoint::COMPATIBLE_PROVIDER,
                fields[0],
                &model,
            ),
        };
        let result = probe_thinking_behavior_with_protocol(
            crate::byok_endpoint::COMPATIBLE_PROVIDER,
            &model,
            fields[1],
            Some(fields[0]),
            Some(protocol),
        )
        .await;
        eprintln!(
            "thinking_probe verified_toggle={}",
            result.error.is_none() && result.capability == ThinkingCapability::Both
        );
        assert!(
            result.error.is_none(),
            "probe failed (upstream details suppressed)"
        );
        assert_eq!(result.capability, ThinkingCapability::Both);
    }

    #[test]
    fn snapshot_reuse_is_bound_to_exact_configuration_and_revision() {
        let identity = probe_identity(
            "openai-compatible",
            "https://provider.test/v1",
            "m",
            "ciphertext-v1",
            "{}",
        );
        let result = ThinkingProbeResult {
            capability: ThinkingCapability::Both,
            error: None,
        };
        let snapshot =
            ThinkingProbeSnapshot::new(identity.clone(), ThinkingProtocol::ThinkingObject, &result);
        let raw = serde_json::to_string(&snapshot).unwrap();
        assert_eq!(
            cached_capability(Some(&raw), &identity, ThinkingProtocol::ThinkingObject),
            Some(ThinkingCapability::Both)
        );
        for changed in [
            probe_identity(
                "openai",
                "https://provider.test/v1",
                "m",
                "ciphertext-v1",
                "{}",
            ),
            probe_identity(
                "openai-compatible",
                "https://other.test/v1",
                "m",
                "ciphertext-v1",
                "{}",
            ),
            probe_identity(
                "openai-compatible",
                "https://provider.test/v1",
                "n",
                "ciphertext-v1",
                "{}",
            ),
            probe_identity(
                "openai-compatible",
                "https://provider.test/v1",
                "m",
                "ciphertext-v2",
                "{}",
            ),
            probe_identity(
                "openai-compatible",
                "https://provider.test/v1",
                "m",
                "ciphertext-v1",
                "{\"changed\":true}",
            ),
        ] {
            assert_eq!(
                cached_capability(Some(&raw), &changed, ThinkingProtocol::ThinkingObject),
                None
            );
        }
        assert_eq!(
            cached_capability(Some(&raw), &identity, ThinkingProtocol::Moonshot),
            None
        );
        assert_eq!(
            cached_capability(None, &identity, ThinkingProtocol::ThinkingObject),
            None
        );
        let mut stale = snapshot.clone();
        stale.revision += 1;
        assert_eq!(
            stale.capability(&identity, ThinkingProtocol::ThinkingObject),
            None
        );
        let failed = ThinkingProbeSnapshot::new(
            identity.clone(),
            ThinkingProtocol::ThinkingObject,
            &ThinkingProbeResult {
                capability: ThinkingCapability::Both,
                error: Some("failed".into()),
            },
        );
        assert_eq!(
            failed.capability(&identity, ThinkingProtocol::ThinkingObject),
            None
        );
    }
}
