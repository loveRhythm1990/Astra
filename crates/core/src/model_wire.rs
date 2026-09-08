//! Shared wire rules for chat inference and credential/connectivity probes.
//! Keep this below services/runtime so probes cannot invent a second contract.
use serde_json::{Value, json};

/// Apply a caller-bounded output budget to Anthropic Messages or OpenAI-style
/// chat completions. Bedrock Converse has a separate inferenceConfig shape.
/// Thinking-budget policy belongs to the caller, not this serialization helper.
pub fn apply_chat_output_token_limit(body: &mut Value, provider: &str, tokens: usize) {
    let (field, obsolete) = if provider == "anthropic" {
        ("max_tokens", "max_completion_tokens")
    } else {
        ("max_completion_tokens", "max_tokens")
    };
    if let Some(object) = body.as_object_mut() {
        object.remove(obsolete);
        object.insert(field.into(), json!(tokens));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_limit_uses_the_protocol_not_the_model_name() {
        for provider in ["openai", "openai-compatible", "deepseek", "anthropic"] {
            let mut body = json!({"model":"o3", "max_tokens":1, "max_completion_tokens":2});
            apply_chat_output_token_limit(&mut body, provider, 32);
            let (field, absent) = if provider == "anthropic" {
                ("max_tokens", "max_completion_tokens")
            } else {
                ("max_completion_tokens", "max_tokens")
            };
            assert_eq!(body[field], 32);
            assert!(body.get(absent).is_none());
        }
    }
}
