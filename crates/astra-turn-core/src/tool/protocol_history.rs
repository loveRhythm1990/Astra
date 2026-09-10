//! Provider-neutral detection of tool protocol state in conversation history.
//!
//! Some providers reject a request that contains historical tool-use blocks
//! when the request omits tool declarations. Keep this detector shared by the
//! local and Server request builders so an optimization cannot accidentally
//! produce an invalid replay shape.

use serde_json::Value;

fn content_contains_tool_block(content: Option<&Value>) -> bool {
    let is_tool_block = |block: &Value| {
        matches!(
            block.get("type").and_then(Value::as_str),
            Some("tool_use" | "tool_result")
        ) || block.get("toolUse").is_some()
            || block.get("toolResult").is_some()
    };

    match content {
        Some(Value::Array(blocks)) => blocks.iter().any(is_tool_block),
        Some(Value::Object(_)) => content.is_some_and(is_tool_block),
        _ => false,
    }
}

/// Whether messages contain any OpenAI-, Anthropic-, or Bedrock-shaped tool
/// call/result state that requires a compatible tool declaration surface.
#[must_use]
pub fn messages_contain_tool_protocol(messages: &[Value]) -> bool {
    messages.iter().any(|message| {
        message.get("role").and_then(Value::as_str) == Some("tool")
            || message.get("tool_call_id").is_some()
            || message
                .get("tool_calls")
                .and_then(Value::as_array)
                .is_some_and(|calls| !calls.is_empty())
            || content_contains_tool_block(message.get("content"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn detects_supported_tool_protocol_history_shapes() {
        for messages in [
            vec![json!({"role":"assistant","tool_calls":[{"id":"call-1"}]})],
            vec![json!({"role":"tool","tool_call_id":"call-1","content":"ok"})],
            vec![json!({"role":"assistant","content":[{"type":"tool_use","id":"call-1"}]})],
            vec![json!({"role":"user","content":[{"type":"tool_result","tool_use_id":"call-1"}]})],
            vec![json!({"role":"assistant","content":[{"toolUse":{"toolUseId":"call-1"}}]})],
            vec![json!({"role":"user","content":[{"toolResult":{"toolUseId":"call-1"}}]})],
        ] {
            assert!(messages_contain_tool_protocol(&messages), "{messages:?}");
        }
    }

    #[test]
    fn ordinary_history_does_not_claim_a_tool_protocol() {
        assert!(!messages_contain_tool_protocol(&[
            json!({"role":"user","content":"hello"}),
            json!({"role":"assistant","content":[{"type":"text","text":"hi"}]})
        ]));
        assert!(!messages_contain_tool_protocol(&[json!({
            "role":"assistant",
            "tool_calls":[]
        })]));
    }
}
