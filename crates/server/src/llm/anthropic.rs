//! The Claude API, over `POST /v1/messages`.
//!
//! Raw HTTP rather than the official SDK because there is no first-party Anthropic SDK for
//! Rust, and `reqwest` is already a dependency of this crate.

use async_trait::async_trait;

use super::{classify_status, LlmConfig, LlmError, LlmProvider, LlmRequest, LlmResponse};

/// The dated API version this request shape is written against. Required on every call, and
/// pinned: it is the contract, and letting it float would mean a server-side change could
/// alter our parsing without a deploy.
const API_VERSION: &str = "2023-06-01";

pub struct AnthropicProvider;

#[async_trait]
impl LlmProvider for AnthropicProvider {
    fn name(&self) -> &'static str {
        "anthropic"
    }

    async fn complete(
        &self,
        http: &reqwest::Client,
        cfg: &LlmConfig,
        req: &LlmRequest,
    ) -> Result<LlmResponse, LlmError> {
        let url = format!("{}/v1/messages", cfg.base());

        let body = serde_json::json!({
            "model": cfg.model,
            "max_tokens": req.max_output_tokens,
            // The system prompt is a top-level field here, not a message. It is the half of
            // the prompt that says the alert is evidence rather than instruction, so it
            // must not be something a payload could be mistaken for.
            "system": req.system,
            "messages": [{ "role": "user", "content": req.user }],
            "output_config": {
                // Constrained decoding: the answer is rendered as fields in a UI, so
                // "mostly JSON" is a parse failure.
                "format": { "type": "json_schema", "schema": req.schema },
                // Describing a monitoring alert is a short, high-volume, well-specified
                // task — the kind that does not repay deep reasoning. Effort is the lever
                // for that, rather than reaching for a smaller model: it keeps the
                // description quality of the model the operator chose at a fraction of the
                // thinking spend.
                "effort": "low"
            }
        });

        let resp = http
            .post(&url)
            .header("x-api-key", cfg.api_key.as_deref().unwrap_or_default())
            .header("anthropic-version", API_VERSION)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| LlmError::Transport(e.to_string()))?;

        let status = resp.status().as_u16();
        let text = resp
            .text()
            .await
            .map_err(|e| LlmError::Transport(e.to_string()))?;
        if !(200..300).contains(&status) {
            return Err(classify_status(status, &text));
        }

        let v: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| LlmError::Malformed(e.to_string()))?;

        // Checked before the content is read, per the API contract: on a refusal the
        // content does not match the schema, and on a `max_tokens` stop it is truncated
        // JSON. Both would otherwise surface as a confusing parse error.
        match v.get("stop_reason").and_then(|s| s.as_str()) {
            Some("refusal") => {
                let why = v
                    .get("stop_details")
                    .and_then(|d| d.get("explanation"))
                    .and_then(|e| e.as_str())
                    .unwrap_or("no explanation given");
                return Err(LlmError::Refused(why.chars().take(400).collect()));
            }
            Some("max_tokens") => {
                return Err(LlmError::Malformed(
                    "the answer hit max_tokens and is incomplete".into(),
                ))
            }
            _ => {}
        }

        // `content` is a list of blocks; with thinking on, the text block is not
        // necessarily the first one.
        let answer = v
            .get("content")
            .and_then(|c| c.as_array())
            .map(|blocks| {
                blocks
                    .iter()
                    .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("text"))
                    .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                    .collect::<Vec<_>>()
                    .join("")
            })
            .unwrap_or_default();
        if answer.trim().is_empty() {
            return Err(LlmError::Malformed(
                "the reply carried no text block".into(),
            ));
        }

        let usage = v.get("usage");
        Ok(LlmResponse {
            text: answer,
            input_tokens: usage
                .and_then(|u| u.get("input_tokens"))
                .and_then(|t| t.as_i64()),
            output_tokens: usage
                .and_then(|u| u.get("output_tokens"))
                .and_then(|t| t.as_i64()),
        })
    }
}
