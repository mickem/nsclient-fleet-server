//! OpenAI's Chat Completions shape — and everything else that speaks it.
//!
//! This provider is doing double duty and the second job is the more important one. Chat
//! Completions is the de-facto interchange format: Azure OpenAI serves it, vLLM serves it,
//! llama.cpp's server serves it, Groq and Together serve it, and most in-house LLM gateways
//! present it. Pointing [`LlmConfig::base_url`] at any of those makes them work here
//! without another provider implementation, which is most of what "various LLMs" means in
//! practice.
//!
//! Two consequences for how this is written. It sends `max_tokens` rather than the newer
//! `max_completion_tokens`, because the older spelling is the one every compatible server
//! accepts. And it does not trust `response_format` to have been honoured: a compatible
//! server may ignore the field entirely, which is exactly the case [`super::extract_json`]
//! exists to rescue.

use async_trait::async_trait;

use super::{classify_status, LlmConfig, LlmError, LlmProvider, LlmRequest, LlmResponse};

pub struct OpenAiProvider;

#[async_trait]
impl LlmProvider for OpenAiProvider {
    fn name(&self) -> &'static str {
        "openai"
    }

    async fn complete(
        &self,
        http: &reqwest::Client,
        cfg: &LlmConfig,
        req: &LlmRequest,
    ) -> Result<LlmResponse, LlmError> {
        // The base URL carries the version prefix (`.../v1`), so that a gateway mounted at
        // an arbitrary path is configurable without string surgery here.
        let url = format!("{}/chat/completions", cfg.base());

        let body = serde_json::json!({
            "model": cfg.model,
            "max_tokens": req.max_output_tokens,
            "messages": [
                { "role": "system", "content": req.system },
                { "role": "user", "content": req.user },
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "alert_description",
                    "strict": true,
                    "schema": req.schema,
                }
            }
        });

        let mut r = http
            .post(&url)
            .header("content-type", "application/json")
            .json(&body);
        if let Some(key) = cfg.api_key.as_deref().filter(|k| !k.is_empty()) {
            r = r.bearer_auth(key);
        }

        let resp = r
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

        let choice = v
            .get("choices")
            .and_then(|c| c.as_array())
            .and_then(|c| c.first())
            .ok_or_else(|| LlmError::Malformed("the reply carried no choices".into()))?;

        // A content filter is a refusal, and a refusal is terminal: re-sending the same
        // evidence will be filtered the same way.
        if choice.get("finish_reason").and_then(|f| f.as_str()) == Some("content_filter") {
            return Err(LlmError::Refused(
                "the provider's content filter declined".into(),
            ));
        }
        if choice.get("finish_reason").and_then(|f| f.as_str()) == Some("length") {
            return Err(LlmError::Malformed(
                "the answer hit max_tokens and is incomplete".into(),
            ));
        }

        let message = choice.get("message");
        // Some servers report a structured-output refusal in its own field rather than via
        // finish_reason.
        if let Some(refusal) = message
            .and_then(|m| m.get("refusal"))
            .and_then(|r| r.as_str())
            .filter(|r| !r.is_empty())
        {
            return Err(LlmError::Refused(refusal.chars().take(400).collect()));
        }

        let answer = message
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .unwrap_or_default();
        if answer.trim().is_empty() {
            return Err(LlmError::Malformed("the reply carried no content".into()));
        }

        let usage = v.get("usage");
        Ok(LlmResponse {
            text: answer.to_string(),
            input_tokens: usage
                .and_then(|u| u.get("prompt_tokens"))
                .and_then(|t| t.as_i64()),
            output_tokens: usage
                .and_then(|u| u.get("completion_tokens"))
                .and_then(|t| t.as_i64()),
        })
    }
}
