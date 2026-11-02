//! A local Ollama daemon, over `POST /api/chat`.
//!
//! This is the provider for the deployment that cannot call anything: an on-prem install on
//! a network with no egress, where the monitoring data is precisely the data that is not
//! allowed to leave. Ollama runs the model on the same machine or the next one over, takes
//! no credential, and supports schema-constrained output through its `format` field — so
//! the air-gapped case gets the same structured description as the hosted one rather than a
//! degraded version of it.
//!
//! Ollama's own API is used rather than its OpenAI-compatible endpoint because `format`
//! takes the JSON schema directly and is honoured by the runner, which is more reliable
//! than the compatibility layer's `response_format` on small local models.

use async_trait::async_trait;

use super::{classify_status, LlmConfig, LlmError, LlmProvider, LlmRequest, LlmResponse};

pub struct OllamaProvider;

#[async_trait]
impl LlmProvider for OllamaProvider {
    fn name(&self) -> &'static str {
        "ollama"
    }

    async fn complete(
        &self,
        http: &reqwest::Client,
        cfg: &LlmConfig,
        req: &LlmRequest,
    ) -> Result<LlmResponse, LlmError> {
        let url = format!("{}/api/chat", cfg.base());

        let body = serde_json::json!({
            "model": cfg.model,
            // Without this the daemon streams NDJSON, and this worker has no use for
            // incremental output — nobody is watching it arrive.
            "stream": false,
            "messages": [
                { "role": "system", "content": req.system },
                { "role": "user", "content": req.user },
            ],
            "format": req.schema,
            "options": {
                "num_predict": req.max_output_tokens,
                // Local models drift more than hosted ones on a structured task; a low
                // temperature is what keeps a 7B model emitting the schema rather than an
                // essay about it.
                "temperature": 0.2
            }
        });

        // Ollama is usually unauthenticated on a private network, but a reverse proxy in
        // front of it may not be — so a key is sent when one is configured and omitted
        // otherwise, rather than being refused outright.
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

        let answer = v
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .unwrap_or_default();
        if answer.trim().is_empty() {
            return Err(LlmError::Malformed("the reply carried no content".into()));
        }

        Ok(LlmResponse {
            text: answer.to_string(),
            // Ollama reports token counts under its own names. Both are optional here, so
            // a runner that omits them costs us accounting detail and nothing else.
            input_tokens: v.get("prompt_eval_count").and_then(|t| t.as_i64()),
            output_tokens: v.get("eval_count").and_then(|t| t.as_i64()),
        })
    }
}
