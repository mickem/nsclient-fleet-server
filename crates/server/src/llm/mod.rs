//! Asking a language model to describe an alert.
//!
//! # Why there is a provider abstraction at all
//!
//! The obvious implementation calls one vendor. That fails the first deployment it meets:
//! this server ships both as a hosted service and as an on-prem install, and a meaningful
//! share of the on-prem installs are on networks that will not reach an external API at
//! all, ever, for policy reasons that predate this feature. Those sites do want the
//! descriptions — they will run the model themselves. Meanwhile a hosted tenant has a
//! vendor relationship of their own and a key they would rather use than ours.
//!
//! So the unit of configuration is (provider, model, base URL, key), and there are three
//! providers, chosen to cover the space rather than to enumerate vendors:
//!
//! | provider    | covers                                                                  |
//! |-------------|-------------------------------------------------------------------------|
//! | `anthropic` | the Claude API (Messages), first-party                                  |
//! | `openai`    | OpenAI **and** every endpoint that speaks its Chat Completions shape — Azure OpenAI, vLLM, llama.cpp's server, Groq, Together, an in-house gateway — via `base_url` |
//! | `ollama`    | a local Ollama daemon: no key, no egress, the air-gapped answer         |
//!
//! Adding a fourth is a file and a match arm, not a migration: `tenant_llm_settings.provider`
//! is deliberately not a CHECK constraint.
//!
//! # What every provider must do the same way
//!
//! Each one is handed a system prompt, a user message, and a JSON schema, and must return
//! text that parses against that schema plus whatever token counts it knows. Structured
//! output is not a nicety here — the answer is rendered as fields in a UI, and "mostly JSON
//! with a sentence of preamble" is a parse failure. Every provider therefore uses its
//! native schema-constrained mode ([`anthropic::AnthropicProvider`] `output_config.format`,
//! [`openai::OpenAiProvider`] `response_format`, [`ollama::OllamaProvider`] `format`), and
//! [`parse_answer`] is still defensive on top of that, because a compatible-but-not-OpenAI
//! server may ignore the field entirely.
//!
//! Errors are classified into retryable and terminal by [`LlmError::retryable`], and that
//! classification is the whole of the retry policy. A 429 or a 503 is worth coming back
//! for; a 401 is not, and a worker that retried it would spend the rest of the week making
//! authenticated-looking requests against an account that has revoked us.

pub mod anthropic;
pub mod ollama;
pub mod openai;
pub mod prompt;
pub mod redact;

use async_trait::async_trait;
use std::sync::OnceLock;
use std::time::Duration;

/// The process-wide default configuration, from the environment, read once at startup.
///
/// A global rather than a field on `AppState` because it is genuinely process-wide — it
/// comes from environment variables, cannot change without a restart, and every tenant
/// without a row of its own resolves to the same value. Leaving it unset (as every test
/// does) means "no server default", which is also the right answer for a hosted install
/// where configuration is per tenant.
static SERVER_DEFAULT: OnceLock<Option<LlmConfig>> = OnceLock::new();

/// Install the process-wide default. Called once, at startup, before any request is served.
/// A second call is ignored rather than panicking: losing a race here would be a worse
/// outcome than the first writer winning, and there is only ever one caller.
pub fn init_server_default(cfg: Option<LlmConfig>) {
    let _ = SERVER_DEFAULT.set(cfg);
}

/// The process-wide default, if one was installed.
pub fn server_default() -> Option<&'static LlmConfig> {
    SERVER_DEFAULT.get().and_then(|c| c.as_ref())
}

/// How long any one model call may take.
///
/// Generous: a reasoning model on a long prompt genuinely takes tens of seconds, and a
/// locally hosted model on modest hardware takes longer still. It is a bound on a
/// background worker, not on a request path — nobody is waiting on it — so the only thing
/// it has to prevent is a hung connection occupying the worker for good.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(120);

/// Which provider's wire shape to speak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    Anthropic,
    OpenAi,
    Ollama,
}

impl ProviderKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "anthropic" | "claude" => Some(Self::Anthropic),
            // `azure` and `openai-compatible` are the same wire shape with a different
            // base URL; accepting the names people will actually type saves a support
            // round trip and costs nothing.
            "openai" | "azure" | "openai-compatible" => Some(Self::OpenAi),
            "ollama" | "local" => Some(Self::Ollama),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAi => "openai",
            Self::Ollama => "ollama",
        }
    }

    /// A sensible model when the operator named a provider but not a model.
    pub fn default_model(self) -> &'static str {
        match self {
            Self::Anthropic => "claude-opus-5",
            Self::OpenAi => "gpt-4o-mini",
            Self::Ollama => "llama3.1",
        }
    }

    /// Whether a key is required. Ollama is normally unauthenticated on a private network;
    /// requiring one would make the air-gapped case impossible to configure.
    pub fn requires_api_key(self) -> bool {
        !matches!(self, Self::Ollama)
    }

    pub fn default_base_url(self) -> &'static str {
        match self {
            Self::Anthropic => "https://api.anthropic.com",
            Self::OpenAi => "https://api.openai.com/v1",
            Self::Ollama => "http://127.0.0.1:11434",
        }
    }
}

/// Everything needed to make one call, after per-tenant settings and process defaults have
/// been reconciled.
#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub provider: ProviderKind,
    pub model: String,
    /// Endpoint override. `None` means [`ProviderKind::default_base_url`].
    pub base_url: Option<String>,
    pub api_key: Option<String>,
    /// Model calls allowed per UTC day for this tenant. 0 disables enrichment outright.
    pub daily_call_budget: i64,
}

impl LlmConfig {
    /// The process-wide default, from the environment.
    ///
    /// This is the on-prem path: one tenant, an operator with a shell, and no desire to
    /// click through a console to turn something on. `LLM_PROVIDER` unset means the feature
    /// is off unless a tenant has configured it in the database.
    ///
    /// Returns `Err` with an operator-readable reason when the variables are present but
    /// contradictory, so a typo surfaces at startup rather than as alerts that quietly
    /// never get described.
    pub fn from_env() -> Result<Option<Self>, String> {
        let Some(raw) = std::env::var("LLM_PROVIDER")
            .ok()
            .filter(|v| !v.trim().is_empty())
        else {
            return Ok(None);
        };
        let provider = ProviderKind::parse(&raw).ok_or_else(|| {
            format!("LLM_PROVIDER '{raw}' is not one of anthropic, openai, ollama")
        })?;

        let api_key = std::env::var("LLM_API_KEY")
            .ok()
            .filter(|v| !v.trim().is_empty());
        if provider.requires_api_key() && api_key.is_none() {
            return Err(format!(
                "LLM_PROVIDER is '{}' but LLM_API_KEY is not set",
                provider.as_str()
            ));
        }

        let budget = match std::env::var("LLM_DAILY_CALL_BUDGET") {
            Ok(v) if !v.trim().is_empty() => v
                .trim()
                .parse::<i64>()
                .map_err(|_| format!("LLM_DAILY_CALL_BUDGET '{v}' is not a number"))?,
            // Unset means "no cap I set", which on-prem is the right default: the operator
            // is running their own model or paying their own bill and did not ask us to
            // ration it. The hosted path gets its cap from the tenant row instead.
            _ => i64::MAX,
        };
        if budget < 0 {
            return Err("LLM_DAILY_CALL_BUDGET cannot be negative".into());
        }

        Ok(Some(Self {
            provider,
            model: std::env::var("LLM_MODEL")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| provider.default_model().to_string()),
            base_url: std::env::var("LLM_BASE_URL")
                .ok()
                .filter(|v| !v.trim().is_empty()),
            api_key,
            daily_call_budget: budget,
        }))
    }

    pub fn base(&self) -> &str {
        self.base_url
            .as_deref()
            // Whitespace first: a value of "   " is an operator who cleared the field, not
            // an endpoint, and trimming only slashes would leave it non-empty and used.
            .map(|u| u.trim().trim_end_matches('/'))
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| self.provider.default_base_url())
    }

    pub fn provider_impl(&self) -> Box<dyn LlmProvider> {
        match self.provider {
            ProviderKind::Anthropic => Box::new(anthropic::AnthropicProvider),
            ProviderKind::OpenAi => Box::new(openai::OpenAiProvider),
            ProviderKind::Ollama => Box::new(ollama::OllamaProvider),
        }
    }
}

/// One model call, provider-independent.
#[derive(Debug, Clone)]
pub struct LlmRequest {
    pub system: String,
    pub user: String,
    /// JSON Schema the answer must satisfy. Kept to the subset every provider's
    /// constrained-decoding mode accepts: objects, strings, arrays, enums, and
    /// `additionalProperties: false`, with no numeric or length constraints.
    pub schema: serde_json::Value,
    pub max_output_tokens: u32,
}

#[derive(Debug, Clone)]
pub struct LlmResponse {
    /// The assistant's text, expected to be a JSON document matching the schema.
    pub text: String,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
}

#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    /// The request never got an answer. Always worth retrying.
    #[error("could not reach the model provider: {0}")]
    Transport(String),
    #[error("the model provider is rate limiting us")]
    RateLimited,
    #[error("the model provider returned {0}: {1}")]
    Server(u16, String),
    /// Credentials. Terminal: no amount of waiting fixes a revoked key.
    #[error("the model provider rejected our credentials ({0}): {1}")]
    Auth(u16, String),
    /// The request itself is wrong — an unknown model, an unsupported parameter. Terminal
    /// for the same reason: every retry sends the identical bytes.
    #[error("the model provider rejected the request ({0}): {1}")]
    BadRequest(u16, String),
    /// The model declined to answer.
    #[error("the model declined to describe this alert: {0}")]
    Refused(String),
    /// An answer arrived but was not usable.
    #[error("the model's answer could not be read: {0}")]
    Malformed(String),
}

impl LlmError {
    /// Whether coming back later could plausibly produce a different outcome.
    ///
    /// `Malformed` counts as retryable: a model that truncated or wandered off-schema once
    /// may well not do so again, and unlike an auth failure the retry is not guaranteed
    /// futile. It is still bounded by the attempt limit, so a model that cannot follow the
    /// schema at all gives up after a few tries rather than never.
    pub fn retryable(&self) -> bool {
        match self {
            Self::Transport(_) | Self::RateLimited | Self::Server(_, _) | Self::Malformed(_) => {
                true
            }
            Self::Auth(_, _) | Self::BadRequest(_, _) | Self::Refused(_) => false,
        }
    }
}

/// Map an HTTP status onto the retry classification above. Shared by all three providers so
/// one of them cannot quietly decide that 401 is worth another go.
pub fn classify_status(status: u16, body: &str) -> LlmError {
    // Bodies are provider error text and can be long, and they end up in a column and a
    // log line.
    let body: String = body.chars().take(400).collect();
    match status {
        401 | 403 => LlmError::Auth(status, body),
        429 => LlmError::RateLimited,
        // 408 and 409 are the two 4xx that genuinely are transient.
        408 | 409 => LlmError::Server(status, body),
        400..=499 => LlmError::BadRequest(status, body),
        _ => LlmError::Server(status, body),
    }
}

#[async_trait]
pub trait LlmProvider: Send + Sync {
    fn name(&self) -> &'static str;

    /// Make the call. Implementations own their wire format and nothing else: the prompt,
    /// the schema, the retry decision and the accounting all live outside.
    async fn complete(
        &self,
        http: &reqwest::Client,
        cfg: &LlmConfig,
        req: &LlmRequest,
    ) -> Result<LlmResponse, LlmError>;
}

/// Pull the first JSON object out of a model's reply and parse it.
///
/// Every provider is asked for schema-constrained output, so the common case is that `text`
/// is already exactly one JSON document. This exists for the case that is not: an
/// OpenAI-compatible server that ignores `response_format`, or a small local model that
/// wraps its answer in a ```json fence and a friendly sentence. Recovering from that is
/// worth a dozen lines, because the alternative is telling an on-prem operator their model
/// is unsupported when it answered correctly.
pub fn extract_json(text: &str) -> Result<serde_json::Value, LlmError> {
    let trimmed = text.trim();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
        return Ok(v);
    }
    // Scan for a balanced object, tracking string state so a brace inside a string value —
    // a Windows path, a log line — does not end the scan early.
    let bytes = trimmed.as_bytes();
    let start = bytes.iter().position(|&b| b == b'{');
    if let Some(start) = start {
        let mut depth = 0usize;
        let mut in_string = false;
        let mut escaped = false;
        for (i, &b) in bytes.iter().enumerate().skip(start) {
            if in_string {
                if escaped {
                    escaped = false;
                } else if b == b'\\' {
                    escaped = true;
                } else if b == b'"' {
                    in_string = false;
                }
                continue;
            }
            match b {
                b'"' => in_string = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        let candidate = &trimmed[start..=i];
                        return serde_json::from_str(candidate)
                            .map_err(|e| LlmError::Malformed(e.to_string()));
                    }
                }
                _ => {}
            }
        }
    }
    Err(LlmError::Malformed(format!(
        "no JSON object in a {}-character reply",
        trimmed.chars().count()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_names_people_actually_type_are_accepted() {
        assert_eq!(
            ProviderKind::parse("anthropic"),
            Some(ProviderKind::Anthropic)
        );
        assert_eq!(
            ProviderKind::parse("  Claude "),
            Some(ProviderKind::Anthropic)
        );
        assert_eq!(ProviderKind::parse("AZURE"), Some(ProviderKind::OpenAi));
        assert_eq!(
            ProviderKind::parse("openai-compatible"),
            Some(ProviderKind::OpenAi)
        );
        assert_eq!(ProviderKind::parse("ollama"), Some(ProviderKind::Ollama));
        assert_eq!(ProviderKind::parse("gemini"), None);
    }

    #[test]
    fn only_the_local_provider_may_go_without_a_key() {
        assert!(ProviderKind::Anthropic.requires_api_key());
        assert!(ProviderKind::OpenAi.requires_api_key());
        assert!(
            !ProviderKind::Ollama.requires_api_key(),
            "requiring a key would make the air-gapped case impossible to configure"
        );
    }

    #[test]
    fn base_url_overrides_the_default_and_loses_its_trailing_slash() {
        let mut cfg = LlmConfig {
            provider: ProviderKind::OpenAi,
            model: "m".into(),
            base_url: None,
            api_key: None,
            daily_call_budget: 10,
        };
        assert_eq!(cfg.base(), "https://api.openai.com/v1");
        cfg.base_url = Some("https://gw.internal/v1/".into());
        assert_eq!(cfg.base(), "https://gw.internal/v1");
        cfg.base_url = Some("  ".into());
        assert_eq!(
            cfg.base(),
            "https://api.openai.com/v1",
            "blank is not an override"
        );
    }

    #[test]
    fn credentials_are_never_retried_but_outages_are() {
        assert!(!classify_status(401, "bad key").retryable());
        assert!(!classify_status(403, "forbidden").retryable());
        assert!(!classify_status(404, "no such model").retryable());
        assert!(!classify_status(400, "unsupported parameter").retryable());
        assert!(classify_status(429, "slow down").retryable());
        assert!(classify_status(500, "oops").retryable());
        assert!(classify_status(503, "overloaded").retryable());
        assert!(classify_status(408, "timeout").retryable());
    }

    #[test]
    fn error_bodies_cannot_flood_a_column_or_a_log_line() {
        let err = classify_status(500, &"x".repeat(10_000));
        let LlmError::Server(_, body) = err else {
            panic!("expected a server error")
        };
        assert_eq!(body.chars().count(), 400);
    }

    #[test]
    fn a_clean_json_answer_parses() {
        let v = extract_json(r#"{"summary":"disk full"}"#).unwrap();
        assert_eq!(v["summary"], "disk full");
    }

    #[test]
    fn an_answer_wrapped_in_prose_or_a_fence_is_still_recovered() {
        let v =
            extract_json("Sure! Here you go:\n```json\n{\"summary\":\"ok\"}\n```\nHope that helps")
                .unwrap();
        assert_eq!(v["summary"], "ok");
    }

    #[test]
    fn a_brace_inside_a_string_does_not_end_the_scan() {
        // A Windows path and a log line with braces are exactly what alert evidence holds.
        let v =
            extract_json(r#"note: {"summary":"C:\\Program Files\\{GUID} is full","n":1}"#).unwrap();
        assert_eq!(v["summary"], "C:\\Program Files\\{GUID} is full");
        assert_eq!(v["n"], 1);
    }

    #[test]
    fn nested_objects_are_read_to_their_real_end() {
        let v = extract_json(r#"answer: {"a":{"b":{"c":1}},"d":2} done"#).unwrap();
        assert_eq!(v["d"], 2);
    }

    #[test]
    fn a_reply_with_no_json_is_an_error_rather_than_a_panic() {
        assert!(extract_json("I cannot help with that.").is_err());
        assert!(extract_json("").is_err());
        assert!(extract_json("{\"unterminated\": ").is_err());
    }

    #[test]
    fn env_config_is_absent_by_default_and_refuses_a_half_configuration() {
        // Serialised through one test: these are process-wide.
        temp_env(&[("LLM_PROVIDER", None)], || {
            assert!(LlmConfig::from_env().unwrap().is_none());
        });
        temp_env(
            &[("LLM_PROVIDER", Some("anthropic")), ("LLM_API_KEY", None)],
            || {
                let err = LlmConfig::from_env().unwrap_err();
                assert!(err.contains("LLM_API_KEY"), "{err}");
            },
        );
        temp_env(
            &[("LLM_PROVIDER", Some("nope")), ("LLM_API_KEY", Some("k"))],
            || {
                assert!(LlmConfig::from_env().unwrap_err().contains("not one of"));
            },
        );
        temp_env(
            &[
                ("LLM_PROVIDER", Some("ollama")),
                ("LLM_API_KEY", None),
                ("LLM_MODEL", None),
            ],
            || {
                let cfg = LlmConfig::from_env().unwrap().unwrap();
                assert_eq!(cfg.provider, ProviderKind::Ollama);
                assert_eq!(
                    cfg.model, "llama3.1",
                    "a named provider needs no named model"
                );
                assert_eq!(
                    cfg.daily_call_budget,
                    i64::MAX,
                    "on-prem is not rationed by us"
                );
            },
        );
        temp_env(
            &[
                ("LLM_PROVIDER", Some("anthropic")),
                ("LLM_API_KEY", Some("sk-test")),
                ("LLM_MODEL", Some("claude-sonnet-5")),
                ("LLM_DAILY_CALL_BUDGET", Some("50")),
            ],
            || {
                let cfg = LlmConfig::from_env().unwrap().unwrap();
                assert_eq!(cfg.model, "claude-sonnet-5");
                assert_eq!(cfg.daily_call_budget, 50);
            },
        );
        temp_env(
            &[
                ("LLM_PROVIDER", Some("anthropic")),
                ("LLM_API_KEY", Some("k")),
                ("LLM_DAILY_CALL_BUDGET", Some("lots")),
            ],
            || assert!(LlmConfig::from_env().unwrap_err().contains("not a number")),
        );
        // Leave the process as we found it.
        temp_env(
            &[
                ("LLM_PROVIDER", None),
                ("LLM_API_KEY", None),
                ("LLM_MODEL", None),
                ("LLM_DAILY_CALL_BUDGET", None),
            ],
            || {},
        );
    }

    fn temp_env(vars: &[(&str, Option<&str>)], f: impl FnOnce()) {
        for (k, v) in vars {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        f();
    }
}
