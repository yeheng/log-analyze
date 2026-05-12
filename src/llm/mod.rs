//! LLM-powered analysis post-processing via rig-core.

use crate::config::LlmConfig;
use crate::core::error::AppError;

const MAX_REPORT_CHARS: usize = 100_000;

fn resolve_api_key(config: &LlmConfig) -> Result<String, AppError> {
    if !config.api_key.is_empty() {
        return Ok(config.api_key.clone());
    }
    if let Ok(key) = std::env::var("LOG_ANALYZE_API_KEY") {
        if !key.is_empty() {
            return Ok(key);
        }
    }
    let is_anthropic = config.base_url.contains("anthropic.com");
    let env_var = if is_anthropic {
        "ANTHROPIC_API_KEY"
    } else {
        "OPENAI_API_KEY"
    };
    std::env::var(env_var).map_err(|_| AppError::Llm {
        status: 0,
        message: format!(
            "No API key found. Set [llm] api_key in config, LOG_ANALYZE_API_KEY, or {}",
            env_var
        ),
    })
}

fn system_prompt(language: &str) -> String {
    let lang_name = match language {
        "zh" => "Chinese (Simplified)",
        "ja" => "Japanese",
        "ko" => "Korean",
        "fr" => "French",
        "de" => "German",
        "es" => "Spanish",
        "pt" => "Portuguese",
        "ru" => "Russian",
        _ => "English",
    };
    format!(
        "You are an expert site reliability engineer and log analysis specialist. \
         You will receive a structured JSON analysis report from a log analysis tool. \
         Your task is to:\n\
         1. Summarize the key findings in plain language.\n\
         2. Identify the most critical issues and explain their likely root causes.\n\
         3. Suggest concrete remediation steps.\n\
         4. Highlight any patterns or anomalies that deserve attention.\n\n\
         Format your response in clear sections with headers.\n\
         Respond in {}.",
        lang_name,
    )
}

pub fn analyze_with_llm(config: &LlmConfig, report_json: &str) -> Result<String, AppError> {
    let api_key = resolve_api_key(config)?;
    let preamble = system_prompt(&config.language);

    let user_message = if report_json.len() > MAX_REPORT_CHARS {
        &report_json[..MAX_REPORT_CHARS]
    } else {
        report_json
    };

    let rt = tokio::runtime::Runtime::new().map_err(|e| AppError::Llm {
        status: 0,
        message: format!("Failed to create tokio runtime: {}", e),
    })?;

    let is_anthropic = config.base_url.contains("anthropic.com");
    if is_anthropic {
        rt.block_on(call_anthropic(
            &api_key,
            &config.base_url,
            &config.model,
            &preamble,
            user_message,
        ))
    } else {
        rt.block_on(call_openai_compatible(
            &api_key,
            &config.base_url,
            &config.model,
            &preamble,
            user_message,
        ))
    }
}

async fn call_anthropic(
    api_key: &str,
    base_url: &str,
    model: &str,
    preamble: &str,
    user_message: &str,
) -> Result<String, AppError> {
    use rig::client::CompletionClient;
    use rig::completion::Prompt;
    use rig::providers::anthropic::Client as AnthropicClient;

    let client = AnthropicClient::builder()
        .api_key(api_key)
        .base_url(base_url)
        .build()
        .map_err(|e| AppError::Llm {
            status: 0,
            message: format!("Anthropic client error: {}", e),
        })?;

    let agent = client.agent(model).preamble(preamble).build();

    agent
        .prompt(user_message)
        .await
        .map_err(|e| AppError::Llm {
            status: 0,
            message: format!("Anthropic API error: {}", e),
        })
}

async fn call_openai_compatible(
    api_key: &str,
    base_url: &str,
    model: &str,
    preamble: &str,
    user_message: &str,
) -> Result<String, AppError> {
    use rig::client::CompletionClient;
    use rig::completion::Prompt;
    use rig::providers::openai::CompletionsClient;

    let url = if base_url.ends_with("/v1") || base_url.ends_with("/v1/") {
        base_url.to_string()
    } else {
        format!("{}/v1", base_url.trim_end_matches('/'))
    };

    let client = CompletionsClient::builder()
        .api_key(api_key)
        .base_url(&url)
        .build()
        .map_err(|e| AppError::Llm {
            status: 0,
            message: format!("OpenAI-compatible client error: {}", e),
        })?;

    let agent = client.agent(model).preamble(preamble).build();

    agent
        .prompt(user_message)
        .await
        .map_err(|e| AppError::Llm {
            status: 0,
            message: format!("OpenAI-compatible API error: {}", e),
        })
}
