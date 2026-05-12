use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error in {file}:{line}: {detail}")]
    Parse {
        file: String,
        line: u64,
        detail: String,
    },

    #[error("Config error in {path}: {reason}")]
    Config {
        path: String,
        reason: String,
    },

    #[error("LLM API error (status {status}): {message}")]
    Llm {
        status: u16,
        message: String,
    },
}
