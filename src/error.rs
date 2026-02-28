use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Config error: {0}")]
    Config(String),

    #[error("Config file not found: {0}")]
    ConfigNotFound(PathBuf),

    #[error("Auth failed: {0}")]
    Auth(String),

    #[error("Grant denied by {decided_by}")]
    Denied {
        grant_id: String,
        decided_by: String,
    },

    #[error("Grant timed out after {secs}s")]
    Timeout { grant_id: String, secs: u64 },

    #[error("JWT verification failed: {0}")]
    Jwt(String),

    #[error("cmd_hash mismatch: expected {expected}, got {got}")]
    CmdHashMismatch { expected: String, got: String },

    #[error("Exec failed: {0}")]
    Exec(String),

    #[error("Key does not match any registered agent")]
    NoMatchingAgent,

    #[error("Legacy config format detected. Migrate to multi-agent format: remove top-level agent_id/key_path/server_url, add [[agents]] array. See README.md")]
    LegacyConfig,

    #[error("Wrong key type: expected Ed25519")]
    WrongKeyType,

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Privilege error: {0}")]
    Privilege(String),
}

impl Error {
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Config(_) | Error::ConfigNotFound(_) | Error::NoMatchingAgent | Error::LegacyConfig => 1,
            Error::Auth(_) | Error::WrongKeyType => 2,
            Error::Denied { .. } => 3,
            Error::Timeout { .. } => 4,
            Error::Jwt(_) | Error::CmdHashMismatch { .. } => 5,
            Error::Exec(_) | Error::Privilege(_) => 126,
            Error::Http(_) | Error::Io(_) | Error::Json(_) => 1,
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Error::Config(msg) => {
                serde_json::json!({"error": "config", "message": msg})
            }
            Error::ConfigNotFound(path) => {
                serde_json::json!({"error": "config", "message": format!("Config file not found: {}", path.display())})
            }
            Error::Auth(msg) => {
                serde_json::json!({"error": "auth", "message": msg})
            }
            Error::Denied { grant_id, decided_by } => {
                serde_json::json!({"error": "denied", "grant_id": grant_id, "decided_by": decided_by})
            }
            Error::Timeout { grant_id, secs } => {
                serde_json::json!({"error": "timeout", "grant_id": grant_id, "secs": secs})
            }
            Error::Jwt(msg) => {
                serde_json::json!({"error": "jwt", "message": msg})
            }
            Error::CmdHashMismatch { .. } => {
                serde_json::json!({"error": "cmd_hash_mismatch"})
            }
            Error::Exec(msg) => {
                serde_json::json!({"error": "exec", "message": msg})
            }
            Error::NoMatchingAgent => {
                serde_json::json!({"error": "no_matching_agent", "message": self.to_string()})
            }
            Error::LegacyConfig => {
                serde_json::json!({"error": "legacy_config", "message": self.to_string()})
            }
            _ => {
                serde_json::json!({"error": "internal", "message": self.to_string()})
            }
        }
    }
}
