use std::fs::OpenOptions;
use std::io::Write;

use chrono::Utc;
use nix::unistd::Uid;

use crate::config::Config;

/// Write an audit log entry for a grant-token mode command run.
pub fn log_grant_run(
    config: &Config,
    claims: &crate::grant_mode::GrantClaims,
    real_uid: Uid,
    cmd: &[String],
    cmd_hash: &str,
) {
    let entry = serde_json::json!({
        "ts": Utc::now().to_rfc3339(),
        "event": "grant_run",
        "real_uid": real_uid.as_raw(),
        "command": cmd,
        "cmd_hash": cmd_hash,
        "grant_id": claims.grant_id,
        "grant_type": claims.grant_type,
        "agent": claims.sub,
        "issuer": claims.iss,
        "decided_by": claims.decided_by,
        "audience": claims.aud,
        "target_host": claims.target_host,
        "run_as": claims.run_as,
        "host": config.effective_host(),
        "cwd": std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_default(),
    });

    write_entry(config, &entry);
}

/// Write an audit log entry for an error.
#[allow(dead_code)]
pub fn log_error(config: &Config, real_uid: Uid, cmd: &[String], message: &str) {
    let entry = serde_json::json!({
        "ts": Utc::now().to_rfc3339(),
        "event": "error",
        "real_uid": real_uid.as_raw(),
        "command": cmd,
        "host": config.effective_host(),
        "message": message,
    });

    write_entry(config, &entry);
}

fn write_entry(config: &Config, entry: &serde_json::Value) {
    let log_path = &config.audit_log;

    // Ensure parent directory exists
    if let Some(parent) = log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let result = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .and_then(|mut file| writeln!(file, "{entry}"));

    if let Err(e) = result {
        eprintln!(
            "{}",
            serde_json::json!({"warning": "audit_log_failed", "path": log_path.display().to_string(), "error": e.to_string()})
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{SecurityConfig, TlsConfig};

    fn test_config(dir: &std::path::Path) -> Config {
        Config {
            host: Some("test-host".into()),
            run_as: "root".into(),
            audit_log: dir.join("audit.log"),
            security: SecurityConfig {
                allowed_issuers: vec!["https://id.openape.at".into()],
                allowed_approvers: vec!["admin@example.com".into()],
                allowed_audiences: vec!["escapes".into()],
            },
            tls: TlsConfig::default(),
        }
    }

    #[test]
    fn test_write_audit_entry() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());

        let entry = serde_json::json!({"event": "test", "ts": "2026-01-01T00:00:00Z"});
        write_entry(&config, &entry);

        let content = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        assert!(content.contains("\"event\":\"test\""));
    }

    #[test]
    fn test_append_multiple_entries() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());

        write_entry(&config, &serde_json::json!({"n": 1}));
        write_entry(&config, &serde_json::json!({"n": 2}));

        let content = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
    }
}
