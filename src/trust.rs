use std::fs;
use std::io::{self, BufRead, IsTerminal, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use toml::{Table, Value};

use crate::cli::TrustArgs;
use crate::error::Error;

const CONFIG_MODE: u32 = 0o600;
const PARENT_MODE: u32 = 0o755;

pub fn run(config_path: &Path, args: &TrustArgs) -> Result<(), Error> {
    require_root(config_path)?;

    let idp = resolve_idp(args)?;
    let approvers = resolve_approvers(args)?;

    if !args.skip_validation {
        validate_idp(&idp)?;
    }

    let mut doc = read_existing_or_default(config_path)?;
    apply_trust(&mut doc, &idp, &approvers, args.replace);
    write_config(config_path, &doc)?;

    print_summary(config_path, &doc);
    Ok(())
}

fn resolve_idp(args: &TrustArgs) -> Result<String, Error> {
    if let Some(v) = args.idp.as_deref() {
        let v = v.trim().to_string();
        if v.is_empty() {
            return Err(Error::Config("--idp must not be empty".into()));
        }
        return Ok(v);
    }
    let v = prompt("IdP URL (e.g. https://id.openape.ai): ", "--idp")?;
    if v.is_empty() {
        return Err(Error::Config("IdP URL must not be empty".into()));
    }
    Ok(v)
}

fn resolve_approvers(args: &TrustArgs) -> Result<Vec<String>, Error> {
    let raw = match args.approvers.as_deref() {
        Some(v) => v.to_string(),
        None => prompt("Approver emails (comma-separated): ", "--approvers")?,
    };
    let list: Vec<String> = raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if list.is_empty() {
        return Err(Error::Config(
            "approvers must contain at least one email".into(),
        ));
    }
    Ok(list)
}

fn prompt(message: &str, flag_hint: &str) -> Result<String, Error> {
    if !io::stdin().is_terminal() {
        return Err(Error::Config(format!(
            "{flag_hint} missing and stdin is not a TTY — pass it on the command line or run in an interactive shell"
        )));
    }
    eprint!("{message}");
    io::stderr().flush().ok();
    let mut line = String::new();
    io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| Error::Config(format!("failed to read stdin: {e}")))?;
    Ok(line.trim().to_string())
}

fn validate_idp(idp: &str) -> Result<(), Error> {
    let base = idp.trim_end_matches('/');
    let discovery_url = format!("{base}/.well-known/openid-configuration");
    let discovery: serde_json::Value = ureq::get(&discovery_url)
        .set("User-Agent", "escapes-trust")
        .call()
        .map_err(|e| {
            Error::Http(format!(
                "IdP unreachable at {discovery_url} — {e}. Check the URL or add --skip-validation for airgapped setups."
            ))
        })?
        .into_json()
        .map_err(|e| Error::Http(format!("IdP returned invalid JSON at {discovery_url}: {e}")))?;

    let jwks_uri = discovery
        .get("jwks_uri")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            Error::Http(format!(
                "{discovery_url} has no `jwks_uri` — is this really an OpenID Connect IdP?"
            ))
        })?;
    eprintln!("✓ IdP reachable — {base}");

    let jwks: serde_json::Value = ureq::get(jwks_uri)
        .set("User-Agent", "escapes-trust")
        .call()
        .map_err(|e| Error::Http(format!("JWKS unreachable at {jwks_uri} — {e}")))?
        .into_json()
        .map_err(|e| Error::Http(format!("JWKS returned invalid JSON at {jwks_uri}: {e}")))?;

    let keys = jwks
        .get("keys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| Error::Http(format!("JWKS at {jwks_uri} has no `keys` array")))?;
    if keys.is_empty() {
        return Err(Error::Http(format!(
            "JWKS at {jwks_uri} has 0 signing keys — IdP not ready?"
        )));
    }
    let first_kid = keys
        .first()
        .and_then(|k| k.get("kid"))
        .and_then(|v| v.as_str())
        .unwrap_or("<no-kid>");
    eprintln!(
        "✓ JWKS has {} signing key{} (first kid: {first_kid})",
        keys.len(),
        if keys.len() == 1 { "" } else { "s" }
    );
    Ok(())
}

fn require_root(config_path: &Path) -> Result<(), Error> {
    if !nix::unistd::geteuid().is_root() {
        return Err(Error::Privilege(format!(
            "`escapes trust` must run as root to write {}. Try: sudo escapes trust ...",
            config_path.display()
        )));
    }
    Ok(())
}

fn read_existing_or_default(path: &Path) -> Result<Table, Error> {
    if !path.exists() {
        return Ok(Table::new());
    }
    let content = fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("Failed to read {}: {e}", path.display())))?;
    toml::from_str::<Table>(&content)
        .map_err(|e| Error::Config(format!("Failed to parse {}: {e}", path.display())))
}

fn apply_trust(doc: &mut Table, idp: &str, approvers: &[String], replace: bool) {
    let security = doc
        .entry("security".to_string())
        .or_insert_with(|| Value::Table(Table::new()));
    let Value::Table(security_table) = security else {
        // If the existing file has `security = "..."` (wrong shape), overwrite.
        *security = Value::Table(Table::new());
        let Value::Table(t) = security else {
            unreachable!()
        };
        return apply_trust_to_security_table(t, idp, approvers, replace);
    };
    apply_trust_to_security_table(security_table, idp, approvers, replace);
}

fn apply_trust_to_security_table(
    security: &mut Table,
    idp: &str,
    approvers: &[String],
    replace: bool,
) {
    let issuers = merge_list(
        security.get("allowed_issuers"),
        std::slice::from_ref(&idp.to_string()),
        replace,
    );
    let approvers_merged = merge_list(security.get("allowed_approvers"), approvers, replace);

    security.insert(
        "allowed_issuers".to_string(),
        Value::Array(issuers.into_iter().map(Value::String).collect()),
    );
    security.insert(
        "allowed_approvers".to_string(),
        Value::Array(approvers_merged.into_iter().map(Value::String).collect()),
    );
}

fn merge_list(existing: Option<&Value>, incoming: &[String], replace: bool) -> Vec<String> {
    let incoming_clean: Vec<String> = incoming
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if replace || existing.is_none() {
        return dedupe(incoming_clean);
    }
    let mut merged: Vec<String> = existing
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    for item in incoming_clean {
        if !merged.iter().any(|m| m == &item) {
            merged.push(item);
        }
    }
    merged
}

fn dedupe(items: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        if !out.iter().any(|o| o == &item) {
            out.push(item);
        }
    }
    out
}

fn write_config(path: &Path, doc: &Table) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent)
                .map_err(|e| Error::Config(format!("Create {}: {e}", parent.display())))?;
            fs::set_permissions(parent, fs::Permissions::from_mode(PARENT_MODE))
                .map_err(|e| Error::Config(format!("Chmod {}: {e}", parent.display())))?;
        }
    }
    let rendered =
        toml::to_string_pretty(doc).map_err(|e| Error::Config(format!("Render TOML: {e}")))?;
    fs::write(path, rendered)
        .map_err(|e| Error::Config(format!("Write {}: {e}", path.display())))?;
    fs::set_permissions(path, fs::Permissions::from_mode(CONFIG_MODE))
        .map_err(|e| Error::Config(format!("Chmod {}: {e}", path.display())))?;
    Ok(())
}

fn print_summary(path: &Path, doc: &Table) {
    let security = doc.get("security").and_then(|v| v.as_table());
    let n_issuers = security
        .and_then(|t| t.get("allowed_issuers"))
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let n_approvers = security
        .and_then(|t| t.get("allowed_approvers"))
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    eprintln!("✓ wrote {} (mode 0600)", path.display());
    eprintln!("Trust summary:");
    eprintln!("  allowed_issuers:   {n_issuers}");
    eprintln!("  allowed_approvers: {n_approvers}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_trust_creates_security_table_when_missing() {
        let mut doc = Table::new();
        apply_trust(&mut doc, "https://id.example.com", &["a@x".into()], false);
        let sec = doc["security"].as_table().unwrap();
        let issuers = sec["allowed_issuers"].as_array().unwrap();
        assert_eq!(issuers.len(), 1);
        assert_eq!(issuers[0].as_str().unwrap(), "https://id.example.com");
        let approvers = sec["allowed_approvers"].as_array().unwrap();
        assert_eq!(approvers[0].as_str().unwrap(), "a@x");
    }

    #[test]
    fn apply_trust_merges_by_default_and_dedupes() {
        let mut doc = toml::from_str::<Table>(
            r#"
[security]
allowed_issuers = ["https://id.a.com"]
allowed_approvers = ["a@x", "b@x"]
"#,
        )
        .unwrap();
        apply_trust(
            &mut doc,
            "https://id.a.com",
            &["b@x".into(), "c@x".into()],
            false,
        );
        let sec = doc["security"].as_table().unwrap();
        let issuers: Vec<&str> = sec["allowed_issuers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let approvers: Vec<&str> = sec["allowed_approvers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(issuers, vec!["https://id.a.com"]);
        assert_eq!(approvers, vec!["a@x", "b@x", "c@x"]);
    }

    #[test]
    fn apply_trust_replace_overwrites() {
        let mut doc = toml::from_str::<Table>(
            r#"
[security]
allowed_issuers = ["https://id.a.com"]
allowed_approvers = ["a@x", "b@x"]
"#,
        )
        .unwrap();
        apply_trust(&mut doc, "https://id.b.com", &["c@x".into()], true);
        let sec = doc["security"].as_table().unwrap();
        assert_eq!(
            sec["allowed_issuers"].as_array().unwrap()[0]
                .as_str()
                .unwrap(),
            "https://id.b.com"
        );
        assert_eq!(sec["allowed_issuers"].as_array().unwrap().len(), 1);
        assert_eq!(sec["allowed_approvers"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn apply_trust_preserves_unrelated_keys() {
        let mut doc = toml::from_str::<Table>(
            r#"
host = "box.example.com"
run_as = "deploy"

[security]
allowed_issuers = []
allowed_approvers = []
allowed_audiences = ["escapes", "custom"]

[tls]
ca_bundle = "/etc/ssl/ca.pem"
"#,
        )
        .unwrap();
        apply_trust(&mut doc, "https://id.a.com", &["a@x".into()], false);
        assert_eq!(doc["host"].as_str().unwrap(), "box.example.com");
        assert_eq!(doc["run_as"].as_str().unwrap(), "deploy");
        let sec = doc["security"].as_table().unwrap();
        assert_eq!(
            sec["allowed_audiences"].as_array().unwrap()[1]
                .as_str()
                .unwrap(),
            "custom"
        );
        assert_eq!(doc["tls"]["ca_bundle"].as_str().unwrap(), "/etc/ssl/ca.pem");
    }

    #[test]
    fn validate_idp_accepts_healthy_server() {
        let server = httpmock::MockServer::start();
        let base = server.url("");
        let jwks_url = format!("{base}/.well-known/jwks.json");
        server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/.well-known/openid-configuration");
            then.status(200)
                .json_body(serde_json::json!({ "jwks_uri": jwks_url }));
        });
        server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/.well-known/jwks.json");
            then.status(200).json_body(serde_json::json!({
                "keys": [{"kid": "abc123", "kty": "OKP", "crv": "Ed25519", "x": "..."}]
            }));
        });
        assert!(validate_idp(&base).is_ok());
    }

    #[test]
    fn validate_idp_rejects_404_discovery() {
        let server = httpmock::MockServer::start();
        server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/.well-known/openid-configuration");
            then.status(404);
        });
        let err = validate_idp(&server.url("")).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("IdP unreachable"));
    }

    #[test]
    fn validate_idp_rejects_missing_jwks_uri() {
        let server = httpmock::MockServer::start();
        server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/.well-known/openid-configuration");
            then.status(200).json_body(serde_json::json!({}));
        });
        let err = validate_idp(&server.url("")).unwrap_err();
        assert!(format!("{err}").contains("no `jwks_uri`"));
    }

    #[test]
    fn validate_idp_rejects_empty_jwks() {
        let server = httpmock::MockServer::start();
        let base = server.url("");
        let jwks_url = format!("{base}/.well-known/jwks.json");
        server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/.well-known/openid-configuration");
            then.status(200)
                .json_body(serde_json::json!({ "jwks_uri": jwks_url }));
        });
        server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/.well-known/jwks.json");
            then.status(200)
                .json_body(serde_json::json!({ "keys": [] }));
        });
        let err = validate_idp(&base).unwrap_err();
        assert!(format!("{err}").contains("0 signing keys"));
    }

    #[test]
    fn write_and_reread_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.toml");
        let mut doc = Table::new();
        apply_trust(&mut doc, "https://id.example.com", &["a@x".into()], false);
        write_config(&path, &doc).unwrap();
        let reread = read_existing_or_default(&path).unwrap();
        assert_eq!(
            reread["security"]["allowed_issuers"][0].as_str().unwrap(),
            "https://id.example.com"
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
