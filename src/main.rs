mod audit;
mod auth;
mod cli;
mod config;
mod crypto;
mod enroll;
mod error;
mod exec;
mod grants;
mod jwt;

use clap::Parser;

use cli::{Cli, Commands};
use error::Error;

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Some(Commands::Enroll {
            server,
            agent_email,
            agent_name,
            key,
        }) => enroll::run(&server, &agent_email, &agent_name, &key),
        None => run_sudo(&cli),
    };

    if let Err(e) = result {
        match &e {
            Error::Denied { decided_by, .. } => eprintln!("denied by {decided_by}"),
            Error::Timeout { secs, .. } => eprintln!("timed out after {secs}s — no approval received"),
            _ => eprintln!("{}", e.to_json()),
        }
        std::process::exit(e.exit_code());
    }
}

fn run_sudo(cli: &Cli) -> Result<(), Error> {
    if cli.cmd.is_empty() {
        return Err(Error::Config("No command specified. Usage: apes --key <path> -- <command> [args...]".into()));
    }

    let key_path = cli.key.as_ref().ok_or_else(|| {
        Error::Config("--key <path> is required. Provide the path to your agent private key.".into())
    })?;

    // 1. Load config (still root — config is root-owned)
    let config = config::Config::load(&cli.config)?;

    // 2. Drop privileges FIRST (key is user-owned)
    let real_uid = exec::drop_privileges()?;

    // 3. Load user's private key + derive public key (as real user)
    let (signing_key, public_key) = crypto::load_key_and_derive_public(key_path)?;

    // 4. Match against registered agents
    let agent = config.find_agent_by_public_key(&public_key)
        .ok_or(Error::NoMatchingAgent)?;

    // 5. Derive agent_id
    let agent_id = crypto::derive_agent_id(&public_key);

    // 6. Compute cmd_hash
    let cmd_hash = crypto::cmd_hash(&cli.cmd);

    // 7. Authenticate (challenge-response with matched agent's server)
    let agent_token = auth::authenticate(&agent.server_url, &agent_id, &signing_key)?;

    // 8. Create grant
    let target = config.effective_target();
    let grant = grants::create_grant(
        &agent.server_url,
        &agent_token,
        &target,
        &cli.cmd,
        &cmd_hash,
        cli.reason.as_deref(),
    )?;

    // 9. Poll for approval
    let server_domain = agent.server_url
        .strip_prefix("https://").or_else(|| agent.server_url.strip_prefix("http://"))
        .unwrap_or(&agent.server_url)
        .split('/').next()
        .unwrap_or(&agent.server_url);
    eprintln!("waiting for approval… (grant {})", &grant.id[..8.min(grant.id.len())]);
    eprintln!("   approve at: {server_domain}");
    let timeout = cli.timeout.unwrap_or(config.poll.timeout_secs);
    let grant = match grants::poll_grant(&agent.server_url, &agent_token, &grant.id, timeout, config.poll.interval_secs) {
        Ok(g) => g,
        Err(Error::Denied { ref grant_id, ref decided_by }) => {
            audit::log_denied(&config, &agent_id, real_uid, &cli.cmd, &cmd_hash, grant_id, decided_by);
            return Err(Error::Denied { grant_id: grant_id.clone(), decided_by: decided_by.clone() });
        }
        Err(Error::Timeout { ref grant_id, secs }) => {
            audit::log_timeout(&config, &agent_id, real_uid, &cli.cmd, &cmd_hash, grant_id, secs);
            return Err(Error::Timeout { grant_id: grant_id.clone(), secs });
        }
        Err(e) => {
            audit::log_error(&config, &agent_id, real_uid, &cli.cmd, &e.to_string());
            return Err(e);
        }
    };
    eprintln!("grant approved");

    // 10. Get authorization token
    let authz_response = match grants::get_token(&agent.server_url, &agent_token, &grant.id) {
        Ok(r) => r,
        Err(e) => {
            audit::log_error(&config, &agent_id, real_uid, &cli.cmd, &e.to_string());
            return Err(e);
        }
    };

    // 11. Verify AuthZ-JWT locally
    let claims = match jwt::verify_authz_jwt(&authz_response.authz_jwt, &agent.server_url) {
        Ok(c) => c,
        Err(e) => {
            audit::log_error(&config, &agent_id, real_uid, &cli.cmd, &e.to_string());
            return Err(e);
        }
    };

    // 12. Verify cmd_hash in JWT matches our cmd_hash
    let jwt_cmd_hash = claims.cmd_hash.as_deref().unwrap_or("");
    if jwt_cmd_hash != cmd_hash {
        let e = Error::CmdHashMismatch {
            expected: cmd_hash,
            got: jwt_cmd_hash.to_string(),
        };
        audit::log_error(&config, &agent_id, real_uid, &cli.cmd, &e.to_string());
        return Err(e);
    }

    // 13. Elevate privileges
    exec::elevate()?;

    // 14. Sanitize environment
    exec::sanitize_env();

    // 14b. Switch user (default: root; override with --run-as <user>)
    match cli.run_as.as_deref() {
        Some(user) => exec::switch_user(user)?,
        None => exec::become_root()?,
    }

    // 15. Write audit log
    audit::log_run(
        &config,
        &agent_id,
        real_uid,
        &cli.cmd,
        &cmd_hash,
        &grant,
    );

    // 16. exec the command (replaces this process)
    exec::run_command(&cli.cmd)
}
