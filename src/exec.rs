use std::ffi::CString;

use nix::unistd::{geteuid, getuid, setgid, seteuid, setuid, Uid, User};

use crate::error::Error;

/// Drop privileges from setuid-root to real user.
/// Returns the real UID for later use in audit log.
pub fn drop_privileges() -> Result<Uid, Error> {
    let real_uid = getuid();
    let effective_uid = geteuid();

    if effective_uid.is_root() {
        seteuid(real_uid)
            .map_err(|e| Error::Privilege(format!("Failed to drop privileges: {e}")))?;
    }

    Ok(real_uid)
}

/// Re-elevate to root (using saved set-user-ID from setuid bit).
pub fn elevate() -> Result<(), Error> {
    seteuid(Uid::from_raw(0))
        .map_err(|e| Error::Privilege(format!("Failed to elevate privileges: {e}")))?;
    Ok(())
}

/// Make the process fully root (real + effective UID/GID).
/// Called when no --run-as is specified — the default for privilege elevation.
pub fn become_root() -> Result<(), Error> {
    setgid(nix::unistd::Gid::from_raw(0))
        .map_err(|e| Error::Privilege(format!("Failed to setgid(0): {e}")))?;
    setuid(Uid::from_raw(0))
        .map_err(|e| Error::Privilege(format!("Failed to setuid(0): {e}")))?;
    unsafe {
        std::env::set_var("HOME", "/var/root");
        std::env::set_var("USER", "root");
        std::env::set_var("LOGNAME", "root");
    }
    Ok(())
}

/// Switch to a different user (must be called while euid is root).
/// Sets GID first, then UID (order matters — can't setgid after dropping root).
/// This is a one-way operation: the process cannot return to root.
pub fn switch_user(username: &str) -> Result<(), Error> {
    let user = User::from_name(username)
        .map_err(|e| Error::Privilege(format!("Failed to look up user '{username}': {e}")))?
        .ok_or_else(|| Error::Privilege(format!("User '{username}' not found")))?;

    // Set GID first (requires root)
    setgid(user.gid)
        .map_err(|e| Error::Privilege(format!("Failed to setgid({}): {e}", user.gid)))?;

    // Set UID (irreversible — drops root permanently)
    setuid(user.uid)
        .map_err(|e| Error::Privilege(format!("Failed to setuid({}): {e}", user.uid)))?;

    // Set HOME and USER env vars
    unsafe {
        std::env::set_var("HOME", user.dir.to_string_lossy().as_ref());
        std::env::set_var("USER", username);
        std::env::set_var("LOGNAME", username);
    }

    Ok(())
}

/// Remove dangerous environment variables before exec.
/// Preserves the caller's PATH (inherited from the invoking user).
pub fn sanitize_env() {
    // Preserve the caller's PATH before sanitizing
    let caller_path = std::env::var("PATH").ok();

    for var in [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "LD_DEBUG",
        "LD_PROFILE",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "IFS",
        "BASH_ENV",
        "ENV",
        "CDPATH",
    ] {
        // SAFETY: var names are static strings, no concurrent access concern in single-threaded context
        unsafe { std::env::remove_var(var) };
    }

    // SAFETY: Restore the caller's PATH (or fall back to a safe default)
    let path = caller_path
        .unwrap_or_else(|| "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string());
    unsafe { std::env::set_var("PATH", &path) };
}

/// Replace the current process with the given command using execvp.
pub fn run_command(cmd: &[String]) -> Result<(), Error> {
    if cmd.is_empty() {
        return Err(Error::Exec("Empty command".into()));
    }

    let program = CString::new(cmd[0].as_str())
        .map_err(|_| Error::Exec(format!("Invalid command name: {}", cmd[0])))?;

    let args: Vec<CString> = cmd
        .iter()
        .map(|a| {
            CString::new(a.as_str())
                .map_err(|_| Error::Exec(format!("Invalid argument: {a}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let arg_refs: Vec<&std::ffi::CStr> = args.iter().map(|a| a.as_c_str()).collect();

    // execvp replaces this process — if it returns, it failed
    nix::unistd::execvp(&program, &arg_refs)
        .map_err(|e| {
            if e == nix::errno::Errno::ENOENT {
                let path = std::env::var("PATH").unwrap_or_else(|_| "(unset)".to_string());
                Error::Exec(format!("Command not found: {}. PATH was: {}", cmd[0], path))
            } else {
                Error::Exec(format!("execvp failed: {e}"))
            }
        })?;

    unreachable!()
}
