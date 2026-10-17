//! `beacon-server` binary: see `beacon-server help`.

#![forbid(unsafe_code)]

use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use beacon_server::cli::{self, Command};
use beacon_server::config::{self, Config, ConfigError};
use beacon_server::{health, server};
use tracing::level_filters::LevelFilter;

fn main() -> ExitCode {
    let command = match cli::parse(std::env::args_os().skip(1)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("beacon-server: {e}\n\n{}", cli::USAGE);
            return ExitCode::from(2);
        }
    };
    match command {
        Command::Help => {
            print!("{}", cli::USAGE);
            ExitCode::SUCCESS
        }
        Command::Version => {
            println!("beacon-server {}", beacon_server::VERSION);
            ExitCode::SUCCESS
        }
        Command::InitConfig { path, force } => init_config(&config::config_path(path), force),
        Command::SetPassword {
            config,
            password_stdin,
        } => set_password(&config::config_path(config), password_stdin),
        Command::Health { addr, config } => health_check(addr, config),
        Command::Run { config } => run(&config::config_path(config)),
    }
}

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("beacon-server: {msg}");
    ExitCode::FAILURE
}

fn init_config(path: &Path, force: bool) -> ExitCode {
    match config::write_example(path, force) {
        Ok(()) => {
            if path.as_os_str() != "-" {
                eprintln!(
                    "Wrote {}. Next: beacon-server set-password --config {}",
                    path.display(),
                    path.display()
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => fail(e),
    }
}

fn read_line_from_stdin() -> Result<String, String> {
    let mut line = String::new();
    io::stdin()
        .lock()
        .take(config::MAX_PASSWORD_LEN as u64 + 2)
        .read_line(&mut line)
        .map_err(|e| format!("cannot read the password: {e}"))?;
    let line = line.strip_suffix('\n').unwrap_or(&line);
    let line = line.strip_suffix('\r').unwrap_or(line);
    Ok(line.to_owned())
}

fn read_password(from_stdin: bool) -> Result<String, String> {
    if from_stdin {
        let password = read_line_from_stdin()?;
        if password.is_empty() {
            return Err("no password on stdin".to_owned());
        }
        return Ok(password);
    }
    if io::stdin().is_terminal() {
        eprintln!("Note: the input is visible. To avoid that, pipe it in with --password-stdin.");
    }
    eprint!("New server password: ");
    let _ = io::stderr().flush();
    let first = read_line_from_stdin()?;
    eprint!("Repeat the password: ");
    let _ = io::stderr().flush();
    let second = read_line_from_stdin()?;
    if first != second {
        return Err("the passwords do not match".to_owned());
    }
    Ok(first)
}

fn set_password(path: &Path, from_stdin: bool) -> ExitCode {
    let password = match read_password(from_stdin) {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    if let Err(e) = config::validate_password(&password) {
        return fail(e);
    }
    match config::set_password_file(path, &password) {
        Ok(()) => {
            eprintln!(
                "Password set in {} (random salt + derived key; the password itself is not stored).\n\
                 Restart the server to apply it, and tell your players the new password.",
                path.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(e),
    }
}

fn health_check(addr: Option<String>, config_arg: Option<PathBuf>) -> ExitCode {
    let target = match addr {
        Some(a) => match health::resolve(&a) {
            Ok(t) => t,
            Err(e) => return fail(e),
        },
        None => {
            let path = config::config_path(config_arg);
            match Config::load(&path) {
                Ok(cfg) => match config::status_addr_of(&cfg) {
                    Ok(Some(bind)) => health::probe_addr(bind),
                    Ok(None) => return fail("the status endpoint is disabled (status_bind = \"\")"),
                    Err(e) => return fail(e),
                },
                Err(ConfigError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                    health::DEFAULT_ADDR
                }
                Err(e) => return fail(e),
            }
        }
    };
    match health::check(target, Duration::from_secs(3)) {
        Ok(()) => {
            println!("ok");
            ExitCode::SUCCESS
        }
        Err(e) => fail(format!("unhealthy ({target}): {e}")),
    }
}

fn init_logging(level: LevelFilter) {
    let _ = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(io::stderr)
        .try_init();
}

fn run(path: &Path) -> ExitCode {
    let cfg = match Config::load(path) {
        Ok(c) => c,
        Err(e) => {
            if let ConfigError::Io { source, .. } = &e {
                if source.kind() == io::ErrorKind::NotFound {
                    return fail(format!(
                        "{e}\nCreate one with `beacon-server init-config {}`.",
                        path.display()
                    ));
                }
            }
            return fail(e);
        }
    };
    let settings = match cfg.into_settings(&config::base_dir_of(path)) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    let level = std::env::var(config::LOG_LEVEL_ENV)
        .ok()
        .and_then(|v| config::parse_level(&v))
        .unwrap_or(settings.log_level);
    init_logging(level);
    tracing::info!(config = %path.display(), "beacon-server {} starting", beacon_server::VERSION);
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("beacon")
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return fail(format!("cannot start the async runtime: {e}")),
    };
    let result = runtime.block_on(server::run_until_signal(settings));
    runtime.shutdown_timeout(Duration::from_secs(2));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::FAILURE
        }
    }
}
