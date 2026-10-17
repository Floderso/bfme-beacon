//! `Beacon.exe`: see `beacon_launcher::cli` for the commands.
//!
//! Release builds use the Windows GUI subsystem (no console window for the normal
//! start); the terminal commands attach to the parent console (or use the pipes
//! of Git Bash/mintty) so their output appears in the terminal.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![deny(unsafe_code)]

use std::io::{self, BufRead, Read};
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use beacon_launcher::app::{self, App, AppOptions, ConnectRequest};
use beacon_launcher::cli::{self, Command, Common, ConnectArgs, PasswordSource};
use beacon_launcher::config::LaunchOptions;
use beacon_launcher::game::hook::HOOK_DLL_NAME;
use beacon_launcher::instance::{self, Acquire, Action};
use beacon_launcher::paths::DataDirs;
use beacon_launcher::state::{Change, ConnectionState};
use beacon_launcher::{fingerprint, logging, sys, util};
use tokio::sync::broadcast::error::RecvError;
use tracing::{error, info, warn};

/// Exit codes.
const EXIT_FAILURE: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_LAUNCH: u8 = 3;

fn main() -> ExitCode {
    let args: Result<Vec<String>, _> = std::env::args_os().skip(1).map(|a| a.into_string()).collect();
    let parsed = args
        .map_err(|_| cli::CliError("arguments must be valid Unicode".into()))
        .and_then(|a| cli::parse(&a));
    if parsed.as_ref().map_or(true, Command::is_cli) {
        sys::attach_parent_console();
    }
    let cmd = match parsed {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}\n\n{}", cli::USAGE);
            return ExitCode::from(EXIT_USAGE);
        }
    };
    match cmd {
        Command::Version => {
            println!("Beacon {} ({})", beacon_launcher::VERSION, beacon_launcher::BUILD_ID);
            ExitCode::SUCCESS
        }
        Command::Help => {
            println!("{}", cli::USAGE);
            ExitCode::SUCCESS
        }
        Command::Detect(c) => detect(&c),
        Command::Fingerprint(c) => fingerprint_cmd(&c),
        Command::RestoreName(c) => with_runtime(restore_name(c)),
        Command::Stop(c) => with_runtime(stop(c)),
        Command::Connect(c) => {
            let password = match c.password {
                PasswordSource::Stdin => match read_password() {
                    Ok(p) => Some(p),
                    Err(e) => {
                        eprintln!("cannot read the password from stdin: {e}");
                        return ExitCode::from(EXIT_USAGE);
                    }
                },
                PasswordSource::Remembered => None,
            };
            with_runtime(connect(c, password))
        }
        Command::Run(c) => with_runtime(run_default(c)),
    }
}

fn with_runtime(fut: impl std::future::Future<Output = ExitCode>) -> ExitCode {
    match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("beacon")
        .enable_all()
        .build()
    {
        Ok(rt) => {
            let code = rt.block_on(fut);
            rt.shutdown_timeout(Duration::from_secs(2));
            code
        }
        Err(e) => {
            eprintln!("cannot start the runtime: {e}");
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

/// One line from stdin (at most 1 KiB, trailing `\r\n` removed).
fn read_password() -> io::Result<String> {
    let mut line = String::new();
    io::stdin().lock().take(1024).read_line(&mut line)?;
    let password = line.trim_end_matches(['\r', '\n']).to_owned();
    util::wipe_string(&mut line);
    if password.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty password"));
    }
    Ok(password)
}

fn data_dirs(c: &Common) -> Result<DataDirs, ExitCode> {
    DataDirs::resolve(c.data_dir.as_deref(), c.instance).map_err(|e| {
        eprintln!("{e}");
        ExitCode::from(EXIT_USAGE)
    })
}

fn hook_source(c: &Common) -> Option<std::path::PathBuf> {
    c.hook_dll.clone().or_else(|| {
        std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|d| d.join(HOOK_DLL_NAME)))
    })
}

fn options(c: &Common, data: DataDirs) -> AppOptions {
    let mut opts = AppOptions::new(data);
    opts.game_dir = c.game_dir.clone();
    opts.hook_dll = c.hook_dll.clone();
    opts.multi = c.multi;
    opts
}

fn detect(c: &Common) -> ExitCode {
    let (info, hook) = app::detect_now(c.game_dir.as_deref(), hook_source(c).as_deref());
    let found = info.exe.is_some();
    let report = serde_json::json!({
        "version": beacon_launcher::VERSION,
        "game_dir": info.game_dir,
        "source": info.source,
        "exe": info.exe,
        "user": info.user,
        "registry_leaf": info.registry_leaf,
        "registry_use_local_user_maps": info.registry_use_local_user_maps,
        "hook": hook,
        "warnings": info.warnings,
    });
    match serde_json::to_string_pretty(&report) {
        Ok(text) => println!("{text}"),
        Err(e) => eprintln!("{e}"),
    }
    if found {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_FAILURE)
    }
}

fn fingerprint_cmd(c: &Common) -> ExitCode {
    let data = match data_dirs(c) {
        Ok(d) => d,
        Err(code) => return code,
    };
    let (info, _) = app::detect_now(c.game_dir.as_deref(), None);
    let Some(game_dir) = info.game_dir.filter(|_| info.exe.is_some()) else {
        eprintln!("BFME was not found (use --game-dir)");
        return ExitCode::from(EXIT_FAILURE);
    };
    let hook = hook_source(c).filter(|p| p.is_file());
    let cancel = AtomicBool::new(false);
    let mut last = std::time::Instant::now();
    let result = fingerprint::run(&game_dir, hook.as_deref(), &data.cache_file(), &cancel, &mut |p| {
        if last.elapsed() >= Duration::from_secs(1) {
            last = std::time::Instant::now();
            eprintln!("hashing: {}/{} files, {} / {} MiB", p.files_done, p.files_total, p.bytes_done >> 20, p.bytes_total >> 20);
        }
    });
    match result {
        Ok(fp) => {
            let report = serde_json::json!({
                "game_dir": game_dir,
                "digest": fp.digest_hex,
                "short": fp.short(),
                "files": fp.entries,
            });
            match serde_json::to_string_pretty(&report) {
                Ok(text) => println!("{text}"),
                Err(e) => eprintln!("{e}"),
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("fingerprint failed: {e}");
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

async fn restore_name(c: Common) -> ExitCode {
    let data = match data_dirs(&c) {
        Ok(d) => d,
        Err(code) => return code,
    };
    logging::init(None, true, c.verbose);
    let mut opts = options(&c, data);
    opts.fingerprint = false;
    let app = match App::start(opts).await {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(EXIT_FAILURE);
        }
    };
    wait_for_detection(&app).await;
    let code = match app.restore_user_name().await {
        Ok(true) => {
            println!("BFME's original LAN name was restored");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            println!("nothing to restore (Beacon never changed the name)");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(EXIT_FAILURE)
        }
    };
    app.quit().await;
    code
}

async fn wait_for_detection(app: &App) {
    let mut rx = app.subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while app.snapshot().game.is_none() {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Ok(_) | Err(RecvError::Lagged(_))) => {}
            _ => return,
        }
    }
}

/// Acquires the instance; `Err` = another process runs it (handover attempted if
/// `hand_over`).
async fn acquire(data: &DataDirs, hand_over: bool) -> Result<instance::InstanceLock, ExitCode> {
    match instance::acquire(data) {
        Ok(Acquire::Acquired(lock)) => Ok(lock),
        Ok(Acquire::Running(info)) => {
            let pid = info.as_ref().map(|i| i.pid.to_string()).unwrap_or_else(|| "?".into());
            if hand_over {
                if let Some(info) = &info {
                    match instance::hand_over(info, Action::Activate).await {
                        Ok(()) => {
                            info!("Beacon (instance {}) is already running (pid {pid}); asked it to show itself", data.instance());
                            return Err(ExitCode::SUCCESS);
                        }
                        Err(e) => warn!("the running instance did not answer: {e}"),
                    }
                }
            }
            error!("Beacon instance {} is already running (pid {pid})", data.instance());
            Err(ExitCode::from(EXIT_FAILURE))
        }
        Err(e) => {
            error!("instance check failed: {e}");
            Err(ExitCode::from(EXIT_FAILURE))
        }
    }
}

async fn run_default(c: Common) -> ExitCode {
    let data = match data_dirs(&c) {
        Ok(d) => d,
        Err(code) => return code,
    };
    if let Some(log) = logging::init(Some(&data.logs_dir()), true, c.verbose) {
        info!("log file: {}", log.display());
    }
    let lock = match acquire(&data, true).await {
        Ok(l) => l,
        Err(code) => return code,
    };
    let app = match App::start(options(&c, data)).await {
        Ok(a) => a,
        Err(e) => {
            error!("{e}");
            return ExitCode::from(EXIT_FAILURE);
        }
    };
    let handover_app = app.clone();
    let _guard = match lock
        .publish(move |action| match action {
            Action::Activate => handover_app.activate(),
            Action::Quit => handover_app.request_quit(),
        })
        .await
    {
        Ok(g) => Some(g),
        Err(e) => {
            warn!("handover listener unavailable: {e}");
            None
        }
    };
    info!(
        "Beacon {} started; the web UI is not built yet, Beacon runs headless (Ctrl-C to quit)",
        beacon_launcher::VERSION
    );
    tokio::select! {
        what = shutdown_signal() => info!("{what}: quitting"),
        () = app.quit_requested() => {}
    }
    app.quit().await;
    ExitCode::SUCCESS
}

/// Resolves on Ctrl+C, Ctrl+Break or when the console window is closed (the
/// process has a few seconds left then).
#[cfg(windows)]
async fn shutdown_signal() -> &'static str {
    use tokio::signal::windows;
    let (mut brk, mut close) = (windows::ctrl_break().ok(), windows::ctrl_close().ok());
    tokio::select! {
        what = ctrl_c() => what,
        () = async {
            let got = match brk.as_mut() {
                Some(s) => s.recv().await.is_some(),
                None => false,
            };
            if !got {
                std::future::pending::<()>().await;
            }
        } => "Ctrl-Break",
        () = async {
            let got = match close.as_mut() {
                Some(s) => s.recv().await.is_some(),
                None => false,
            };
            if !got {
                std::future::pending::<()>().await;
            }
        } => "console closed",
    }
}

/// Resolves on Ctrl+C.
#[cfg(not(windows))]
async fn shutdown_signal() -> &'static str {
    ctrl_c().await
}

async fn ctrl_c() -> &'static str {
    match tokio::signal::ctrl_c().await {
        Ok(()) => "Ctrl-C",
        Err(e) => {
            warn!("Ctrl-C handler unavailable: {e}");
            std::future::pending().await
        }
    }
}

/// `Beacon.exe stop`: asks the running instance to quit and waits (bounded) until it
/// has exited.
async fn stop(c: Common) -> ExitCode {
    let data = match data_dirs(&c) {
        Ok(d) => d,
        Err(code) => return code,
    };
    let info = match instance::acquire(&data) {
        Ok(Acquire::Running(Some(info))) => info,
        Ok(Acquire::Running(None)) => {
            eprintln!("Beacon instance {} runs, but its running.json is unreadable", data.instance());
            return ExitCode::from(EXIT_FAILURE);
        }
        Ok(Acquire::Acquired(_)) => {
            println!("Beacon instance {} is not running", data.instance());
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("instance check failed: {e}");
            return ExitCode::from(EXIT_FAILURE);
        }
    };
    if let Err(e) = instance::hand_over(&info, Action::Quit).await {
        eprintln!("the running instance (pid {}) did not accept the request: {e}", info.pid);
        return ExitCode::from(EXIT_FAILURE);
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if let Ok(Acquire::Acquired(_)) = instance::acquire(&data) {
            println!("Beacon (pid {}) has quit", info.pid);
            return ExitCode::SUCCESS;
        }
    }
    eprintln!("Beacon (pid {}) is still running", info.pid);
    ExitCode::from(EXIT_FAILURE)
}

async fn connect(c: ConnectArgs, password: Option<String>) -> ExitCode {
    let data = match data_dirs(&c.common) {
        Ok(d) => d,
        Err(code) => return code,
    };
    if let Some(log) = logging::init(Some(&data.logs_dir()), true, c.common.verbose) {
        info!("log file: {}", log.display());
    }
    let lock = match acquire(&data, false).await {
        Ok(l) => l,
        Err(code) => return code,
    };
    let mut opts = options(&c.common, data);
    if c.windowed || c.xres.is_some() || c.yres.is_some() {
        opts.launch = Some(LaunchOptions {
            windowed: c.windowed,
            xres: c.xres,
            yres: c.yres,
            noshellmap: true,
        });
    }
    let app = match App::start(opts).await {
        Ok(a) => a,
        Err(e) => {
            error!("{e}");
            return ExitCode::from(EXIT_FAILURE);
        }
    };
    let handover_app = app.clone();
    let _guard = lock
        .publish(move |action| {
            if action == Action::Quit {
                handover_app.request_quit();
            }
        })
        .await
        .ok();
    let (port, _) = app.agent_endpoint();
    info!("agent on 127.0.0.1:{port}");
    let mut changes = app.subscribe();
    let request = ConnectRequest {
        server: c.server.clone(),
        name: c.name.clone(),
        password,
        use_remembered: c.password == PasswordSource::Remembered,
        remember: c.remember,
    };
    if let Err(e) = app.connect(request).await {
        error!("{e}");
        app.quit().await;
        return ExitCode::from(EXIT_USAGE);
    }
    let mut launch_pending = c.launch;
    let mut summary = tokio::time::interval(Duration::from_secs(30));
    summary.tick().await;
    let code = loop {
        tokio::select! {
            what = shutdown_signal() => {
                info!("{what}: disconnecting");
                break ExitCode::SUCCESS;
            }
            ev = changes.recv() => {
                match ev {
                    Ok(Change::Connection | Change::Game) | Err(RecvError::Lagged(_)) => {}
                    Ok(Change::Quit) | Err(RecvError::Closed) => break ExitCode::SUCCESS,
                    Ok(_) => continue,
                }
                let st = app.snapshot();
                if let ConnectionState::Failed { message, .. } = &st.connection {
                    error!("{message}");
                    break ExitCode::from(EXIT_FAILURE);
                }
                if launch_pending && st.is_connected() && st.game.is_some() {
                    launch_pending = false;
                    if let Err(e) = app.launch_game().await {
                        error!("{e}");
                        break ExitCode::from(EXIT_LAUNCH);
                    }
                }
            }
            _ = summary.tick() => {
                let s = app.agent_stats();
                info!(
                    "status: rtt {:?} ms, loss {:?} %, sent {} (+{} copies), received {}, delivered {} (+{} local), vports {:?}",
                    s.rtt_ms, s.loss_pct, s.data_sent, s.copies_sent, s.data_received, s.delivered,
                    s.delivered_local, s.registrations.iter().map(|r| r.vport).collect::<Vec<_>>()
                );
            }
        }
    };
    app.quit().await;
    code
}
