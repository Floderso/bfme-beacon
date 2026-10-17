//! beacon-hook-harness: loads the built 32-bit `wsock32.dll` (beacon-hook) by full
//! path, resolves its exports with `GetProcAddress` and replays BFME's socket
//! sequence against a fake agent (architecture §12.3). Every scenario runs in a
//! fresh child process because the hook reads its environment once in `DllMain`.
//!
//! ```text
//! beacon-hook-harness [--dll <path\to\wsock32.dll>]
//! ```
//!
//! Default DLL: `<target>\i686-pc-windows-gnullvm\release-hook\wsock32.dll` next to
//! this exe's profile directory (or `BEACON_HOOK_DLL`). Exit code 0 = all passed.
//! `BEACON_HARNESS_KEEP=1` keeps the scenario logs in `%TEMP%`.

#[cfg(windows)]
mod agent;
#[cfg(windows)]
mod scenarios;
#[cfg(windows)]
mod win;

use std::process::ExitCode;

#[cfg(not(windows))]
fn main() -> ExitCode {
    eprintln!("beacon-hook-harness runs on Windows only");
    ExitCode::FAILURE
}

#[cfg(windows)]
fn main() -> ExitCode {
    imp::main()
}

#[cfg(windows)]
mod imp {
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitCode};

    use crate::scenarios::{self, Checks};

    type Scenario = fn(&mut Checks, &Path) -> Result<(), String>;

    const SCENARIOS: [(&str, Scenario); 5] = [
        ("passive", scenarios::passive),
        ("armed", scenarios::armed),
        ("multi", scenarios::multi),
        ("not-the-game", scenarios::not_the_game),
        ("bad-config", scenarios::bad_config),
    ];

    fn default_dll() -> Option<PathBuf> {
        if let Some(p) = std::env::var_os("BEACON_HOOK_DLL") {
            return Some(PathBuf::from(p));
        }
        // <target>\i686-pc-windows-gnullvm\<profile>\beacon-hook-harness.exe
        let exe = std::env::current_exe().ok()?;
        let triple_dir = exe.parent()?.parent()?;
        Some(triple_dir.join("release-hook").join("wsock32.dll"))
    }

    pub fn main() -> ExitCode {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let mut dll = None;
        let mut child = None;
        let mut it = args.iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--dll" => dll = it.next().map(PathBuf::from),
                "--child" => child = it.next().cloned(),
                other => {
                    eprintln!("unknown argument {other:?}; usage: beacon-hook-harness [--dll <wsock32.dll>]");
                    return ExitCode::from(2);
                }
            }
        }
        let Some(dll) = dll.or_else(default_dll) else {
            eprintln!("cannot determine the DLL path; pass --dll");
            return ExitCode::from(2);
        };
        let dll = std::fs::canonicalize(&dll).unwrap_or(dll);
        match child {
            Some(name) => run_child(&name, &dll),
            None => run_all(&dll),
        }
    }

    fn run_child(name: &str, dll: &Path) -> ExitCode {
        let Some((scenario, run)) = SCENARIOS.iter().find(|(n, _)| *n == name) else {
            eprintln!("unknown scenario {name}");
            return ExitCode::from(2);
        };
        let mut checks = Checks::new(scenario);
        if let Err(e) = run(&mut checks, dll) {
            checks.ok(false, format_args!("setup: {e}"));
        }
        if checks.summary() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        }
    }

    fn run_all(dll: &Path) -> ExitCode {
        if !cfg!(target_arch = "x86") {
            eprintln!("build the harness for i686-pc-windows-gnullvm: the hook DLL is 32-bit");
            return ExitCode::from(2);
        }
        if !dll.is_file() {
            eprintln!("{} not found (build it with `cargo hook`)", dll.display());
            return ExitCode::from(2);
        }
        println!("beacon-hook-harness: {}", dll.display());
        let Ok(exe) = std::env::current_exe() else {
            eprintln!("current_exe unavailable");
            return ExitCode::FAILURE;
        };
        let mut failed = Vec::new();
        for (name, _) in SCENARIOS {
            println!("scenario {name}");
            let mut cmd = Command::new(&exe);
            cmd.arg("--child").arg(name).arg("--dll").arg(dll);
            for (key, _) in std::env::vars_os() {
                let upper = key.to_string_lossy().to_ascii_uppercase();
                if upper.starts_with("BEACON_") && upper != "BEACON_HARNESS_KEEP" {
                    cmd.env_remove(key);
                }
            }
            match cmd.status() {
                Ok(status) if status.success() => {}
                Ok(status) => {
                    println!("  scenario {name} FAILED ({status})");
                    failed.push(name);
                }
                Err(e) => {
                    println!("  scenario {name} could not start: {e}");
                    failed.push(name);
                }
            }
        }
        if failed.is_empty() {
            println!("all {} scenarios passed", SCENARIOS.len());
            ExitCode::SUCCESS
        } else {
            println!("FAILED scenarios: {}", failed.join(", "));
            ExitCode::FAILURE
        }
    }
}
