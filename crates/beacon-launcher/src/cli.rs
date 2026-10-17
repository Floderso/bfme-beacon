//! Hand-written command-line parser (no dependencies).
//!
//! ```text
//! Beacon.exe [OPTIONS]                       start the app (default mode)
//! Beacon.exe connect --server HOST[:PORT] --name NAME (--password-stdin | --remembered)
//!            [--remember] [--launch] [--windowed] [--xres W] [--yres H] [OPTIONS]
//! Beacon.exe detect [OPTIONS]                JSON: game folder, exe identity, user dir, hook
//! Beacon.exe fingerprint [OPTIONS]           JSON: game-data fingerprint and file list
//! Beacon.exe restore-name [OPTIONS]          restore BFME's original LAN name
//! Beacon.exe stop [OPTIONS]                  ask the running instance to quit
//! Beacon.exe version | help
//!
//! OPTIONS: --instance N  --multi  --data-dir DIR  --game-dir DIR  --hook-dll PATH  -v/--verbose
//! ```
//! Values may follow as the next argument or after `=` (`--name=Bob`).

use std::fmt;
use std::path::PathBuf;

use crate::config::RES_RANGE;
use crate::paths::MAX_INSTANCE;

/// Options shared by the commands.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Common {
    /// `--instance N` (1 = default).
    pub instance: u32,
    /// `--multi`: test mode.
    pub multi: bool,
    /// `--data-dir DIR`.
    pub data_dir: Option<PathBuf>,
    /// `--game-dir DIR`.
    pub game_dir: Option<PathBuf>,
    /// `--hook-dll PATH`.
    pub hook_dll: Option<PathBuf>,
    /// `-v` / `--verbose`: debug logging.
    pub verbose: bool,
}

/// Where the password comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordSource {
    /// One line on stdin.
    Stdin,
    /// The remembered key.
    Remembered,
}

/// `connect` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectArgs {
    /// Shared options.
    pub common: Common,
    /// `--server HOST[:PORT]`.
    pub server: String,
    /// `--name NAME`.
    pub name: String,
    /// `--password-stdin` / `--remembered`.
    pub password: PasswordSource,
    /// `--remember`: store the key (DPAPI) after login.
    pub remember: bool,
    /// `--launch`: start BFME once connected.
    pub launch: bool,
    /// `--windowed`.
    pub windowed: bool,
    /// `--xres W`.
    pub xres: Option<u32>,
    /// `--yres H`.
    pub yres: Option<u32>,
}

/// A parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Default mode.
    Run(Common),
    /// Headless session.
    Connect(ConnectArgs),
    /// Detection report.
    Detect(Common),
    /// Fingerprint report.
    Fingerprint(Common),
    /// Restore the BFME LAN name.
    RestoreName(Common),
    /// Ask the running instance (of `--instance`/`--data-dir`) to quit.
    Stop(Common),
    /// Version.
    Version,
    /// Usage.
    Help,
}

impl Command {
    /// `true` for the terminal commands (everything but the default mode).
    pub fn is_cli(&self) -> bool {
        !matches!(self, Self::Run(_))
    }
}

/// A usage error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError(pub String);

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CliError {}

/// Usage text.
pub const USAGE: &str = "\
BFME Beacon launcher

Usage:
  Beacon.exe [OPTIONS]                         start Beacon
  Beacon.exe connect --server HOST[:PORT] --name NAME (--password-stdin | --remembered)
             [--remember] [--launch] [--windowed] [--xres W] [--yres H] [OPTIONS]
                                               headless session, logs to stdout until Ctrl-C
  Beacon.exe detect [OPTIONS]                  game folder, exe identity, user folder, hook (JSON)
  Beacon.exe fingerprint [OPTIONS]             game-data fingerprint (JSON)
  Beacon.exe restore-name [OPTIONS]            restore BFME's original LAN name
  Beacon.exe stop [OPTIONS]                    ask the running instance to quit (for scripts)
  Beacon.exe version | help

Options:
  --instance N      instance 1..=8 (N >= 2: own data folder and test mode)
  --multi           test mode (two BFME instances on one PC)
  --data-dir DIR    data folder (default %APPDATA%\\Beacon)
  --game-dir DIR    BFME folder (default: registry InstallPath)
  --hook-dll PATH   wsock32.dll to install (default: next to Beacon.exe)
  -v, --verbose     debug logging
";

struct Args<'a> {
    items: &'a [String],
    pos: usize,
}

impl<'a> Args<'a> {
    /// Next option name and inline value (`--x=v`).
    fn next(&mut self) -> Option<(&'a str, Option<&'a str>)> {
        let item = self.items.get(self.pos)?;
        self.pos += 1;
        Some(match item.split_once('=') {
            Some((k, v)) if k.starts_with("--") => (k, Some(v)),
            _ => (item.as_str(), None),
        })
    }

    fn value(&mut self, name: &str, inline: Option<&'a str>) -> Result<&'a str, CliError> {
        if let Some(v) = inline {
            return Ok(v);
        }
        let v = self
            .items
            .get(self.pos)
            .ok_or_else(|| CliError(format!("{name} needs a value")))?;
        self.pos += 1;
        Ok(v)
    }
}

fn number(name: &str, v: &str) -> Result<u32, CliError> {
    v.parse::<u32>()
        .map_err(|_| CliError(format!("{name}: {v:?} is not a number")))
}

fn flag(name: &str, inline: Option<&str>) -> Result<(), CliError> {
    match inline {
        None => Ok(()),
        Some(_) => Err(CliError(format!("{name} takes no value"))),
    }
}

/// Parses the arguments after the program name.
pub fn parse(args: &[String]) -> Result<Command, CliError> {
    let (sub, rest) = match args.first().map(String::as_str) {
        Some(s) if !s.starts_with('-') => (s, args.get(1..).unwrap_or_default()),
        _ => ("", args),
    };
    match sub {
        "version" | "--version" => return Ok(Command::Version),
        "help" | "--help" | "-h" | "/?" => return Ok(Command::Help),
        "" | "connect" | "detect" | "fingerprint" | "restore-name" | "stop" => {}
        other => return Err(CliError(format!("unknown command {other:?} (see `Beacon.exe help`)"))),
    }
    if rest.iter().any(|a| a == "--help" || a == "-h") {
        return Ok(Command::Help);
    }
    let mut common = Common {
        instance: 1,
        ..Common::default()
    };
    let mut server = None;
    let mut name = None;
    let mut password = None;
    let (mut remember, mut launch, mut windowed) = (false, false, false);
    let (mut xres, mut yres) = (None, None);
    let connect = sub == "connect";
    let mut it = Args { items: rest, pos: 0 };
    while let Some((opt, inline)) = it.next() {
        match opt {
            "--instance" => {
                let n = number(opt, it.value(opt, inline)?)?;
                if !(1..=MAX_INSTANCE).contains(&n) {
                    return Err(CliError(format!("--instance must be 1..={MAX_INSTANCE}")));
                }
                common.instance = n;
            }
            "--multi" => {
                flag(opt, inline)?;
                common.multi = true;
            }
            "--data-dir" => common.data_dir = Some(PathBuf::from(it.value(opt, inline)?)),
            "--game-dir" => common.game_dir = Some(PathBuf::from(it.value(opt, inline)?)),
            "--hook-dll" => common.hook_dll = Some(PathBuf::from(it.value(opt, inline)?)),
            "-v" | "--verbose" => {
                flag(opt, inline)?;
                common.verbose = true;
            }
            "--server" if connect => server = Some(it.value(opt, inline)?.to_owned()),
            "--name" if connect => name = Some(it.value(opt, inline)?.to_owned()),
            "--password-stdin" | "--remembered" if connect => {
                flag(opt, inline)?;
                let src = if opt == "--remembered" {
                    PasswordSource::Remembered
                } else {
                    PasswordSource::Stdin
                };
                if password.replace(src).is_some_and(|old| old != src) {
                    return Err(CliError("use either --password-stdin or --remembered".into()));
                }
            }
            "--remember" if connect => {
                flag(opt, inline)?;
                remember = true;
            }
            "--launch" if connect => {
                flag(opt, inline)?;
                launch = true;
            }
            "--windowed" if connect => {
                flag(opt, inline)?;
                windowed = true;
            }
            "--xres" | "--yres" if connect => {
                let v = number(opt, it.value(opt, inline)?)?;
                if !RES_RANGE.contains(&v) {
                    return Err(CliError(format!(
                        "{opt} must be {}..={}",
                        RES_RANGE.start(),
                        RES_RANGE.end()
                    )));
                }
                if opt == "--xres" {
                    xres = Some(v);
                } else {
                    yres = Some(v);
                }
            }
            other => {
                return Err(CliError(format!(
                    "unknown option {other:?}{}",
                    if sub.is_empty() { String::new() } else { format!(" for `{sub}`") }
                )))
            }
        }
    }
    for p in [&common.data_dir, &common.game_dir, &common.hook_dll].into_iter().flatten() {
        if !p.is_absolute() {
            return Err(CliError(format!("{} must be an absolute path", p.display())));
        }
    }
    Ok(match sub {
        "connect" => Command::Connect(ConnectArgs {
            common,
            server: server.ok_or_else(|| CliError("connect needs --server HOST[:PORT]".into()))?,
            name: name.ok_or_else(|| CliError("connect needs --name NAME".into()))?,
            password: password.ok_or_else(|| CliError("connect needs --password-stdin or --remembered".into()))?,
            remember,
            launch,
            windowed,
            xres,
            yres,
        }),
        "detect" => Command::Detect(common),
        "fingerprint" => Command::Fingerprint(common),
        "restore-name" => Command::RestoreName(common),
        "stop" => Command::Stop(common),
        _ => Command::Run(common),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Command, CliError> {
        parse(&args.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
    }

    #[test]
    fn default_and_simple_commands() {
        assert_eq!(p(&[]).unwrap(), Command::Run(Common { instance: 1, ..Common::default() }));
        assert_eq!(p(&["version"]).unwrap(), Command::Version);
        let Command::Stop(c) = p(&["stop", "--instance", "2"]).unwrap() else { panic!() };
        assert_eq!(c.instance, 2);
        assert_eq!(p(&["--help"]).unwrap(), Command::Help);
        assert_eq!(p(&["connect", "-h"]).unwrap(), Command::Help);
        let Command::Detect(c) = p(&["detect", "--game-dir", r"C:\BFME1", "-v"]).unwrap() else {
            panic!()
        };
        assert_eq!(c.game_dir, Some(PathBuf::from(r"C:\BFME1")));
        assert!(c.verbose);
        let Command::Run(c) = p(&["--instance=2", "--multi", r"--data-dir=D:\b"]).unwrap() else {
            panic!()
        };
        assert_eq!((c.instance, c.multi), (2, true));
        assert_eq!(c.data_dir, Some(PathBuf::from(r"D:\b")));
    }

    #[test]
    fn connect_command() {
        let cmd = p(&[
            "connect", "--server", "home.example.org:28086", "--name=Bob", "--password-stdin", "--launch",
            "--windowed", "--xres", "1280", "--yres=720", "--instance", "2", "--hook-dll", r"C:\x\wsock32.dll",
        ])
        .unwrap();
        let Command::Connect(c) = cmd else { panic!() };
        assert_eq!(c.server, "home.example.org:28086");
        assert_eq!(c.name, "Bob");
        assert_eq!(c.password, PasswordSource::Stdin);
        assert!(c.launch && c.windowed && !c.remember);
        assert_eq!((c.xres, c.yres), (Some(1280), Some(720)));
        assert_eq!(c.common.instance, 2);
        assert!(p(&["connect", "--server", "x", "--name", "a", "--remembered", "--remember"]).is_ok());
    }

    #[test]
    fn usage_errors() {
        for bad in [
            &["frobnicate"][..],
            &["connect", "--name", "a", "--password-stdin"],
            &["connect", "--server", "x", "--password-stdin"],
            &["connect", "--server", "x", "--name", "a"],
            &["connect", "--server", "x", "--name", "a", "--password-stdin", "--remembered"],
            &["connect", "--server"],
            &["connect", "--server", "x", "--name", "a", "--remembered", "--xres", "99"],
            &["--instance", "0"],
            &["--instance", "9"],
            &["--instance", "x"],
            &["--multi=1"],
            &["--launch"],
            &["detect", "--server", "x"],
            &["--data-dir", "relative"],
            &["--bogus"],
        ] {
            assert!(p(bad).is_err(), "{bad:?}");
        }
        assert!(p(&["--bogus"]).unwrap_err().to_string().contains("--bogus"));
    }
}
