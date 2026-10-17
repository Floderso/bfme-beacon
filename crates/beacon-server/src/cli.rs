//! Command-line parsing (no external parser: a handful of subcommands and options).

use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

/// Usage text printed by `help` and after a usage error.
pub const USAGE: &str = "\
beacon-server - BFME Beacon home server (lobby, relay, maps)

USAGE:
    beacon-server [run] [--config PATH]
    beacon-server init-config [PATH] [--force]
    beacon-server set-password [--config PATH] [--password-stdin]
    beacon-server health [--addr HOST:PORT] [--config PATH]
    beacon-server version
    beacon-server help

COMMANDS:
    run            Start the server (default).
    init-config    Write a commented example configuration (default PATH: config.toml,
                   '-' prints it). Refuses to overwrite without --force.
    set-password   Read a new server password and store a random salt plus the derived
                   key in the config (the password itself is never stored).
                   --password-stdin reads one line from stdin without prompting.
    health         Exit 0 if the status endpoint answers GET /health with \"ok\".
                   Address: --addr, else status_bind from the config, else 127.0.0.1:28087.
    version        Print the version.

The config path defaults to $BEACON_CONFIG, else ./config.toml.
";

/// A parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Run the server.
    Run {
        /// `--config`.
        config: Option<PathBuf>,
    },
    /// Write the example configuration.
    InitConfig {
        /// Target path (`-` = stdout).
        path: Option<PathBuf>,
        /// Overwrite an existing file.
        force: bool,
    },
    /// Set the server password.
    SetPassword {
        /// `--config`.
        config: Option<PathBuf>,
        /// Read the password from stdin without prompting.
        password_stdin: bool,
    },
    /// Probe the status endpoint.
    Health {
        /// `--addr`.
        addr: Option<String>,
        /// `--config`.
        config: Option<PathBuf>,
    },
    /// Print the version.
    Version,
    /// Print the usage.
    Help,
}

/// A usage error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    /// Unknown subcommand.
    UnknownCommand(String),
    /// Option not valid for the subcommand.
    UnknownOption(String),
    /// An option is missing its value.
    MissingValue(String),
    /// A positional argument that the subcommand does not take.
    UnexpectedArgument(String),
    /// An argument is not valid UTF-8.
    NotUnicode,
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCommand(c) => write!(f, "unknown command '{c}'"),
            Self::UnknownOption(o) => write!(f, "unknown option '{o}'"),
            Self::MissingValue(o) => write!(f, "option '{o}' needs a value"),
            Self::UnexpectedArgument(a) => write!(f, "unexpected argument '{a}'"),
            Self::NotUnicode => f.write_str("arguments must be valid UTF-8"),
        }
    }
}

impl std::error::Error for CliError {}

/// Options seen on the command line (validated per subcommand afterwards).
#[derive(Default)]
struct Opts {
    config: Option<PathBuf>,
    addr: Option<String>,
    force: bool,
    password_stdin: bool,
    positional: Vec<String>,
    seen: Vec<&'static str>,
}

/// Parses the arguments after the program name.
pub fn parse<I: IntoIterator<Item = OsString>>(args: I) -> Result<Command, CliError> {
    let args = args
        .into_iter()
        .map(|a| a.into_string().map_err(|_| CliError::NotUnicode))
        .collect::<Result<Vec<String>, CliError>>()?;
    let mut iter = args.into_iter().peekable();
    let sub = match iter.peek().map(String::as_str) {
        Some("-h" | "--help") => return Ok(Command::Help),
        Some("-V" | "--version") => return Ok(Command::Version),
        Some(s) if !s.starts_with('-') => iter.next(),
        _ => None,
    };

    let mut opts = Opts::default();
    while let Some(arg) = iter.next() {
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n.to_owned(), Some(v.to_owned())),
            _ => (arg.clone(), None),
        };
        match name.as_str() {
            "-c" | "--config" => {
                let value = take_value(&name, inline, &mut iter)?;
                opts.config = Some(PathBuf::from(value));
                opts.seen.push("config");
            }
            "--addr" => {
                opts.addr = Some(take_value(&name, inline, &mut iter)?);
                opts.seen.push("addr");
            }
            "-f" | "--force" if inline.is_none() => {
                opts.force = true;
                opts.seen.push("force");
            }
            "--password-stdin" if inline.is_none() => {
                opts.password_stdin = true;
                opts.seen.push("password-stdin");
            }
            "-h" | "--help" => return Ok(Command::Help),
            "-" => opts.positional.push(arg),
            _ if name.starts_with('-') => return Err(CliError::UnknownOption(arg)),
            _ => opts.positional.push(arg),
        }
    }

    let allow = |allowed: &[&str], opts: &Opts| -> Result<(), CliError> {
        match opts.seen.iter().find(|s| !allowed.contains(s)) {
            Some(bad) => Err(CliError::UnknownOption(format!("--{bad}"))),
            None => Ok(()),
        }
    };
    let no_positional = |opts: &Opts| -> Result<(), CliError> {
        match opts.positional.first() {
            Some(p) => Err(CliError::UnexpectedArgument(p.clone())),
            None => Ok(()),
        }
    };

    match sub.as_deref() {
        None | Some("run") => {
            allow(&["config"], &opts)?;
            no_positional(&opts)?;
            Ok(Command::Run {
                config: opts.config,
            })
        }
        Some("init-config") => {
            allow(&["force"], &opts)?;
            let mut positional = opts.positional.into_iter();
            let path = positional.next().map(PathBuf::from);
            if let Some(extra) = positional.next() {
                return Err(CliError::UnexpectedArgument(extra));
            }
            Ok(Command::InitConfig {
                path,
                force: opts.force,
            })
        }
        Some("set-password") => {
            allow(&["config", "password-stdin"], &opts)?;
            no_positional(&opts)?;
            Ok(Command::SetPassword {
                config: opts.config,
                password_stdin: opts.password_stdin,
            })
        }
        Some("health") => {
            allow(&["config", "addr"], &opts)?;
            no_positional(&opts)?;
            Ok(Command::Health {
                addr: opts.addr,
                config: opts.config,
            })
        }
        Some("version") => {
            allow(&[], &opts)?;
            no_positional(&opts)?;
            Ok(Command::Version)
        }
        Some("help") => Ok(Command::Help),
        Some(other) => Err(CliError::UnknownCommand(other.to_owned())),
    }
}

fn take_value(
    name: &str,
    inline: Option<String>,
    iter: &mut impl Iterator<Item = String>,
) -> Result<String, CliError> {
    match inline {
        Some(v) if !v.is_empty() => Ok(v),
        Some(_) => Err(CliError::MissingValue(name.to_owned())),
        None => iter
            .next()
            .ok_or_else(|| CliError::MissingValue(name.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Command, CliError> {
        parse(args.iter().map(OsString::from))
    }

    #[test]
    fn default_is_run() {
        assert_eq!(p(&[]), Ok(Command::Run { config: None }));
        assert_eq!(
            p(&["--config", "x.toml"]),
            Ok(Command::Run {
                config: Some("x.toml".into())
            })
        );
        assert_eq!(
            p(&["run", "--config=/etc/b.toml"]),
            Ok(Command::Run {
                config: Some("/etc/b.toml".into())
            })
        );
        assert_eq!(
            p(&["run", "-c", "a"]),
            Ok(Command::Run {
                config: Some("a".into())
            })
        );
    }

    #[test]
    fn subcommands() {
        assert_eq!(
            p(&["init-config"]),
            Ok(Command::InitConfig {
                path: None,
                force: false
            })
        );
        assert_eq!(
            p(&["init-config", "-", "--force"]),
            Ok(Command::InitConfig {
                path: Some("-".into()),
                force: true
            })
        );
        assert_eq!(
            p(&["set-password", "--password-stdin", "--config", "c.toml"]),
            Ok(Command::SetPassword {
                config: Some("c.toml".into()),
                password_stdin: true
            })
        );
        assert_eq!(
            p(&["health", "--addr", "127.0.0.1:1"]),
            Ok(Command::Health {
                addr: Some("127.0.0.1:1".into()),
                config: None
            })
        );
        assert_eq!(p(&["version"]), Ok(Command::Version));
        assert_eq!(p(&["--version"]), Ok(Command::Version));
        assert_eq!(p(&["help"]), Ok(Command::Help));
        assert_eq!(p(&["-h"]), Ok(Command::Help));
        assert_eq!(p(&["run", "--help"]), Ok(Command::Help));
    }

    #[test]
    fn errors() {
        assert_eq!(p(&["bogus"]), Err(CliError::UnknownCommand("bogus".into())));
        assert_eq!(p(&["run", "--nope"]), Err(CliError::UnknownOption("--nope".into())));
        assert_eq!(p(&["run", "--config"]), Err(CliError::MissingValue("--config".into())));
        assert_eq!(p(&["run", "--config="]), Err(CliError::MissingValue("--config".into())));
        assert_eq!(p(&["run", "extra"]), Err(CliError::UnexpectedArgument("extra".into())));
        assert_eq!(p(&["version", "--force"]), Err(CliError::UnknownOption("--force".into())));
        assert_eq!(p(&["run", "--addr", "x"]), Err(CliError::UnknownOption("--addr".into())));
        assert_eq!(
            p(&["init-config", "a", "b"]),
            Err(CliError::UnexpectedArgument("b".into()))
        );
        assert_eq!(
            p(&["set-password", "--password-stdin=yes"]),
            Err(CliError::UnknownOption("--password-stdin=yes".into()))
        );
    }
}
