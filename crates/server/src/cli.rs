//! The handful of arguments this binary takes.
//!
//! Configuration is environment variables, and that is not changing — these are the things
//! that cannot be one: asking the build what it is, producing the argon2 hash that an env
//! variable then holds, pointing at the file the variables come from, and registering the
//! Windows service that will pass that same file back on the command line.
//!
//! Hand-rolled rather than a parser crate, because the whole surface is six flags and one
//! of them is `--help`.

use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;

use anyhow::{bail, Result};

/// What the process was asked to do. Everything but [`Command::Serve`] prints something
/// and exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Serve,
    Version,
    Help,
    HashPassword,
    #[cfg(windows)]
    ServiceInstall,
    #[cfg(windows)]
    ServiceUninstall,
}

/// The parsed command line.
#[derive(Debug, Clone)]
pub struct Args {
    pub command: Command,
    /// `--env-file`. Read into the environment before config, and on Windows also written
    /// into the service's command line by `--service-install`.
    pub env_file: Option<PathBuf>,
}

impl Args {
    /// Parse arguments, excluding the program name.
    ///
    /// The informational flags win over everything: `--help` is the answer to a command
    /// line that also asks for something else, since the reason to type both is not
    /// knowing what the other one does.
    pub fn parse<I, S>(args: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
        let as_str: Vec<String> = args.iter().map(|a| a.to_string_lossy().into()).collect();

        let mut command = None;
        let mut env_file = None;
        let mut i = 0;
        while i < as_str.len() {
            let arg = as_str[i].as_str();
            let mut set = |c: Command| -> Result<()> {
                match command {
                    // Help is not a command that competes; it is the answer to a command
                    // line somebody is unsure about, which is exactly the one that names
                    // two things at once.
                    _ if c == Command::Help => {
                        command = Some(Command::Help);
                        Ok(())
                    }
                    Some(Command::Help) => Ok(()),
                    Some(existing) if existing != c => {
                        bail!("{arg} cannot be combined with the other command given")
                    }
                    _ => {
                        command = Some(c);
                        Ok(())
                    }
                }
            };
            match arg {
                "--version" | "-V" => set(Command::Version)?,
                "--help" | "-h" => set(Command::Help)?,
                "--hash-password" => set(Command::HashPassword)?,
                #[cfg(windows)]
                "--service-install" => set(Command::ServiceInstall)?,
                #[cfg(windows)]
                "--service-uninstall" => set(Command::ServiceUninstall)?,
                "--env-file" => {
                    i += 1;
                    let Some(path) = args.get(i) else {
                        bail!("--env-file needs a path");
                    };
                    env_file = Some(PathBuf::from(path));
                }
                other => {
                    if let Some(path) = other.strip_prefix("--env-file=") {
                        env_file = Some(PathBuf::from(path));
                    } else {
                        bail!("unrecognised argument {other:?} — try --help");
                    }
                }
            }
            i += 1;
        }

        Ok(Args {
            command: command.unwrap_or(Command::Serve),
            env_file,
        })
    }
}

/// The `--help` text.
pub fn help(version: &str) -> String {
    format!(
        "nsclient-fleet {version}\n\n\
         NSClient Fleet — fleet management control plane for NSClient.\n\n\
         Configuration is environment variables; the flags below are the things that\n\
         cannot be one. See docs/deployment.md for the full reference. MASTER_KEY is\n\
         required to serve.\n\n\
         \x20   --env-file <path>     read KEY=VALUE lines into the environment first.\n\
         \x20                         Variables already set are left alone.\n\
         \x20   --hash-password       prompt for a password and print the argon2 hash\n\
         \x20                         for ON_PREM_ADMIN_PASSWORD_HASH, then exit\n\
         {service}\
         \x20   --version, -V         print the version and exit\n\
         \x20   --help,    -h         print this message and exit\n",
        service = if cfg!(windows) {
            "\x20   --service-install     register the Windows service (as administrator),\n\
             \x20                         passing on any --env-file given here\n\
             \x20   --service-uninstall   remove the Windows service\n"
        } else {
            ""
        }
    )
}

/// Read a password and return its argon2 hash.
///
/// From a terminal: prompted twice with the echo off, so the password reaches neither the
/// shell history nor the scrollback. From a pipe: one line on stdin, for the deployment
/// that generates the hash from a script and a secret store.
pub fn hash_password_interactively() -> Result<String> {
    let password = if std::io::stdin().is_terminal() {
        let first = rpassword::prompt_password("Password: ")?;
        let second = rpassword::prompt_password("Confirm:  ")?;
        if first != second {
            bail!("the two passwords do not match");
        }
        first
    } else {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        line.trim_end_matches(['\n', '\r']).to_string()
    };

    if password.is_empty() {
        bail!("the password is empty");
    }
    // To stderr, so `--hash-password > hash.txt` captures the hash alone while the person
    // running it still sees what to do with it.
    let mut err = std::io::stderr();
    let _ = writeln!(
        err,
        "\nSet ON_PREM_ADMIN_PASSWORD_HASH to the line below (quote it — it contains $):"
    );
    fleet_server::admin_password::hash(&password)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Args> {
        Args::parse(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn no_arguments_means_serve() {
        let args = parse(&[]).unwrap();
        assert_eq!(args.command, Command::Serve);
        assert!(args.env_file.is_none());
    }

    #[test]
    fn recognises_the_informational_flags() {
        assert_eq!(parse(&["--version"]).unwrap().command, Command::Version);
        assert_eq!(parse(&["-V"]).unwrap().command, Command::Version);
        assert_eq!(parse(&["--help"]).unwrap().command, Command::Help);
        assert_eq!(parse(&["-h"]).unwrap().command, Command::Help);
    }

    #[test]
    fn recognises_hash_password() {
        assert_eq!(
            parse(&["--hash-password"]).unwrap().command,
            Command::HashPassword
        );
    }

    #[test]
    fn env_file_takes_a_path_either_way() {
        let spaced = parse(&["--env-file", "C:\\ProgramData\\nsclient-fleet\\env"]).unwrap();
        let equals = parse(&["--env-file=C:\\ProgramData\\nsclient-fleet\\env"]).unwrap();
        assert_eq!(spaced.env_file, equals.env_file);
        assert_eq!(spaced.command, Command::Serve);
    }

    #[test]
    fn env_file_without_a_path_is_an_error() {
        assert!(parse(&["--env-file"]).is_err());
    }

    #[test]
    fn an_unknown_flag_is_an_error() {
        let err = parse(&["--serve-harder"]).unwrap_err().to_string();
        assert!(err.contains("--help"), "{err}");
    }

    /// A command line that asks for two different things is a mistake worth naming rather
    /// than silently resolving in argument order.
    #[test]
    fn two_commands_are_an_error() {
        assert!(parse(&["--version", "--hash-password"]).is_err());
    }

    #[test]
    fn the_same_command_twice_is_fine() {
        assert_eq!(
            parse(&["-V", "--version"]).unwrap().command,
            Command::Version
        );
    }

    /// `--help` alongside anything else answers the help, on the reasoning that someone
    /// typing both does not yet know what the other flag does.
    #[test]
    fn help_wins_over_another_command() {
        assert_eq!(
            parse(&["--hash-password", "--help"]).unwrap().command,
            Command::Help
        );
        assert_eq!(parse(&["--help", "-V"]).unwrap().command, Command::Help);
    }

    #[test]
    fn a_command_keeps_its_env_file() {
        let args = parse(&["--env-file", "/etc/nsclient-fleet/env", "--version"]).unwrap();
        assert_eq!(args.command, Command::Version);
        assert_eq!(
            args.env_file.unwrap().to_str().unwrap(),
            "/etc/nsclient-fleet/env"
        );
    }

    #[test]
    fn help_names_every_flag_it_accepts() {
        let text = help("1.2.3");
        assert!(text.contains("nsclient-fleet 1.2.3"));
        for flag in ["--env-file", "--hash-password", "--version", "--help"] {
            assert!(text.contains(flag), "help does not mention {flag}");
        }
        #[cfg(windows)]
        for flag in ["--service-install", "--service-uninstall"] {
            assert!(text.contains(flag), "help does not mention {flag}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn recognises_the_service_flags() {
        assert_eq!(
            parse(&["--service-install"]).unwrap().command,
            Command::ServiceInstall
        );
        assert_eq!(
            parse(&["--service-uninstall"]).unwrap().command,
            Command::ServiceUninstall
        );
    }

    /// The service registers itself with `--env-file` in its command line, so that pair
    /// has to parse when the SCM hands it back.
    #[cfg(windows)]
    #[test]
    fn the_service_command_line_round_trips() {
        let args = parse(&["--env-file", "C:\\ProgramData\\nsclient-fleet\\env"]).unwrap();
        assert_eq!(args.command, Command::Serve);
        assert_eq!(
            args.env_file.unwrap().to_str().unwrap(),
            "C:\\ProgramData\\nsclient-fleet\\env"
        );
    }
}
