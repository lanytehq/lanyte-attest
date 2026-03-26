use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "lanyte-attest",
    version,
    about = "Session attestation CLI for supervised agent sessions"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Keygen(KeygenArgs),
    Begin(BeginArgs),
    Verify(VerifyArgs),
    End,
    Revoke(RevokeArgs),
}

#[derive(Debug, Args)]
pub struct KeygenArgs {
    #[arg(long)]
    pub output: Option<PathBuf>,

    #[arg(long)]
    pub issuer: Option<String>,
}

#[derive(Debug, Args)]
pub struct BeginArgs {
    #[arg(long)]
    pub role: String,

    #[arg(long)]
    pub scope: String,

    #[arg(long)]
    pub ttl: Option<String>,

    #[arg(long)]
    pub supervisor: Option<String>,

    #[arg(long, conflicts_with = "exec")]
    pub emit_env: bool,

    #[arg(last = true, conflicts_with = "emit_env")]
    pub exec: Vec<String>,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    #[arg(long)]
    pub expected_issuer: Option<String>,

    #[arg(long)]
    pub expected_role: Option<String>,

    #[arg(long)]
    pub expected_scope: Option<String>,

    pub token: String,
}

#[derive(Debug, Args)]
pub struct RevokeArgs {
    pub jti: String,
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, Command};

    #[test]
    fn parses_keygen_command() {
        let cli = Cli::parse_from(["lanyte-attest", "keygen", "--issuer", "lanyte-dev.local"]);
        match cli.command {
            Command::Keygen(args) => {
                assert_eq!(args.issuer.as_deref(), Some("lanyte-dev.local"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_begin_command_with_exec_tail() {
        let cli = Cli::parse_from([
            "lanyte-attest",
            "begin",
            "--role",
            "devlead",
            "--scope",
            "lanytehq",
            "--",
            "bash",
            "-lc",
            "pwd",
        ]);

        match cli.command {
            Command::Begin(args) => {
                assert_eq!(args.role, "devlead");
                assert_eq!(args.scope, "lanytehq");
                assert!(!args.emit_env);
                assert_eq!(args.exec, vec!["bash", "-lc", "pwd"]);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn rejects_emit_env_with_exec_tail() {
        let err = Cli::try_parse_from([
            "lanyte-attest",
            "begin",
            "--role",
            "devlead",
            "--scope",
            "lanytehq",
            "--emit-env",
            "--",
            "bash",
        ])
        .expect_err("mixed delivery modes must fail");

        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn parses_verify_command() {
        let cli = Cli::parse_from([
            "lanyte-attest",
            "verify",
            "--expected-role",
            "devlead",
            "token-value",
        ]);

        match cli.command {
            Command::Verify(args) => {
                assert_eq!(args.expected_role.as_deref(), Some("devlead"));
                assert_eq!(args.token, "token-value");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }
}
