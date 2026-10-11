use apiman::cli::{handle_cli, load_session, Cli, Commands};
use apiman::config::Config;
use apiman::security::read_secure_password;
use apiman::storage::init_vault;
use apiman::tui::run_tui;
use clap::Parser;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use zeroize::Zeroize;

fn main() -> ExitCode {
    let cli = Cli::parse();

    let is_tui_requested = cli.command.is_none() || matches!(cli.command, Some(Commands::Tui));

    if is_tui_requested {
        let config = Config::load_or_default();
        let vault_path = cli
            .vault
            .clone()
            .unwrap_or_else(|| config.vault_path.clone());

        if !vault_path.exists() {
            if io::stdin().is_terminal() {
                eprint!(
                    "No vault found at '{}'. Initialize a new vault now? [Y/n]: ",
                    vault_path.display()
                );
                let _ = io::stderr().flush();
                let mut answer = String::new();
                if io::stdin().read_line(&mut answer).is_ok() {
                    let trimmed = answer.trim();
                    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("y") {
                        if let Err(e) = interactive_init(&vault_path, &config) {
                            eprintln!("Error initializing vault: {e}");
                            return ExitCode::FAILURE;
                        }
                    } else {
                        eprintln!("Run 'apiman init' when you are ready to create a vault.");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                eprintln!(
                    "Vault not found at '{}'. Run 'apiman init' to create one.",
                    vault_path.display()
                );
                return ExitCode::FAILURE;
            }
        }

        match load_session(cli.config.as_deref(), cli.vault.as_deref(), true) {
            Ok(ctx) => {
                if let Err(e) = run_tui(ctx) {
                    eprintln!("TUI error: {e}");
                    ExitCode::FAILURE
                } else {
                    ExitCode::SUCCESS
                }
            }
            Err(e) => {
                eprintln!("Error: {e}");
                ExitCode::FAILURE
            }
        }
    } else {
        match handle_cli(cli) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("Error: {e}");
                ExitCode::FAILURE
            }
        }
    }
}

fn interactive_init(
    vault_path: &PathBuf,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut pw1 = read_secure_password("Enter new master password: ")?;

    if pw1.is_empty() {
        return Err("Password cannot be empty".into());
    }

    let mut pw2 = read_secure_password("Confirm master password: ")?;

    if pw1 != pw2 {
        pw1.zeroize();
        pw2.zeroize();
        return Err("Passwords do not match".into());
    }

    let (_, master_key, _) = init_vault(&pw1, vault_path)?;
    pw1.zeroize();
    pw2.zeroize();

    let socket_path = apiman::config::default_socket_path();
    let _ = apiman::daemon::spawn_daemon(
        &master_key,
        config.auto_lock_timeout_seconds,
        &socket_path,
    );

    eprintln!("Vault initialized successfully at '{}'", vault_path.display());
    Ok(())
}
