use apiman::cli::{Cli, Commands, create_vault_interactive, handle_cli, load_session};
use apiman::config::{Config, expand_path};
use apiman::tui::run_tui;
use clap::Parser;
use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();

    let is_tui_requested = cli.command.is_none() || matches!(cli.command, Some(Commands::Tui));
    let result = if is_tui_requested {
        launch_tui(&cli)
    } else {
        handle_cli(cli)
    };

    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn launch_tui(cli: &Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    if !io::stdout().is_terminal() {
        eprintln!(
            "The apiman TUI needs an interactive terminal. See 'apiman --help' for CLI commands."
        );
        return Ok(ExitCode::FAILURE);
    }

    let config = Config::load(cli.config.as_deref())?;
    let vault_path = cli
        .vault
        .as_deref()
        .map(expand_path)
        .unwrap_or_else(|| config.vault_path.clone());

    if !vault_path.exists() {
        if !io::stdin().is_terminal() {
            eprintln!(
                "Vault not found at '{}'. Run 'apiman init' to create one.",
                vault_path.display()
            );
            return Ok(ExitCode::FAILURE);
        }
        eprint!(
            "No vault found at '{}'. Initialize a new vault now? [Y/n]: ",
            vault_path.display()
        );
        io::stderr().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        let trimmed = answer.trim();
        if !(trimmed.is_empty() || trimmed.eq_ignore_ascii_case("y")) {
            eprintln!("Run 'apiman init' when you are ready to create a vault.");
            return Ok(ExitCode::FAILURE);
        }
        create_vault_interactive(&config, &vault_path)?;
    }

    let ctx = load_session(cli.config.as_deref(), cli.vault.as_deref(), true)?;
    run_tui(ctx)?;
    Ok(ExitCode::SUCCESS)
}
