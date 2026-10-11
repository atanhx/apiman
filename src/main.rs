use apiman::cli::{handle_cli, Cli};
use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.command.is_none() {
        println!("Launch TUI mode");
        return ExitCode::SUCCESS;
    }

    match handle_cli(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}
