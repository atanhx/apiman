use clap::{Args, Parser, Subcommand, ValueEnum};
use rpassword::prompt_password;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zeroize::{Zeroize, Zeroizing};

use crate::config::{default_socket_path, Config};
use crate::daemon::{
    check_daemon_status, get_cached_master_key, lock_daemon, run_daemon_loop, spawn_daemon,
};
use crate::security::{harden_process, SecretString};
use crate::storage::{
    init_vault, load_vault_with_key, load_vault_with_password, save_vault, StorageError,
};
use crate::vault::Vault;

#[derive(Parser, Debug)]
#[command(
    name = "apiman",
    about = "Secure, minimal API credential manager & runner",
    version,
    arg_required_else_help = false
)]
pub struct Cli {
    #[arg(short, long, help = "Custom configuration file path")]
    pub config: Option<PathBuf>,

    #[arg(short, long, help = "Custom encrypted vault file path")]
    pub vault: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(about = "Initialize a new encrypted vault")]
    Init,

    #[command(about = "Set or update a secret entry")]
    Set(SetArgs),

    #[command(about = "Retrieve a secret value (safe against terminal leaks)")]
    Get(GetArgs),

    #[command(about = "List stored secrets without exposing values")]
    List(ListArgs),

    #[command(about = "Delete a secret entry")]
    Delete(DeleteArgs),

    #[command(about = "Run a command with secrets injected into process environment")]
    Run(RunArgs),

    #[command(about = "Lock the vault and terminate the in-memory session daemon")]
    Lock,

    #[command(about = "Unlock the vault and start the in-memory session daemon")]
    Unlock,

    #[command(about = "Show vault and session daemon status")]
    Status,

    #[command(about = "Launch the interactive Terminal User Interface")]
    Tui,

    #[command(hide = true)]
    Daemon(DaemonArgs),
}

#[derive(Args, Debug)]
pub struct SetArgs {
    #[arg(help = "Secret name (e.g. OPENAI_API_KEY)")]
    pub name: String,

    #[arg(help = "Secret value (if omitted, prompts securely without echo)")]
    pub value: Option<String>,

    #[arg(short, long, help = "Project scope (defaults to global)")]
    pub project: Option<String>,

    #[arg(short, long, value_delimiter = ',', help = "Comma-separated tags")]
    pub tags: Vec<String>,

    #[arg(short, long, help = "Description or notes")]
    pub description: Option<String>,
}

#[derive(Args, Debug)]
pub struct GetArgs {
    #[arg(help = "Secret name to retrieve")]
    pub name: String,

    #[arg(short, long, help = "Target project scope")]
    pub project: Option<String>,

    #[arg(
        long,
        help = "Allow printing raw secret to console (prevented by default in interactive TTY)"
    )]
    pub allow_view: bool,
}

#[derive(Args, Debug)]
pub struct ListArgs {
    #[arg(short, long, help = "Filter by project name (or 'all', 'global')")]
    pub project: Option<String>,

    #[arg(short, long, help = "Filter by tag")]
    pub tag: Option<String>,

    #[arg(short, long, value_enum, default_value_t = OutputFormat::Table, help = "Output format")]
    pub format: OutputFormat,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Table,
    Json,
}

#[derive(Args, Debug)]
pub struct DeleteArgs {
    #[arg(help = "Secret name to delete")]
    pub name: String,

    #[arg(short, long, help = "Project scope (defaults to global)")]
    pub project: Option<String>,
}

#[derive(Args, Debug)]
pub struct RunArgs {
    #[arg(short, long, help = "Project scope to load secrets from")]
    pub project: Option<String>,

    #[arg(short, long, help = "Only inject secrets matching this tag")]
    pub tag: Option<String>,

    #[arg(
        trailing_var_arg = true,
        required = true,
        help = "Command and arguments to execute (after --)"
    )]
    pub command: Vec<String>,
}

#[derive(Args, Debug)]
pub struct DaemonArgs {
    #[arg(long)]
    pub run: bool,

    #[arg(long, default_value = "900")]
    pub timeout: u64,

    #[arg(long)]
    pub socket: PathBuf,
}

pub struct SessionContext {
    pub config: Config,
    pub vault_path: PathBuf,
    pub socket_path: PathBuf,
    pub master_key: Zeroizing<[u8; 32]>,
    pub salt: [u8; 32],
    pub vault: Vault,
}

impl SessionContext {
    pub fn save(&self) -> Result<(), StorageError> {
        save_vault(&self.vault, &self.master_key, &self.salt, &self.vault_path)
    }
}

pub fn load_session(
    custom_cfg: Option<&Path>,
    custom_vault: Option<&Path>,
    prompt_if_locked: bool,
) -> Result<SessionContext, Box<dyn std::error::Error>> {
    harden_process();

    let mut config = Config::load_or_default();
    if let Some(cfg_path) = custom_cfg {
        if let Ok(c) = std::fs::read_to_string(cfg_path) {
            config = serde_json::from_str(&c)?;
        }
    }

    let vault_path = custom_vault
        .map(PathBuf::from)
        .unwrap_or_else(|| config.vault_path.clone());

    if !vault_path.exists() {
        return Err(format!(
            "Vault not found at '{}'. Run 'apiman init' to create one.",
            vault_path.display()
        )
        .into());
    }

    let socket_path = default_socket_path();

    // 1. Try in-memory daemon session first
    if let Some(cached_key) = get_cached_master_key(&socket_path) {
        if let Ok((vault, salt)) = load_vault_with_key(&cached_key, &vault_path) {
            return Ok(SessionContext {
                config,
                vault_path,
                socket_path,
                master_key: cached_key,
                salt,
                vault,
            });
        }
    }

    if !prompt_if_locked {
        return Err("Vault is locked and daemon is not running".into());
    }

    // 2. Try environment variable fallback for scripts/CI
    let env_pw = std::env::var("APIMAN_MASTER_PASSWORD")
        .or_else(|_| std::env::var("APIMAN_PASSWORD"))
        .ok();

    let password = if let Some(pw) = env_pw {
        pw
    } else {
        eprint!("Master password: ");
        io::stderr().flush()?;
        prompt_password("")?
    };

    let (vault, master_key, salt) = load_vault_with_password(&password, &vault_path)?;

    // Spawn background daemon to retain session key
    let _ = spawn_daemon(
        &master_key,
        config.auto_lock_timeout_seconds,
        &socket_path,
    );

    Ok(SessionContext {
        config,
        vault_path,
        socket_path,
        master_key,
        salt,
        vault,
    })
}

pub fn handle_cli(cli: Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let custom_cfg = cli.config.as_deref();
    let custom_vault = cli.vault.as_deref();

    let cmd = match cli.command {
        Some(c) => c,
        None => return Ok(ExitCode::SUCCESS), // Caller will launch TUI
    };

    match cmd {
        Commands::Init => handle_init(custom_cfg, custom_vault),
        Commands::Set(args) => handle_set(custom_cfg, custom_vault, args),
        Commands::Get(args) => handle_get(custom_cfg, custom_vault, args),
        Commands::List(args) => handle_list(custom_cfg, custom_vault, args),
        Commands::Delete(args) => handle_delete(custom_cfg, custom_vault, args),
        Commands::Run(args) => handle_run(custom_cfg, custom_vault, args),
        Commands::Lock => handle_lock(custom_cfg),
        Commands::Unlock => handle_unlock(custom_cfg, custom_vault),
        Commands::Status => handle_status(custom_cfg, custom_vault),
        Commands::Tui => Ok(ExitCode::SUCCESS), // Handled by main.rs
        Commands::Daemon(args) => handle_daemon(args),
    }
}

fn handle_init(
    _custom_cfg: Option<&Path>,
    custom_vault: Option<&Path>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let config = Config::load_or_default();
    let vault_path = custom_vault
        .map(PathBuf::from)
        .unwrap_or_else(|| config.vault_path.clone());

    if vault_path.exists() {
        eprint!(
            "Vault already exists at '{}'. Overwrite? [y/N]: ",
            vault_path.display()
        );
        io::stderr().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            eprintln!("Initialization aborted.");
            return Ok(ExitCode::FAILURE);
        }
    }

    eprint!("Enter new master password: ");
    io::stderr().flush()?;
    let mut pw1 = prompt_password("")?;

    if pw1.is_empty() {
        eprintln!("Error: Password cannot be empty.");
        return Ok(ExitCode::FAILURE);
    }

    eprint!("Confirm master password: ");
    io::stderr().flush()?;
    let mut pw2 = prompt_password("")?;

    if pw1 != pw2 {
        pw1.zeroize();
        pw2.zeroize();
        eprintln!("Error: Passwords do not match.");
        return Ok(ExitCode::FAILURE);
    }

    let (_, master_key, _) = init_vault(&pw1, &vault_path)?;
    pw1.zeroize();
    pw2.zeroize();

    let socket_path = default_socket_path();
    let _ = spawn_daemon(
        &master_key,
        config.auto_lock_timeout_seconds,
        &socket_path,
    );

    eprintln!("Vault initialized successfully at '{}'", vault_path.display());
    Ok(ExitCode::SUCCESS)
}

fn handle_set(
    custom_cfg: Option<&Path>,
    custom_vault: Option<&Path>,
    args: SetArgs,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut ctx = load_session(custom_cfg, custom_vault, true)?;

    let mut secret_val = if let Some(v) = args.value {
        v
    } else {
        eprint!("Enter secret value for '{}': ", args.name);
        io::stderr().flush()?;
        prompt_password("")?
    };

    let project = args.project.or_else(|| {
        if ctx.config.default_project == "global" {
            None
        } else {
            Some(ctx.config.default_project.clone())
        }
    });

    ctx.vault.set(
        args.name.clone(),
        SecretString::new(&secret_val),
        project.clone(),
        args.tags,
        args.description,
    );
    secret_val.zeroize();

    ctx.save()?;
    let scope_msg = project.as_deref().unwrap_or("global");
    eprintln!("Secret '{}' saved (scope: {})", args.name, scope_msg);
    Ok(ExitCode::SUCCESS)
}

fn handle_get(
    custom_cfg: Option<&Path>,
    custom_vault: Option<&Path>,
    args: GetArgs,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let ctx = load_session(custom_cfg, custom_vault, true)?;

    let target_proj = args.project.as_deref();
    let entry = match ctx.vault.get(&args.name, target_proj) {
        Some(e) => e,
        None => {
            eprintln!(
                "Error: Secret '{}' not found{}",
                args.name,
                target_proj
                    .map(|p| format!(" in project '{p}' or global"))
                    .unwrap_or_default()
            );
            return Ok(ExitCode::FAILURE);
        }
    };

    let is_tty = io::stdout().is_terminal();

    if is_tty && !args.allow_view {
        eprintln!(
            "Notice: Refusing to print secret directly to interactive terminal without --allow-view to prevent leaks.\nUse 'apiman get {} --allow-view' or pipe output ('apiman get {} | pbcopy')",
            args.name, args.name
        );
        return Ok(ExitCode::FAILURE);
    }

    if is_tty {
        println!("{}", entry.value.expose_secret());
    } else {
        // Piped output: raw without extra trailing newline
        print!("{}", entry.value.expose_secret());
        io::stdout().flush()?;
    }

    Ok(ExitCode::SUCCESS)
}

fn handle_list(
    custom_cfg: Option<&Path>,
    custom_vault: Option<&Path>,
    args: ListArgs,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let ctx = load_session(custom_cfg, custom_vault, true)?;
    let entries = ctx.vault.list(args.project.as_deref(), args.tag.as_deref());

    if args.format == OutputFormat::Json {
        let serializable: Vec<_> = entries
            .into_iter()
            .map(|e| {
                serde_json::json!({
                    "name": e.name,
                    "project": e.project_display(),
                    "tags": e.tags,
                    "description": e.description,
                    "updated_at": e.updated_at
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&serializable)?);
        return Ok(ExitCode::SUCCESS);
    }

    if entries.is_empty() {
        println!("No secret entries found.");
        return Ok(ExitCode::SUCCESS);
    }

    println!("{:<25} {:<15} {:<20} {:<30}", "NAME", "PROJECT", "TAGS", "DESCRIPTION");
    println!("{}", "-".repeat(95));
    for e in entries {
        let tags_str = if e.tags.is_empty() {
            "-".to_string()
        } else {
            e.tags.join(",")
        };
        let desc_str = e.description.as_deref().unwrap_or("-");
        println!(
            "{:<25} {:<15} {:<20} {:<30}",
            e.name,
            e.project_display(),
            tags_str,
            desc_str
        );
    }

    Ok(ExitCode::SUCCESS)
}

fn handle_delete(
    custom_cfg: Option<&Path>,
    custom_vault: Option<&Path>,
    args: DeleteArgs,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut ctx = load_session(custom_cfg, custom_vault, true)?;
    let deleted = ctx.vault.delete(&args.name, args.project.as_deref());

    if deleted {
        ctx.save()?;
        eprintln!(
            "Secret '{}' deleted from project '{}'",
            args.name,
            args.project.as_deref().unwrap_or("global")
        );
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!(
            "Error: Secret '{}' not found in project '{}'",
            args.name,
            args.project.as_deref().unwrap_or("global")
        );
        Ok(ExitCode::FAILURE)
    }
}

fn handle_run(
    custom_cfg: Option<&Path>,
    custom_vault: Option<&Path>,
    args: RunArgs,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    if args.command.is_empty() {
        eprintln!("Error: No command specified to run.");
        return Ok(ExitCode::FAILURE);
    }

    let ctx = load_session(custom_cfg, custom_vault, true)?;
    let mut env_map = ctx.vault.resolve_env_map(args.project.as_deref(), args.tag.as_deref());

    let prog = &args.command[0];
    let prog_args = &args.command[1..];

    let mut child = std::process::Command::new(prog);
    child.args(prog_args);
    for (k, v) in &env_map {
        child.env(k, v);
    }

    let status = child.status()?;

    // Wipe sensitive env map from caller memory
    for (_, v) in env_map.iter_mut() {
        v.zeroize();
    }
    env_map.clear();

    if let Some(code) = status.code() {
        Ok(ExitCode::from(code as u8))
    } else {
        Ok(ExitCode::FAILURE)
    }
}

fn handle_lock(_custom_cfg: Option<&Path>) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let socket_path = default_socket_path();
    lock_daemon(&socket_path)?;
    eprintln!("Vault session locked and in-memory daemon stopped.");
    Ok(ExitCode::SUCCESS)
}

fn handle_unlock(
    custom_cfg: Option<&Path>,
    custom_vault: Option<&Path>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let _ctx = load_session(custom_cfg, custom_vault, true)?;
    eprintln!("Vault unlocked successfully. Session daemon is active.");
    Ok(ExitCode::SUCCESS)
}

fn handle_status(
    _custom_cfg: Option<&Path>,
    custom_vault: Option<&Path>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let config = Config::load_or_default();
    let vault_path = custom_vault
        .map(PathBuf::from)
        .unwrap_or_else(|| config.vault_path.clone());
    let socket_path = default_socket_path();

    println!("Vault Path:   {}", vault_path.display());
    println!("Exists:       {}", vault_path.exists());

    if let Some((unlocked, remaining, timeout)) = check_daemon_status(&socket_path) {
        println!("Daemon:       Active (PID session)");
        println!("State:        {}", if unlocked { "Unlocked" } else { "Locked" });
        println!("Auto-Lock:    {}s / {}s timeout", remaining, timeout);
    } else {
        println!("Daemon:       Inactive (Locked)");
    }

    Ok(ExitCode::SUCCESS)
}

fn handle_daemon(args: DaemonArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    if args.run {
        run_daemon_loop(args.timeout, args.socket)?;
    }
    Ok(ExitCode::SUCCESS)
}
