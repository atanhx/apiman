use clap::{Args, Parser, Subcommand, ValueEnum};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zeroize::{Zeroize, Zeroizing};

use crate::config::{default_socket_path, Config};
use crate::daemon::{
    check_daemon_status, get_cached_master_key, lock_daemon, run_daemon_loop, spawn_daemon,
    update_daemon_master_key, update_daemon_timeout,
};
use crate::dotenv::{format_env, format_example, parse_dotenv, EnvEntry};
use crate::install::{
    install_binary_to, installed_binary_path, is_installed, resolve_install_dir,
    uninstall_binary,
};
use crate::security::{harden_process, read_secure_password, SecretString};
use crate::storage::{
    init_vault, load_vault_with_key, load_vault_with_password, rekey_vault, save_vault,
    StorageError,
};
use crate::vault::Vault;

#[derive(Parser, Debug)]
#[command(
    name = "apiman",
    about = "Secure, minimal API credential manager, runner & TUI",
    version,
    after_help = "\
EXAMPLES:
  # Launch interactive TUI (default when no command given)
  apiman

  # Store an API key (prompted securely for value)
  apiman set OPENAI_API_KEY

  # Store an API key with project and tags
  apiman set STRIPE_KEY \"sk_live_123\" --project billing --tags payment,prod

  # View a secret in terminal (requires --allow-view to prevent screen leaks)
  apiman get OPENAI_API_KEY --allow-view

  # Pipe secret directly to clipboard or another program
  apiman get OPENAI_API_KEY | wl-copy

  # Execute a command with secrets injected into its process memory
  apiman run -- node server.js
  apiman run --project billing -- python main.py

  # Change the master vault password
  apiman passwd

  # Import secrets from a .env file into a project
  apiman import ./backend/.env --project backend --tags prod

  # Export secrets back out to .env format
  apiman export --project backend --output ./backend/.env
  apiman export --format example --output ./.env.example

  # Set auto-lock timeout to 30 minutes, or disable it (always unlocked)
  apiman timeout 30m
  apiman timeout none

  # Install apiman binary to ~/.local/bin/ (or a custom directory)
  apiman install
  apiman install ~/bin
",
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
    #[command(
        about = "Initialize a new encrypted vault",
        after_help = "EXAMPLE:\n  apiman init\n  # Prompts for a master password and initializes ~/.config/apiman/vault.enc"
    )]
    Init,

    #[command(
        about = "Set or update a secret entry",
        after_help = "EXAMPLES:\n  apiman set OPENAI_API_KEY\n  apiman set DATABASE_URL \"postgres://...\" --project backend\n  apiman set STRIPE_KEY \"sk_...\" --project billing --tags payment,prod --description \"Live key\""
    )]
    Set(SetArgs),

    #[command(
        about = "Retrieve a secret value (safe against terminal leaks)",
        after_help = "EXAMPLES:\n  # Safe terminal display (requires --allow-view):\n  apiman get OPENAI_API_KEY --allow-view\n\n  # Pipe directly into tools (no --allow-view needed):\n  apiman get OPENAI_API_KEY | wl-copy\n  apiman get GITHUB_TOKEN | gh auth login --with-token"
    )]
    Get(GetArgs),

    #[command(
        about = "List stored secrets without exposing values",
        after_help = "EXAMPLES:\n  apiman list\n  apiman list --project billing\n  apiman list --tag payment\n  apiman list --format json"
    )]
    List(ListArgs),

    #[command(
        about = "Delete a secret entry",
        after_help = "EXAMPLES:\n  apiman delete OPENAI_API_KEY\n  apiman delete STRIPE_KEY --project billing"
    )]
    Delete(DeleteArgs),

    #[command(
        about = "Run a command with secrets injected into process environment",
        after_help = "EXAMPLES:\n  # Run server with global secrets injected:\n  apiman run -- node index.js\n\n  # Run with project-specific overrides:\n  apiman run --project billing -- python app.py\n\n  # Run tests with secrets matching 'test' tag:\n  apiman run --tag test -- pytest\n\n  # Use in curl command:\n  apiman run -- sh -c 'curl -H \"Authorization: Bearer $OPENAI_API_KEY\" https://api.openai.com/v1/models'"
    )]
    Run(RunArgs),

    #[command(
        about = "Change the master vault encryption password",
        after_help = "EXAMPLE:\n  apiman passwd\n  # Re-encrypts the vault with a new Argon2id key and updates active session"
    )]
    Passwd,

    #[command(
        about = "Import secrets from a .env file into the vault",
        after_help = "EXAMPLES:\n  apiman import ./.env\n  apiman import ./backend/.env --project backend --tags prod\n  apiman import ./.env.example --project myapp"
    )]
    Import(ImportArgs),

    #[command(
        about = "Export secrets to .env format (file, stdout pipe, or safe .env.example)",
        after_help = "EXAMPLES:\n  apiman export --output ./.env\n  apiman export --project billing --output ./billing.env\n  apiman export --format example --output ./.env.example\n  apiman export --project billing | wl-copy"
    )]
    Export(ExportArgs),

    #[command(
        about = "Configure or view auto-lock session timeout (e.g. 15m, 2h, 0, or none)",
        after_help = "EXAMPLES:\n  apiman timeout\n  apiman timeout 30m\n  apiman timeout 2h\n  apiman timeout 900s\n  apiman timeout none    # Keep always unlocked (disable auto-lock)"
    )]
    Timeout(TimeoutArgs),

    #[command(
        about = "Install apiman binary to ~/.local/bin (or a custom directory)",
        after_help = "EXAMPLES:\n  apiman install\n  apiman install ~/bin\n  apiman install /usr/local/bin"
    )]
    Install(InstallArgs),

    #[command(
        about = "Uninstall apiman binary from ~/.local/bin",
        after_help = "EXAMPLE:\n  apiman uninstall\n  # Removes the installed binary from ~/.local/bin/apiman"
    )]
    Uninstall,

    #[command(
        about = "Lock the vault and terminate the in-memory session daemon",
        after_help = "EXAMPLE:\n  apiman lock\n  # Zeroes master key from memory and shuts down daemon"
    )]
    Lock,

    #[command(
        about = "Unlock the vault and start the in-memory session daemon",
        after_help = "EXAMPLE:\n  apiman unlock\n  # Pre-authenticates so subsequent commands don't ask for password"
    )]
    Unlock,

    #[command(
        about = "Show vault, daemon, and installation status",
        after_help = "EXAMPLE:\n  apiman status"
    )]
    Status,

    #[command(
        about = "Launch the interactive Terminal User Interface",
        after_help = "EXAMPLE:\n  apiman tui"
    )]
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

    #[arg(short, long, help = "Target project scope (optional, searched automatically)")]
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
        help = "Executable program and arguments to run (e.g. -- node server.js)"
    )]
    pub command: Vec<String>,
}

#[derive(Args, Debug)]
pub struct ImportArgs {
    #[arg(help = "Path to the .env / .env.example file to import")]
    pub file: PathBuf,

    #[arg(short, long, help = "Project scope to import into (defaults to global)")]
    pub project: Option<String>,

    #[arg(short, long, value_delimiter = ',', help = "Comma-separated tags applied to imported entries")]
    pub tags: Vec<String>,
}

#[derive(Args, Debug)]
pub struct ExportArgs {
    #[arg(short, long, help = "Write output to this file instead of stdout")]
    pub output: Option<PathBuf>,

    #[arg(short, long, help = "Project scope to export (includes global entries with project overrides)")]
    pub project: Option<String>,

    #[arg(short, long, help = "Only export secrets matching this tag")]
    pub tag: Option<String>,

    #[arg(short, long, value_enum, default_value_t = ExportFormat::Env, help = "Output format")]
    pub format: ExportFormat,

    #[arg(
        long,
        help = "Allow printing secret values to an interactive terminal (not needed for pipes or example format)"
    )]
    pub allow_view: bool,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportFormat {
    Env,
    Example,
}

#[derive(Args, Debug)]
pub struct InstallArgs {
    #[arg(
        help = "Custom directory to install into (defaults to ~/.local/bin). The directory is created if needed.",
        value_name = "DIR"
    )]
    pub path: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct TimeoutArgs {
    #[arg(
        help = "Timeout duration (e.g. 15m, 1h, 900s, 0, none, never). If omitted, displays current timeout"
    )]
    pub duration: Option<String>,
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
    let mut stale_daemon = false;
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
        // Daemon is alive but its key does not decrypt this vault
        // (stale key from another vault or an older session).
        stale_daemon = true;
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
        read_secure_password("Master password: ")?
    };

    let (vault, master_key, salt) = load_vault_with_password(&password, &vault_path)?;

    if stale_daemon {
        // Replace the stale daemon so its wrong key stops shadowing this vault.
        let _ = lock_daemon(&socket_path);
    }

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
        None => return Ok(ExitCode::SUCCESS),
    };

    match cmd {
        Commands::Init => handle_init(custom_cfg, custom_vault),
        Commands::Set(args) => handle_set(custom_cfg, custom_vault, args),
        Commands::Get(args) => handle_get(custom_cfg, custom_vault, args),
        Commands::List(args) => handle_list(custom_cfg, custom_vault, args),
        Commands::Delete(args) => handle_delete(custom_cfg, custom_vault, args),
        Commands::Run(args) => handle_run(custom_cfg, custom_vault, args),
        Commands::Passwd => handle_passwd(custom_cfg, custom_vault),
        Commands::Import(args) => handle_import(custom_cfg, custom_vault, args),
        Commands::Export(args) => handle_export(custom_cfg, custom_vault, args),
        Commands::Timeout(args) => handle_timeout(custom_cfg, args),
        Commands::Install(args) => handle_install(args),
        Commands::Uninstall => handle_uninstall(),
        Commands::Lock => handle_lock(custom_cfg),
        Commands::Unlock => handle_unlock(custom_cfg, custom_vault),
        Commands::Status => handle_status(custom_cfg, custom_vault),
        Commands::Tui => Ok(ExitCode::SUCCESS),
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

    let mut pw1 = read_secure_password("Enter new master password: ")?;

    if pw1.is_empty() {
        eprintln!("Error: Password cannot be empty.");
        return Ok(ExitCode::FAILURE);
    }

    let mut pw2 = read_secure_password("Confirm master password: ")?;

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
        read_secure_password(&format!("Enter secret value for '{}': ", args.name))?
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
            eprintln!("Error: Secret '{}' not found", args.name);
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

    let status = match child.status() {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "Error: Command '{}' was not found in system PATH.\n\n\
                Usage: apiman run [OPTIONS] -- <PROGRAM> [ARGS...]\n\
                Examples:\n  \
                  apiman run -- node server.js\n  \
                  apiman run -- python main.py\n  \
                  apiman run --project billing -- npm start\n  \
                  apiman run -- sh -c 'echo $OPENAI_API_KEY'\n\n\
                To retrieve a secret value instead of executing a program, use:\n  \
                  apiman get {}",
                prog, prog
            );
            return Ok(ExitCode::FAILURE);
        }
        Err(e) => return Err(e.into()),
    };

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

fn handle_passwd(
    custom_cfg: Option<&Path>,
    custom_vault: Option<&Path>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let ctx = load_session(custom_cfg, custom_vault, true)?;

    let mut new_pw1 = read_secure_password("Enter new master password: ")?;

    if new_pw1.is_empty() {
        eprintln!("Error: Password cannot be empty.");
        return Ok(ExitCode::FAILURE);
    }

    let mut new_pw2 = read_secure_password("Confirm new master password: ")?;

    if new_pw1 != new_pw2 {
        new_pw1.zeroize();
        new_pw2.zeroize();
        eprintln!("Error: Passwords do not match.");
        return Ok(ExitCode::FAILURE);
    }

    let (new_key, _) = rekey_vault(&ctx.vault, &new_pw1, &ctx.vault_path)?;
    new_pw1.zeroize();
    new_pw2.zeroize();

    // Update active daemon with the new key so the user stays authenticated
    let _ = update_daemon_master_key(&ctx.socket_path, &new_key);

    eprintln!("Master password updated successfully for '{}'", ctx.vault_path.display());
    Ok(ExitCode::SUCCESS)
}

fn handle_import(
    custom_cfg: Option<&Path>,
    custom_vault: Option<&Path>,
    args: ImportArgs,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    if !args.file.exists() {
        eprintln!("Error: File '{}' not found.", args.file.display());
        return Ok(ExitCode::FAILURE);
    }
    if args.file.is_dir() {
        eprintln!(
            "Error: '{}' is a directory. Provide a .env file path to import.",
            args.file.display()
        );
        return Ok(ExitCode::FAILURE);
    }

    let content = std::fs::read_to_string(&args.file)?;
    let (entries, skipped) = parse_dotenv(&content);

    let mut ctx = load_session(custom_cfg, custom_vault, true)?;
    let project = args.project.or_else(|| {
        if ctx.config.default_project == "global" {
            None
        } else {
            Some(ctx.config.default_project.clone())
        }
    });

    let mut imported = 0;
    let mut empty_skipped = 0;
    for e in entries {
        if e.value.is_empty() {
            empty_skipped += 1;
            continue;
        }
        ctx.vault.set(
            e.key,
            SecretString::new(&e.value),
            project.clone(),
            args.tags.clone(),
            None,
        );
        imported += 1;
    }
    ctx.save()?;

    let scope_msg = project.as_deref().unwrap_or("global");
    eprintln!(
        "Imported {imported} entr{} into scope '{scope_msg}' (skipped {skipped} invalid lines, {empty_skipped} empty placeholders).",
        if imported == 1 { "y" } else { "ies" },
    );
    Ok(ExitCode::SUCCESS)
}

fn handle_export(
    custom_cfg: Option<&Path>,
    custom_vault: Option<&Path>,
    args: ExportArgs,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let ctx = load_session(custom_cfg, custom_vault, true)?;
    let is_example = args.format == ExportFormat::Example;

    let output = if is_example {
        let mut keys: Vec<String> = ctx
            .vault
            .list(args.project.as_deref(), args.tag.as_deref())
            .into_iter()
            .map(|e| e.name.clone())
            .collect();
        keys.sort();
        keys.dedup();
        format_example(&keys)
    } else {
        let map = ctx
            .vault
            .resolve_env_map(args.project.as_deref(), args.tag.as_deref());
        let mut entries: Vec<EnvEntry> = map
            .into_iter()
            .map(|(key, value)| EnvEntry { key, value })
            .collect();
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        format_env(&entries)
    };

    if let Some(out_path) = args.output {
        let resolved = resolve_export_path(&out_path, is_example);
        write_secret_file(&resolved, output.as_bytes())?;
        eprintln!(
            "Exported {} to '{}'",
            if is_example { "example template" } else { "secrets" },
            resolved.display()
        );
        return Ok(ExitCode::SUCCESS);
    }

    let is_tty = io::stdout().is_terminal();
    if is_tty && !is_example && !args.allow_view {
        eprintln!(
            "Notice: Refusing to print secrets to an interactive terminal without --allow-view.\nUse 'apiman export --output FILE', pipe the output ('apiman export | wl-copy'), or pass --allow-view."
        );
        return Ok(ExitCode::FAILURE);
    }

    print!("{output}");
    io::stdout().flush()?;
    Ok(ExitCode::SUCCESS)
}

pub fn resolve_export_path(path: &Path, is_example: bool) -> PathBuf {
    let default_name = if is_example {
        "apiman-export.env.example"
    } else {
        "apiman-export.env"
    };
    let raw = path.to_string_lossy();
    if raw.ends_with('/') || raw.ends_with('\\') || (path.exists() && path.is_dir()) {
        return path.join(default_name);
    }
    path.to_path_buf()
}

pub fn write_secret_file(path: &Path, content: &[u8]) -> Result<(), std::io::Error> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.exists() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension("tmp-export");
    std::fs::write(&tmp_path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(&tmp_path, perms);
    }
    std::fs::rename(&tmp_path, path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
    Ok(())
}

fn handle_timeout(
    custom_cfg: Option<&Path>,
    args: TimeoutArgs,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let cfg_path = custom_cfg
        .map(PathBuf::from)
        .unwrap_or_else(Config::config_file_path);
    let mut config =
        Config::load_from(&cfg_path).unwrap_or_else(|| Config::load_or_default());
    let socket_path = default_socket_path();

    if let Some(dur_str) = args.duration {
        let secs = parse_timeout_arg(&dur_str)?;
        config.auto_lock_timeout_seconds = secs;
        config.save_to(&cfg_path)?;

        let _ = update_daemon_timeout(&socket_path, secs);

        if secs == 0 {
            eprintln!("Auto-lock timeout disabled. Session will remain always unlocked.");
        } else {
            eprintln!("Auto-lock timeout set to {}", format_duration_friendly(secs));
        }
    } else {
        println!("Configured Timeout: {}", format_duration_friendly(config.auto_lock_timeout_seconds));
        if let Some((unlocked, remaining, current_timeout)) = check_daemon_status(&socket_path) {
            if current_timeout == 0 {
                println!("Active Session:     Unlocked (Always Unlocked)");
            } else if unlocked {
                println!("Active Session:     Unlocked ({}s remaining until lock)", remaining);
            } else {
                println!("Active Session:     Locked");
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub fn parse_timeout_arg(input: &str) -> Result<u64, String> {
    let lower = input.trim().to_lowercase();
    if matches!(
        lower.as_str(),
        "none" | "never" | "off" | "inf" | "infinite" | "0" | "disable" | "disabled"
    ) {
        return Ok(0);
    }

    if let Some(num_str) = lower.strip_suffix('s') {
        num_str
            .parse::<u64>()
            .map_err(|_| format!("Invalid seconds format '{input}'"))
    } else if let Some(num_str) = lower.strip_suffix('m') {
        let mins = num_str
            .parse::<u64>()
            .map_err(|_| format!("Invalid minutes format '{input}'"))?;
        Ok(mins * 60)
    } else if let Some(num_str) = lower.strip_suffix('h') {
        let hours = num_str
            .parse::<u64>()
            .map_err(|_| format!("Invalid hours format '{input}'"))?;
        Ok(hours * 3600)
    } else if let Some(num_str) = lower.strip_suffix('d') {
        let days = num_str
            .parse::<u64>()
            .map_err(|_| format!("Invalid days format '{input}'"))?;
        Ok(days * 86400)
    } else {
        lower.parse::<u64>().map_err(|_| {
            format!("Invalid duration '{input}'. Use e.g. '15m', '2h', '900s', '0', or 'none'.")
        })
    }
}

pub fn format_duration_friendly(secs: u64) -> String {
    if secs == 0 {
        "Disabled (Always Unlocked)".to_string()
    } else if secs % 3600 == 0 {
        format!("{}h ({}s)", secs / 3600, secs)
    } else if secs % 60 == 0 {
        format!("{}m ({}s)", secs / 60, secs)
    } else {
        format!("{}s", secs)
    }
}

fn handle_install(args: InstallArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let target_dir = resolve_install_dir(args.path.as_deref())
        .map_err(|e| format!("{e}"))?;
    let (target, in_path) = install_binary_to(&target_dir)?;
    eprintln!("Installed apiman binary to '{}'", target.display());
    if !in_path {
        eprintln!(
            "Warning: '{}' is not in your PATH, so 'apiman' will not resolve from a new shell.\nAdd this line to your ~/.bashrc or ~/.zshrc:\n  export PATH=\"{}:$PATH\"",
            target_dir.display(),
            target_dir.display()
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn handle_uninstall() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let target = uninstall_binary()?;
    eprintln!("Uninstalled apiman binary from '{}'", target.display());
    Ok(ExitCode::SUCCESS)
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

    let bin_path = installed_binary_path();
    if is_installed() {
        println!("Installed:    Yes ({})", bin_path.display());
    } else {
        println!("Installed:    No (run 'apiman install' to install to {})", bin_path.display());
    }

    if let Some((unlocked, remaining, timeout)) = check_daemon_status(&socket_path) {
        println!("Daemon:       Active (PID session)");
        println!("State:        {}", if unlocked { "Unlocked" } else { "Locked" });
        if timeout == 0 {
            println!("Auto-Lock:    Disabled (Always Unlocked)");
        } else {
            println!("Auto-Lock:    {}s / {}s timeout", remaining, timeout);
        }
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
