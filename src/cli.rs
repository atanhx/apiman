use clap::builder::styling::{AnsiColor, Effects, Style, Styles};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use std::collections::BTreeMap;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zeroize::Zeroizing;

use crate::agent::{agent_mode_reason, masked, refuse_in_agent_mode};
use crate::config::{Config, default_socket_path, expand_path};
use crate::crypto::{KeyParams, validate_new_password};
use crate::daemon::{
    check_daemon_status, get_cached_master_key, lock_daemon, run_daemon_loop, spawn_daemon,
    update_daemon_master_key, update_daemon_timeout,
};
use crate::dotenv::{
    EnvEntry, format_env, format_example, format_refs, format_shell, parse_dotenv,
};
use crate::install::{
    install_binary_to, installed_binary_path, is_installed, resolve_install_dir, uninstall_binary,
};
use crate::runner::{Masker, run_masked};
use crate::security::{SecretString, harden_process, read_secret_value, read_secure_password};
use crate::storage::{
    StorageError, VaultSignature, init_vault, load_vault_with_key, load_vault_with_password,
    lock_vault, rekey_vault, save_vault, vault_signature,
};
use crate::vault::{SecretRef, Vault, normalize_project, normalize_tags, validate_secret_name};

const STYLES: Styles = Styles::styled()
    .header(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
    .usage(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
    .literal(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
    .placeholder(AnsiColor::Cyan.on_default())
    .valid(AnsiColor::Green.on_default())
    .invalid(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
    .error(AnsiColor::Red.on_default().effects(Effects::BOLD));

const HEADING: Style = AnsiColor::Yellow.on_default().effects(Effects::BOLD);
const COMMENT: Style = AnsiColor::BrightBlack.on_default();

/// Help-text examples in clap's palette: a bold heading, commands as typed and
/// `#` comments dimmed. Lines starting with `! ` are plain notes. Styling is
/// dropped automatically when output is not a terminal or NO_COLOR is set.
fn ex(lines: &[&str]) -> String {
    let mut out = format!("{HEADING}Examples:{HEADING:#}\n");
    for line in lines {
        if line.is_empty() {
            out.push('\n');
        } else if let Some(note) = line.strip_prefix("! ") {
            out.push_str(&format!("\n{note}\n"));
        } else if let Some(comment) = line.strip_prefix("# ") {
            out.push_str(&format!("  {COMMENT}# {comment}{COMMENT:#}\n"));
        } else if let Some((cmd, comment)) = line.split_once("  # ") {
            out.push_str(&format!("  {cmd}  {COMMENT}# {comment}{COMMENT:#}\n"));
        } else {
            out.push_str(&format!("  {line}\n"));
        }
    }
    out.trim_end().to_string()
}

#[derive(Parser, Debug)]
#[command(
    name = "apiman",
    about = "Secure, minimal API credential manager with a TUI, process runner and local auth proxy",
    version,
    styles = STYLES,
    after_help = ex(&[
        "apiman                                                # open the TUI",
        "apiman set OPENAI_API_KEY                             # prompt for the value",
        "apiman set STRIPE_KEY --project billing --tags prod",
        "apiman copy OPENAI_API_KEY                            # clipboard, auto-cleared",
        "apiman run --only OPENAI_API_KEY -- python main.py    # inject into one process",
        "apiman run --env-file .env.apiman -- npm test         # resolve apiman:// references",
        "apiman proxy add --preset openai                      # key never leaves apiman",
        "apiman get GITHUB_TOKEN | gh auth login --with-token",
        "apiman timeout 30m",
        "! Run 'apiman <command> --help' for details on a command.",
    ]),
    arg_required_else_help = false
)]
pub struct Cli {
    #[arg(
        short,
        long,
        global = true,
        value_name = "FILE",
        help = "Custom configuration file path"
    )]
    pub config: Option<PathBuf>,

    #[arg(
        short,
        long,
        global = true,
        value_name = "FILE",
        help = "Custom encrypted vault file path"
    )]
    pub vault: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(
        about = "Initialize a new encrypted vault",
        after_help = ex(&["apiman init  # creates ~/.config/apiman/apiman_vault.enc"])
    )]
    Init,

    #[command(
        about = "Set or update a secret",
        after_help = ex(&[
            "apiman set OPENAI_API_KEY                   # hidden prompt",
            "apiman set DATABASE_URL --project backend",
            "apiman set TLS_KEY < key.pem                # multi-line value from stdin",
            "apiman set STRIPE_KEY --tags payment,prod --description \"Live key\"",
        ])
    )]
    Set(SetArgs),

    #[command(
        about = "Print a secret value (refuses an interactive terminal without --allow-view)",
        after_help = ex(&[
            "apiman get OPENAI_API_KEY --allow-view",
            "apiman get OPENAI_API_KEY | wl-copy",
            "apiman get apiman://billing/STRIPE_KEY | some-tool",
        ])
    )]
    Get(GetArgs),

    #[command(
        about = "Copy a secret to the clipboard and clear it after a timeout",
        after_help = ex(&[
            "apiman copy OPENAI_API_KEY",
            "apiman copy STRIPE_KEY --project billing",
            "! The clipboard is cleared after clipboard_timeout_seconds (default 30) if it still holds the secret.",
        ])
    )]
    Copy(CopyArgs),

    #[command(
        about = "List secrets without values",
        after_help = ex(&["apiman list", "apiman list --project billing --tag prod", "apiman list --format json"])
    )]
    List(ListArgs),

    #[command(
        about = "Delete a secret",
        after_help = ex(&[
            "apiman delete OPENAI_API_KEY",
            "apiman delete STRIPE_KEY --project billing",
            "! With --project only that project is searched. Without it, the global entry or the single project holding the name is used.",
        ])
    )]
    Delete(DeleteArgs),

    #[command(
        about = "Run a command with secrets injected into its environment",
        after_help = ex(&[
            "apiman run -- node index.js                       # all global secrets",
            "apiman run --project billing -- python app.py     # globals plus billing",
            "apiman run --only OPENAI_API_KEY -- pytest        # only what is needed",
            "apiman run --env-file .env.apiman -- npm start    # KEY=apiman://NAME references",
            "apiman run --mask -- ./ci.sh                      # hide values in the output",
            "! Environment variables holding apiman:// references are resolved too. In agent mode the program still gets real values but its output is masked.",
        ])
    )]
    Run(RunArgs),

    #[command(
        about = "Change the master password",
        after_help = ex(&["apiman passwd  # re-encrypts with a new Argon2id key, keeps the session"])
    )]
    Passwd,

    #[command(
        about = "Import secrets from a .env file",
        after_help = ex(&["apiman import ./.env", "apiman import ./backend/.env --project backend --tags prod"])
    )]
    Import(ImportArgs),

    #[command(
        about = "Export secrets as .env, shell exports, a .env.example, or apiman:// references",
        after_help = ex(&[
            "apiman export --output ./.env",
            "apiman export --project billing --output ./billing.env",
            "apiman export --format example --output ./.env.example",
            "apiman export --project billing --format refs --output .env.apiman",
            "eval \"$(apiman export --format shell --allow-view)\"",
        ])
    )]
    Export(ExportArgs),

    #[command(
        about = "Show or set the auto-lock timeout (15m, 2h, 900s, none)",
        after_help = ex(&["apiman timeout", "apiman timeout 30m", "apiman timeout none  # never auto-lock"])
    )]
    Timeout(TimeoutArgs),

    #[command(
        about = "Install the apiman binary to ~/.local/bin or a custom directory",
        after_help = ex(&["apiman install", "apiman install ~/bin"])
    )]
    Install(InstallArgs),

    #[command(
        about = "Remove the installed apiman binary",
        after_help = ex(&["apiman uninstall", "apiman uninstall ~/bin"])
    )]
    Uninstall(UninstallArgs),

    #[command(
        about = "Lock the vault and stop the session daemon",
        after_help = ex(&["apiman lock  # wipes the master key from memory"])
    )]
    Lock,

    #[command(
        about = "Unlock the vault and start the session daemon",
        after_help = ex(&["apiman unlock  # later commands, the TUI and the proxy reuse the session"])
    )]
    Unlock,

    #[command(
        about = "Show vault, session, agent mode and install status",
        after_help = ex(&["apiman status", "apiman status --format json"])
    )]
    Status(StatusArgs),

    #[command(
        subcommand,
        about = "Local auth proxy: apps and AI agents call APIs without holding the key",
        after_help = ex(&[
            "apiman proxy add --preset openai                 # /openai -> api.openai.com",
            "apiman proxy add stripe --secret STRIPE_KEY --upstream https://api.stripe.com",
            "apiman proxy start                               # 127.0.0.1:8787",
            "apiman proxy env                                 # base URLs for SDKs and agents",
            "curl http://127.0.0.1:8787/openai/v1/models      # key added by apiman",
        ])
    )]
    Proxy(ProxyCommand),

    #[command(
        about = "Print or install the agent skill (SKILL.md) for AI coding agents",
        after_help = ex(&[
            "apiman skill --install ~/.agents/skills   # writes ~/.agents/skills/apiman/SKILL.md",
            "apiman skill --install ~/.claude/skills",
            "apiman skill > SKILL.md",
        ])
    )]
    Skill(SkillArgs),

    #[command(
        about = "Show TUI keybindings and check custom ones in config.json",
        after_help = ex(&["apiman keys", "! Customize under \"keybindings\" in config.json, for example: \"keybindings\": { \"copy\": \"y\", \"lock\": [\"L\", \"ctrl+l\"] }"])
    )]
    Keys,

    #[command(
        about = "Print a shell completion script",
        after_help = ex(&[
            "apiman completions bash > ~/.local/share/bash-completion/completions/apiman",
            "apiman completions zsh > ~/.zfunc/_apiman",
            "apiman completions fish > ~/.config/fish/completions/apiman.fish",
        ])
    )]
    Completions(CompletionsArgs),

    #[command(about = "Open the interactive terminal UI (default with no command)")]
    Tui,

    #[command(hide = true)]
    Daemon(DaemonArgs),

    #[command(hide = true, name = "clipboard-clear")]
    ClipboardClear(ClipboardClearArgs),
}

#[derive(Args, Debug)]
pub struct SetArgs {
    #[arg(help = "Secret name (e.g. OPENAI_API_KEY)")]
    pub name: String,

    #[arg(help = "Secret value (if omitted: hidden prompt, or all of stdin when piped)")]
    pub value: Option<String>,

    #[arg(
        short,
        long,
        help = "Project scope (defaults to config default_project / global)"
    )]
    pub project: Option<String>,

    #[arg(short, long, value_delimiter = ',', help = "Comma-separated tags")]
    pub tags: Vec<String>,

    #[arg(short, long, help = "Description or notes (empty string clears it)")]
    pub description: Option<String>,
}

#[derive(Args, Debug)]
pub struct GetArgs {
    #[arg(help = "Secret name or apiman:// reference")]
    pub name: String,

    #[arg(short, long, help = "Project scope (falls back to global)")]
    pub project: Option<String>,

    #[arg(
        long,
        help = "Allow printing the raw secret to an interactive terminal"
    )]
    pub allow_view: bool,
}

#[derive(Args, Debug)]
pub struct CopyArgs {
    #[arg(help = "Secret name or apiman:// reference")]
    pub name: String,

    #[arg(short, long, help = "Project scope (falls back to global)")]
    pub project: Option<String>,
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
pub struct StatusArgs {
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Table, help = "Output format")]
    pub format: OutputFormat,
}

#[derive(Args, Debug)]
pub struct DeleteArgs {
    #[arg(help = "Secret name to delete")]
    pub name: String,

    #[arg(short, long, help = "Project scope (only this project is searched)")]
    pub project: Option<String>,
}

#[derive(Args, Debug)]
pub struct RunArgs {
    #[arg(
        short,
        long,
        help = "Project scope to load secrets from (globals are inherited)"
    )]
    pub project: Option<String>,

    #[arg(short, long, help = "Only inject secrets matching this tag")]
    pub tag: Option<String>,

    #[arg(
        long,
        value_delimiter = ',',
        value_name = "NAME",
        help = "Inject only these secrets (comma-separated) instead of the whole scope"
    )]
    pub only: Vec<String>,

    #[arg(
        long = "env-file",
        value_name = "FILE",
        help = "Load variables from a .env file; apiman:// values are resolved from the vault (repeatable)"
    )]
    pub env_file: Vec<PathBuf>,

    #[arg(
        long,
        help = "Replace injected values with [REDACTED:NAME] in the program's output (always on in agent mode)"
    )]
    pub mask: bool,

    #[arg(
        trailing_var_arg = true,
        required = true,
        help = "Program and arguments to run (e.g. -- node server.js)"
    )]
    pub command: Vec<String>,
}

#[derive(Args, Debug)]
pub struct ImportArgs {
    #[arg(help = "Path to the .env / .env.example file to import")]
    pub file: PathBuf,

    #[arg(
        short,
        long,
        help = "Project scope to import into (defaults to global)"
    )]
    pub project: Option<String>,

    #[arg(
        short,
        long,
        value_delimiter = ',',
        help = "Comma-separated tags applied to imported entries"
    )]
    pub tags: Vec<String>,
}

#[derive(Args, Debug)]
pub struct ExportArgs {
    #[arg(
        short,
        long,
        help = "Write to this file (or into this directory) instead of stdout"
    )]
    pub output: Option<PathBuf>,

    #[arg(
        short,
        long,
        help = "Project scope to export (includes inherited global entries)"
    )]
    pub project: Option<String>,

    #[arg(short, long, help = "Only export secrets matching this tag")]
    pub tag: Option<String>,

    #[arg(short, long, value_enum, default_value_t = ExportFormat::Env, help = "Output format")]
    pub format: ExportFormat,

    #[arg(long, help = "Allow printing secret values to an interactive terminal")]
    pub allow_view: bool,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportFormat {
    /// KEY=value lines (.env)
    Env,
    /// Keys only, empty values (.env.example)
    Example,
    /// `export KEY='value'` lines for eval
    Shell,
    /// KEY=apiman://project/KEY references, safe to commit
    Refs,
}

impl ExportFormat {
    fn contains_values(self) -> bool {
        matches!(self, Self::Env | Self::Shell)
    }
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
pub struct UninstallArgs {
    #[arg(
        help = "Custom directory to uninstall from (defaults to ~/.local/bin).",
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
pub struct CompletionsArgs {
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

#[derive(Subcommand, Debug)]
pub enum ProxyCommand {
    #[command(about = "Add or replace a route (requires a human: refused in agent mode)")]
    Add(ProxyAddArgs),
    #[command(about = "Remove a route")]
    Remove(ProxyRemoveArgs),
    #[command(about = "List routes (no secret values)")]
    List,
    #[command(about = "Print base URL / environment lines for apps and agents")]
    Env,
    #[command(about = "Run the proxy in the foreground")]
    Start(ProxyStartArgs),
}

#[derive(Args, Debug)]
pub struct ProxyAddArgs {
    #[arg(help = "Route alias: requests to http://127.0.0.1:PORT/<alias>/... use this route")]
    pub alias: Option<String>,

    #[arg(
        long,
        help = "Start from a known API: openai, anthropic, gemini, openrouter, groq, mistral, github"
    )]
    pub preset: Option<String>,

    #[arg(long, help = "Secret to inject (defaults to the preset's usual name)")]
    pub secret: Option<String>,

    #[arg(short, long, help = "Project scope of the secret")]
    pub project: Option<String>,

    #[arg(
        long,
        help = "Upstream base URL; the secret is only ever sent to this host"
    )]
    pub upstream: Option<String>,

    #[arg(
        long = "header",
        value_name = "'NAME: TEMPLATE'",
        help = "Header to add, {secret} is replaced (repeatable)"
    )]
    pub headers: Vec<String>,

    #[arg(
        long = "query",
        value_name = "'KEY=TEMPLATE'",
        help = "Query parameter to add, {secret} is replaced (repeatable)"
    )]
    pub query: Vec<String>,
}

#[derive(Args, Debug)]
pub struct ProxyRemoveArgs {
    pub alias: String,
}

#[derive(Args, Debug)]
pub struct ProxyStartArgs {
    #[arg(long, help = "Port (defaults to proxy_port in config, 8787)")]
    pub port: Option<u16>,

    #[arg(long, default_value = "127.0.0.1", help = "Loopback address to bind")]
    pub bind: String,
}

#[derive(Args, Debug)]
pub struct SkillArgs {
    #[arg(
        long,
        value_name = "SKILLS_DIR",
        help = "Write <SKILLS_DIR>/apiman/SKILL.md instead of printing"
    )]
    pub install: Option<PathBuf>,
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

#[derive(Args, Debug)]
pub struct ClipboardClearArgs {
    #[arg(long, default_value = "30")]
    pub after: u64,
}

pub struct SessionContext {
    pub config: Config,
    pub vault_path: PathBuf,
    pub socket_path: PathBuf,
    pub master_key: Zeroizing<[u8; 32]>,
    pub key_params: KeyParams,
    pub vault: Vault,
    disk_signature: Option<VaultSignature>,
}

impl SessionContext {
    pub fn new(
        config: Config,
        vault_path: PathBuf,
        socket_path: PathBuf,
        master_key: Zeroizing<[u8; 32]>,
        key_params: KeyParams,
        vault: Vault,
    ) -> Self {
        let disk_signature = vault_signature(&vault_path);
        Self {
            config,
            vault_path,
            socket_path,
            master_key,
            key_params,
            vault,
            disk_signature,
        }
    }

    fn reload_error(&self, e: StorageError) -> String {
        if e.is_wrong_key() {
            "The vault on disk can no longer be decrypted with this session's key (was the master password changed?). Restart apiman to unlock it again.".to_string()
        } else if matches!(e, StorageError::VaultNotFound) {
            format!(
                "Vault file '{}' no longer exists.",
                self.vault_path.display()
            )
        } else {
            e.to_string()
        }
    }

    /// Read-modify-write under the vault lock: the latest on-disk vault is
    /// reloaded, mutated and saved, so concurrent apiman processes (a TUI left
    /// open plus CLI calls) never overwrite each other's changes.
    pub fn update<R>(
        &mut self,
        mutate: impl FnOnce(&mut Vault) -> Result<R, String>,
    ) -> Result<R, String> {
        let _lock = lock_vault(&self.vault_path).map_err(|e| e.to_string())?;
        let (mut fresh, params) = load_vault_with_key(&self.master_key, &self.vault_path)
            .map_err(|e| self.reload_error(e))?;
        if params != self.key_params {
            return Err(self.reload_error(StorageError::Crypto(
                crate::crypto::CryptoError::DecryptionFailed,
            )));
        }
        let out = mutate(&mut fresh)?;
        save_vault(&fresh, &self.master_key, &self.key_params, &self.vault_path)
            .map_err(|e| e.to_string())?;
        self.vault = fresh;
        self.disk_signature = vault_signature(&self.vault_path);
        Ok(out)
    }

    /// Picks up changes written by other processes. `Ok(true)` when reloaded.
    pub fn reload_if_changed(&mut self) -> Result<bool, String> {
        let sig = vault_signature(&self.vault_path);
        if sig == self.disk_signature {
            return Ok(false);
        }
        self.disk_signature = sig;
        let (fresh, params) = load_vault_with_key(&self.master_key, &self.vault_path)
            .map_err(|e| self.reload_error(e))?;
        if params != self.key_params {
            return Err(self.reload_error(StorageError::Crypto(
                crate::crypto::CryptoError::DecryptionFailed,
            )));
        }
        self.vault = fresh;
        Ok(true)
    }
}

fn vault_path_for(config: &Config, custom_vault: Option<&Path>) -> PathBuf {
    custom_vault
        .map(expand_path)
        .unwrap_or_else(|| config.vault_path.clone())
}

pub fn load_session(
    custom_cfg: Option<&Path>,
    custom_vault: Option<&Path>,
    prompt_if_locked: bool,
) -> Result<SessionContext, Box<dyn std::error::Error>> {
    harden_process();

    let config = Config::load(custom_cfg)?;
    let vault_path = vault_path_for(&config, custom_vault);

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
        if let Ok((vault, params)) = load_vault_with_key(&cached_key, &vault_path) {
            return Ok(SessionContext::new(
                config,
                vault_path,
                socket_path,
                cached_key,
                params,
                vault,
            ));
        }
        // Daemon is alive but its key does not decrypt this vault
        // (stale key from another vault or an older session).
        stale_daemon = true;
    }

    if !prompt_if_locked {
        return Err("Vault is locked and daemon is not running".into());
    }

    // 2. Environment variable fallback for scripts/CI, else interactive prompt
    let env_pw = std::env::var("APIMAN_MASTER_PASSWORD")
        .or_else(|_| std::env::var("APIMAN_PASSWORD"))
        .ok()
        .map(Zeroizing::new);

    let (vault, master_key, params) = match env_pw {
        Some(pw) => load_vault_with_password(&pw, &vault_path)?,
        None => {
            let attempts = if io::stdin().is_terminal() { 3 } else { 1 };
            let mut attempt = 1;
            loop {
                let pw = Zeroizing::new(read_secure_password("Master password: ")?);
                match load_vault_with_password(&pw, &vault_path) {
                    Ok(loaded) => break loaded,
                    Err(e) if e.is_wrong_key() && attempt < attempts => {
                        eprintln!(
                            "Incorrect password, try again ({}/{attempts}).",
                            attempt + 1
                        );
                        attempt += 1;
                    }
                    Err(e) if e.is_wrong_key() => {
                        return Err(
                            "Incorrect master password (or the vault was tampered with)".into()
                        );
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
    };

    if stale_daemon {
        // Replace the stale daemon so its wrong key stops shadowing this vault.
        let _ = lock_daemon(&socket_path);
    }

    if let Err(e) = spawn_daemon(&master_key, config.auto_lock_timeout_seconds, &socket_path) {
        eprintln!("Warning: {e}; the password will be asked again next time.");
    }

    Ok(SessionContext::new(
        config,
        vault_path,
        socket_path,
        master_key,
        params,
        vault,
    ))
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
        Commands::Copy(args) => handle_copy(custom_cfg, custom_vault, args),
        Commands::List(args) => handle_list(custom_cfg, custom_vault, args),
        Commands::Delete(args) => handle_delete(custom_cfg, custom_vault, args),
        Commands::Run(args) => handle_run(custom_cfg, custom_vault, args),
        Commands::Passwd => handle_passwd(custom_cfg, custom_vault),
        Commands::Import(args) => handle_import(custom_cfg, custom_vault, args),
        Commands::Export(args) => handle_export(custom_cfg, custom_vault, args),
        Commands::Timeout(args) => handle_timeout(custom_cfg, args),
        Commands::Install(args) => handle_install(args),
        Commands::Uninstall(args) => handle_uninstall(args),
        Commands::Lock => handle_lock(),
        Commands::Unlock => handle_unlock(custom_cfg, custom_vault),
        Commands::Status(args) => handle_status(custom_cfg, custom_vault, args),
        Commands::Keys => handle_keys(custom_cfg),
        Commands::Proxy(cmd) => handle_proxy(custom_cfg, custom_vault, cmd),
        Commands::Skill(args) => handle_skill(args),
        Commands::Completions(args) => {
            clap_complete::generate(args.shell, &mut Cli::command(), "apiman", &mut io::stdout());
            Ok(ExitCode::SUCCESS)
        }
        Commands::Tui => Ok(ExitCode::SUCCESS),
        Commands::Daemon(args) => handle_daemon(args),
        Commands::ClipboardClear(args) => {
            crate::clipboard::run_clear_helper(args.after)?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn fail(msg: impl std::fmt::Display) -> Result<ExitCode, Box<dyn std::error::Error>> {
    eprintln!("Error: {msg}");
    Ok(ExitCode::FAILURE)
}

fn read_new_password(prompt: &str, confirm_prompt: &str) -> Result<Zeroizing<String>, String> {
    let pw1 = Zeroizing::new(read_secure_password(prompt).map_err(|e| e.to_string())?);
    validate_new_password(&pw1)?;
    let pw2 = Zeroizing::new(read_secure_password(confirm_prompt).map_err(|e| e.to_string())?);
    if *pw1 != *pw2 {
        return Err("Passwords do not match".to_string());
    }
    Ok(pw1)
}

/// Creates a vault at `vault_path` and starts a session for it.
pub fn create_vault_interactive(config: &Config, vault_path: &Path) -> Result<(), String> {
    let password = read_new_password("Enter new master password: ", "Confirm master password: ")?;
    let (_, master_key, _) = init_vault(&password, vault_path).map_err(|e| e.to_string())?;

    let socket_path = default_socket_path();
    // Drop any live daemon holding a key for a previous vault.
    let _ = lock_daemon(&socket_path);
    if let Err(e) = spawn_daemon(&master_key, config.auto_lock_timeout_seconds, &socket_path) {
        eprintln!("Warning: {e}");
    }
    eprintln!(
        "Vault initialized successfully at '{}'",
        vault_path.display()
    );
    Ok(())
}

fn handle_init(
    custom_cfg: Option<&Path>,
    custom_vault: Option<&Path>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let config = Config::load(custom_cfg)?;
    let vault_path = vault_path_for(&config, custom_vault);

    if vault_path.exists() {
        eprint!(
            "Vault already exists at '{}'. Replace it with a new empty vault? [y/N]: ",
            vault_path.display()
        );
        io::stderr().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            eprintln!("Initialization aborted.");
            return Ok(ExitCode::FAILURE);
        }
        let backup = vault_path.with_file_name(format!(
            "{}.bak",
            vault_path.file_name().unwrap_or_default().to_string_lossy()
        ));
        std::fs::rename(&vault_path, &backup)?;
        eprintln!("Previous vault kept as '{}'", backup.display());
    }

    match create_vault_interactive(&config, &vault_path) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(e) => fail(e),
    }
}

fn handle_set(
    custom_cfg: Option<&Path>,
    custom_vault: Option<&Path>,
    args: SetArgs,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let name = validate_secret_name(&args.name)?;
    let mut ctx = load_session(custom_cfg, custom_vault, true)?;

    let value = match args.value {
        Some(v) => Zeroizing::new(v),
        None => read_secret_value(&format!("Enter secret value for '{name}': "))?,
    };
    if value.is_empty() {
        return fail("Secret value cannot be empty");
    }

    let project = match args.project.as_deref() {
        Some(p) => normalize_project(Some(p)),
        None => ctx.config.default_scope(),
    };
    let tags = args.tags;
    let description = args.description;

    let scope = ctx.update(|v| {
        let entry = v.set(
            name.clone(),
            SecretString::new(value.as_str()),
            project,
            tags,
            description,
        );
        Ok(entry.project_display().to_string())
    })?;
    eprintln!("Secret '{name}' saved (scope: {scope})");
    Ok(ExitCode::SUCCESS)
}

fn lookup_target(name: &str, project: Option<&str>) -> (String, Option<String>) {
    match SecretRef::parse(name) {
        Some(r) => (r.name, r.project.or_else(|| project.map(str::to_string))),
        None => (name.to_string(), project.map(str::to_string)),
    }
}

fn handle_get(
    custom_cfg: Option<&Path>,
    custom_vault: Option<&Path>,
    args: GetArgs,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let config = Config::load(custom_cfg)?;
    let agent = agent_mode_reason(&config);

    let is_tty = io::stdout().is_terminal();
    if is_tty && !args.allow_view && agent.is_none() {
        eprintln!(
            "Notice: Refusing to print a secret to an interactive terminal without --allow-view.\nUse 'apiman get {0} --allow-view', 'apiman copy {0}', or pipe the output ('apiman get {0} | wl-copy').",
            args.name
        );
        return Ok(ExitCode::FAILURE);
    }

    let ctx = load_session(custom_cfg, custom_vault, true)?;
    let (name, project) = lookup_target(&args.name, args.project.as_deref());
    let entry = match ctx.vault.resolve(&name, project.as_deref()) {
        Ok(e) => e,
        Err(e) => return fail(e),
    };

    let mut out = io::stdout();
    if let Some(reason) = agent {
        writeln!(out, "{}", masked(&entry.name))?;
        eprintln!(
            "Note: agent mode ({reason}): values are masked. Use `apiman run --only {} -- <cmd>` to use it.",
            entry.name
        );
    } else if is_tty {
        writeln!(out, "{}", entry.value.expose_secret())?;
    } else {
        // Piped output: raw value without a trailing newline
        write!(out, "{}", entry.value.expose_secret())?;
    }
    out.flush()?;
    Ok(ExitCode::SUCCESS)
}

fn handle_copy(
    custom_cfg: Option<&Path>,
    custom_vault: Option<&Path>,
    args: CopyArgs,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let config = Config::load(custom_cfg)?;
    if let Err(e) = refuse_in_agent_mode(&config, "copy a secret to the clipboard") {
        return fail(e);
    }
    let ctx = load_session(custom_cfg, custom_vault, true)?;
    let (name, project) = lookup_target(&args.name, args.project.as_deref());
    let entry = match ctx.vault.resolve(&name, project.as_deref()) {
        Ok(e) => e,
        Err(e) => return fail(e),
    };
    match crate::clipboard::copy_secret(
        entry.value.expose_secret(),
        ctx.config.clipboard_timeout_seconds,
    ) {
        Ok(note) => {
            eprintln!(
                "Copied '{}' ({}) to clipboard, {note}",
                entry.name,
                entry.project_display()
            );
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => fail(e),
    }
}

fn truncate_cell(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(3)).collect();
        t.push_str("...");
        t
    }
}

fn handle_list(
    custom_cfg: Option<&Path>,
    custom_vault: Option<&Path>,
    args: ListArgs,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let ctx = load_session(custom_cfg, custom_vault, true)?;
    let mut entries = ctx.vault.list(args.project.as_deref(), args.tag.as_deref());
    entries.sort_by(|a, b| {
        (!a.is_global(), a.project_display().to_lowercase(), &a.name).cmp(&(
            !b.is_global(),
            b.project_display().to_lowercase(),
            &b.name,
        ))
    });

    if let Some(p) = args.project.as_deref() {
        let p = p.trim();
        if !p.eq_ignore_ascii_case("all")
            && !p.eq_ignore_ascii_case("global")
            && !ctx.vault.has_project(p)
        {
            eprintln!("Note: no entries in project '{p}'; showing inherited global entries only.");
        }
    }

    if args.format == OutputFormat::Json {
        let serializable: Vec<_> = entries
            .into_iter()
            .map(|e| {
                serde_json::json!({
                    "name": e.name,
                    "project": e.project_display(),
                    "reference": SecretRef { project: e.project.clone(), name: e.name.clone() }.to_string(),
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

    let rows: Vec<[String; 4]> = entries
        .iter()
        .map(|e| {
            [
                truncate_cell(&e.name, 40),
                truncate_cell(e.project_display(), 20),
                truncate_cell(
                    &if e.tags.is_empty() {
                        "-".to_string()
                    } else {
                        e.tags.join(",")
                    },
                    30,
                ),
                e.description.clone().unwrap_or_else(|| "-".to_string()),
            ]
        })
        .collect();
    let headers = ["NAME", "PROJECT", "TAGS", "DESCRIPTION"];
    let width = |i: usize| {
        rows.iter()
            .map(|r| r[i].chars().count())
            .chain(std::iter::once(headers[i].len()))
            .max()
            .unwrap_or(0)
    };
    let (w0, w1, w2) = (width(0), width(1), width(2));
    println!(
        "{:<w0$}  {:<w1$}  {:<w2$}  {}",
        headers[0], headers[1], headers[2], headers[3]
    );
    println!("{}", "-".repeat(w0 + w1 + w2 + 6 + width(3)));
    for r in rows {
        println!("{:<w0$}  {:<w1$}  {:<w2$}  {}", r[0], r[1], r[2], r[3]);
    }
    Ok(ExitCode::SUCCESS)
}

fn handle_delete(
    custom_cfg: Option<&Path>,
    custom_vault: Option<&Path>,
    args: DeleteArgs,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut ctx = load_session(custom_cfg, custom_vault, true)?;

    // An explicit --project never falls back to another scope: deleting the
    // global entry when the user named a project would be a nasty surprise.
    let target = match args.project.as_deref() {
        Some(p) => {
            let scope = normalize_project(Some(p));
            ctx.vault
                .find_in_scope(&args.name, scope.as_deref())
                .ok_or_else(|| {
                    format!(
                        "Secret '{}' not found in scope '{}'",
                        args.name.trim(),
                        scope.as_deref().unwrap_or("global")
                    )
                })
        }
        None => ctx
            .vault
            .resolve(&args.name, None)
            .map_err(|e| e.to_string()),
    };
    let (id, name, scope) = match target {
        Ok(e) => (
            e.id.clone(),
            e.name.clone(),
            e.project_display().to_string(),
        ),
        Err(e) => return fail(e),
    };

    ctx.update(|v| {
        let before = v.entries.len();
        v.entries.retain(|e| e.id != id);
        if v.entries.len() == before {
            return Err(format!("Secret '{name}' was already removed"));
        }
        Ok(())
    })?;
    eprintln!("Secret '{name}' deleted from scope '{scope}'");
    Ok(ExitCode::SUCCESS)
}

fn handle_run(
    custom_cfg: Option<&Path>,
    custom_vault: Option<&Path>,
    args: RunArgs,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let ctx = load_session(custom_cfg, custom_vault, true)?;
    let agent = agent_mode_reason(&ctx.config);
    let project = args.project.as_deref();

    // Secrets (masked) and plain variables from --env-file literals.
    let mut secrets: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
    let mut plain: BTreeMap<String, String> = BTreeMap::new();

    for (key, value) in std::env::vars() {
        if let Some(reference) = SecretRef::parse(&value) {
            match ctx.vault.resolve_ref(&reference) {
                Ok(e) => {
                    secrets.insert(key, Zeroizing::new(e.value.expose_secret().to_string()));
                }
                Err(e) => return fail(format!("${key}={reference}: {e}")),
            }
        }
    }

    if args.only.is_empty() && args.env_file.is_empty() {
        if let Some(p) = project
            && normalize_project(Some(p)).is_some()
            && !ctx.vault.has_project(p)
        {
            eprintln!(
                "Warning: no secrets in project '{}'; only global secrets are injected.",
                p.trim()
            );
        }
        secrets.extend(ctx.vault.resolve_env_map(project, args.tag.as_deref()));
    }

    for name in args.only.iter().map(|n| n.trim()).filter(|n| !n.is_empty()) {
        let (name, scope) = lookup_target(name, project);
        match ctx.vault.resolve(&name, scope.as_deref()) {
            Ok(e) => {
                secrets.insert(
                    e.name.clone(),
                    Zeroizing::new(e.value.expose_secret().to_string()),
                );
            }
            Err(e) => return fail(e),
        }
    }

    for file in &args.env_file {
        let content = match std::fs::read_to_string(file) {
            Ok(c) => c,
            Err(e) => return fail(format!("Cannot read env file '{}': {e}", file.display())),
        };
        for entry in parse_dotenv(&content).0 {
            match SecretRef::parse(&entry.value) {
                Some(reference) => match ctx.vault.resolve_ref(&reference) {
                    Ok(e) => {
                        plain.remove(&entry.key);
                        secrets.insert(
                            entry.key,
                            Zeroizing::new(e.value.expose_secret().to_string()),
                        );
                    }
                    Err(e) => {
                        return fail(format!(
                            "{}: {}={reference}: {e}",
                            file.display(),
                            entry.key
                        ));
                    }
                },
                None => {
                    secrets.remove(&entry.key);
                    plain.insert(entry.key, entry.value);
                }
            }
        }
    }

    let mask = args.mask || agent.is_some();

    let prog = &args.command[0];
    let mut child = std::process::Command::new(prog);
    child.args(&args.command[1..]);
    // Never leak the master password itself into the child environment.
    child.env_remove("APIMAN_MASTER_PASSWORD");
    child.env_remove("APIMAN_PASSWORD");
    for (k, v) in &plain {
        child.env(k, v);
    }
    for (k, v) in &secrets {
        child.env(k, v.as_str());
    }

    let not_found = |prog: &str| {
        eprintln!(
            "Error: Command '{prog}' was not found in system PATH.\n\n\
             Usage: apiman run [OPTIONS] -- <PROGRAM> [ARGS...]\n\
             Examples:\n  \
               apiman run -- node server.js\n  \
               apiman run --only OPENAI_API_KEY -- python main.py\n  \
               apiman run --project billing -- npm start\n\n\
             To retrieve a secret value instead of executing a program, use:\n  \
               apiman get {prog}"
        );
        ExitCode::FAILURE
    };

    if mask {
        let masker = Masker::new(secrets.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        drop(ctx);
        return match run_masked(child, masker) {
            Ok(code) => Ok(ExitCode::from(code.clamp(0, 255) as u8)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(not_found(prog)),
            Err(e) => fail(format!("Failed to run '{prog}': {e}")),
        };
    }

    // Unmasked: replace this process so signals, the terminal and the exit
    // status belong to the program, and the decrypted vault is gone from memory.
    use std::os::unix::process::CommandExt;
    drop(secrets);
    drop(ctx);
    let err = child.exec();
    if err.kind() == io::ErrorKind::NotFound {
        return Ok(not_found(prog));
    }
    fail(format!("Failed to run '{prog}': {err}"))
}

fn handle_passwd(
    custom_cfg: Option<&Path>,
    custom_vault: Option<&Path>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let ctx = load_session(custom_cfg, custom_vault, true)?;

    let new_password = match read_new_password(
        "Enter new master password: ",
        "Confirm new master password: ",
    ) {
        Ok(p) => p,
        Err(e) => return fail(e),
    };

    let new_key = {
        let _lock = lock_vault(&ctx.vault_path)?;
        let (latest, _) = load_vault_with_key(&ctx.master_key, &ctx.vault_path)?;
        rekey_vault(&latest, &new_password, &ctx.vault_path)?.0
    };

    // Keep the active session working with the new key.
    let _ = update_daemon_master_key(&ctx.socket_path, &new_key);

    eprintln!(
        "Master password updated successfully for '{}'",
        ctx.vault_path.display()
    );
    Ok(ExitCode::SUCCESS)
}

fn handle_import(
    custom_cfg: Option<&Path>,
    custom_vault: Option<&Path>,
    args: ImportArgs,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let file = expand_path(&args.file);
    if !file.exists() {
        return fail(format!("File '{}' not found.", file.display()));
    }
    if file.is_dir() {
        return fail(format!(
            "'{}' is a directory. Provide a .env file path to import.",
            file.display()
        ));
    }

    let content = Zeroizing::new(std::fs::read_to_string(&file)?);
    let (entries, skipped) = parse_dotenv(&content);

    let mut ctx = load_session(custom_cfg, custom_vault, true)?;
    let project = match args.project.as_deref() {
        Some(p) => normalize_project(Some(p)),
        None => ctx.config.default_scope(),
    };
    let tags = normalize_tags(args.tags);

    let summary = import_entries(&mut ctx, entries, project.clone(), tags)?;
    let scope_msg = project.as_deref().unwrap_or("global");
    eprintln!(
        "Imported {} entr{} into scope '{scope_msg}' (skipped {} invalid lines, {} empty placeholders).",
        summary.imported,
        if summary.imported == 1 { "y" } else { "ies" },
        skipped + summary.invalid_names,
        summary.empty,
    );
    Ok(ExitCode::SUCCESS)
}

pub struct ImportSummary {
    pub imported: usize,
    pub empty: usize,
    pub invalid_names: usize,
}

pub fn import_entries(
    ctx: &mut SessionContext,
    entries: Vec<EnvEntry>,
    project: Option<String>,
    tags: Vec<String>,
) -> Result<ImportSummary, String> {
    ctx.update(|v| {
        let mut summary = ImportSummary {
            imported: 0,
            empty: 0,
            invalid_names: 0,
        };
        for e in entries {
            if e.value.is_empty() || SecretRef::parse(&e.value).is_some() {
                summary.empty += 1;
                continue;
            }
            let Ok(key) = validate_secret_name(&e.key) else {
                summary.invalid_names += 1;
                continue;
            };
            v.set(
                key,
                SecretString::new(e.value.as_str()),
                project.clone(),
                tags.clone(),
                None,
            );
            summary.imported += 1;
        }
        Ok(summary)
    })
}

/// `KEY=value` entries for an export scope. Mirrors `run`: globals overlaid
/// by the project's own entries.
fn export_entries(vault: &Vault, project: Option<&str>, tag: Option<&str>) -> Vec<EnvEntry> {
    vault
        .resolve_env_map(project, tag)
        .into_iter()
        .map(|(key, value)| EnvEntry {
            key,
            value: value.to_string(),
        })
        .collect()
}

fn handle_export(
    custom_cfg: Option<&Path>,
    custom_vault: Option<&Path>,
    args: ExportArgs,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let config = Config::load(custom_cfg)?;
    let agent = agent_mode_reason(&config).filter(|_| args.format.contains_values());
    if agent.is_some() && args.output.is_some() {
        // A file of masked values is useless and would clobber a real .env.
        return fail(refuse_in_agent_mode(&config, "write secret values to a file").unwrap_err());
    }
    if args.format.contains_values()
        && agent.is_none()
        && args.output.is_none()
        && io::stdout().is_terminal()
        && !args.allow_view
    {
        eprintln!(
            "Notice: Refusing to print secrets to an interactive terminal without --allow-view.\nUse 'apiman export --output FILE', pipe the output ('apiman export | wl-copy'), or pass --allow-view."
        );
        return Ok(ExitCode::FAILURE);
    }

    let ctx = load_session(custom_cfg, custom_vault, true)?;
    let project = args.project.as_deref();
    if let Some(p) = project
        && normalize_project(Some(p)).is_some()
        && !ctx.vault.has_project(p)
    {
        eprintln!(
            "Warning: no entries in project '{}'; exporting global entries only.",
            p.trim()
        );
    }

    let mut entries = export_entries(&ctx.vault, project, args.tag.as_deref());
    if agent.is_some() {
        for e in &mut entries {
            e.value = masked(&e.key);
        }
    }
    let output = Zeroizing::new(match args.format {
        ExportFormat::Env => format_env(&entries),
        ExportFormat::Shell => format_shell(&entries),
        ExportFormat::Example => {
            format_example(&entries.iter().map(|e| e.key.clone()).collect::<Vec<_>>())
        }
        ExportFormat::Refs => {
            let refs: Vec<(String, String)> = entries
                .iter()
                .filter_map(|e| ctx.vault.resolve(&e.key, project).ok())
                .map(|e| {
                    (
                        e.name.clone(),
                        SecretRef {
                            project: e.project.clone(),
                            name: e.name.clone(),
                        }
                        .to_string(),
                    )
                })
                .collect();
            format_refs(&refs)
        }
    });

    if let Some(out_path) = args.output {
        let resolved = resolve_export_path(&expand_path(&out_path), args.format);
        write_secret_file(&resolved, output.as_bytes())?;
        eprintln!(
            "Exported {} entr{} to '{}'",
            entries.len(),
            if entries.len() == 1 { "y" } else { "ies" },
            resolved.display()
        );
        return Ok(ExitCode::SUCCESS);
    }

    let mut out = io::stdout();
    out.write_all(output.as_bytes())?;
    out.flush()?;
    Ok(ExitCode::SUCCESS)
}

pub fn resolve_export_path(path: &Path, format: ExportFormat) -> PathBuf {
    let default_name = match format {
        ExportFormat::Example => "apiman-export.env.example",
        ExportFormat::Refs => ".env.apiman",
        ExportFormat::Shell => "apiman-export.sh",
        ExportFormat::Env => "apiman-export.env",
    };
    let raw = path.to_string_lossy();
    if raw.ends_with('/') || path.is_dir() {
        return path.join(default_name);
    }
    path.to_path_buf()
}

/// Atomic 0600 write: the content never exists world-readable and a planted
/// symlink at the destination is replaced rather than followed.
pub fn write_secret_file(path: &Path, content: &[u8]) -> Result<(), io::Error> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    std::fs::create_dir_all(parent)?;
    let mut tmp = tempfile::Builder::new()
        .prefix(".apiman-export-")
        .tempfile_in(parent)?;
    tmp.write_all(content)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

fn handle_timeout(
    custom_cfg: Option<&Path>,
    args: TimeoutArgs,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let cfg_path = custom_cfg
        .map(expand_path)
        .unwrap_or_else(Config::config_file_path);
    let mut config = Config::load(custom_cfg)?;
    let socket_path = default_socket_path();

    if let Some(dur_str) = args.duration {
        let secs = parse_timeout_arg(&dur_str)?;
        config.auto_lock_timeout_seconds = secs;
        config.save_to(&cfg_path)?;

        let _ = update_daemon_timeout(&socket_path, secs);

        if secs == 0 {
            eprintln!("Auto-lock timeout disabled. Session will remain always unlocked.");
        } else {
            eprintln!(
                "Auto-lock timeout set to {}",
                format_duration_friendly(secs)
            );
        }
    } else {
        println!(
            "Configured Timeout: {}",
            format_duration_friendly(config.auto_lock_timeout_seconds)
        );
        if let Some((_, remaining, current_timeout)) = check_daemon_status(&socket_path) {
            if current_timeout == 0 {
                println!("Active Session:     Unlocked (Always Unlocked)");
            } else {
                println!(
                    "Active Session:     Unlocked ({} remaining until lock)",
                    format_duration_short(remaining)
                );
            }
        } else {
            println!("Active Session:     Locked");
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

    let invalid =
        || format!("Invalid duration '{input}'. Use e.g. '15m', '2h', '900s', '0', or 'none'.");
    let (num_str, unit) = match lower.char_indices().last() {
        Some((i, c)) if c.is_ascii_alphabetic() => (&lower[..i], c),
        _ => (lower.as_str(), 's'),
    };
    let multiplier = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        _ => return Err(invalid()),
    };
    num_str
        .trim()
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(multiplier))
        .ok_or_else(invalid)
}

pub fn format_duration_friendly(secs: u64) -> String {
    if secs == 0 {
        "Disabled (Always Unlocked)".to_string()
    } else if secs.is_multiple_of(3600) {
        format!("{}h ({}s)", secs / 3600, secs)
    } else if secs.is_multiple_of(60) {
        format!("{}m ({}s)", secs / 60, secs)
    } else {
        format!("{}s", secs)
    }
}

pub fn format_duration_short(secs: u64) -> String {
    match secs {
        0..60 => format!("{secs}s"),
        60..3600 if secs.is_multiple_of(60) => format!("{}m", secs / 60),
        60..3600 => format!("{}m {}s", secs / 60, secs % 60),
        _ if secs.is_multiple_of(3600) => format!("{}h", secs / 3600),
        _ => format!("{}h {}m", secs / 3600, (secs % 3600) / 60),
    }
}

fn handle_install(args: InstallArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let target_dir = resolve_install_dir(args.path.as_deref())?;
    let outcome = install_binary_to(&target_dir)?;
    if outcome.already_current {
        eprintln!(
            "apiman is already installed at '{}' (this binary).",
            outcome.path.display()
        );
    } else {
        eprintln!("Installed apiman binary to '{}'", outcome.path.display());
    }
    if !outcome.in_path {
        eprintln!(
            "Warning: '{0}' is not in your PATH, so 'apiman' will not resolve from a new shell.\nAdd this line to your ~/.bashrc or ~/.zshrc:\n  export PATH=\"{0}:$PATH\"",
            target_dir.display()
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn handle_uninstall(args: UninstallArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let target = uninstall_binary(args.path.as_deref())?;
    eprintln!("Uninstalled apiman binary from '{}'", target.display());
    Ok(ExitCode::SUCCESS)
}

fn handle_lock() -> Result<ExitCode, Box<dyn std::error::Error>> {
    lock_daemon(&default_socket_path())?;
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
    custom_cfg: Option<&Path>,
    custom_vault: Option<&Path>,
    args: StatusArgs,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let config = Config::load(custom_cfg)?;
    let vault_path = vault_path_for(&config, custom_vault);
    let daemon = check_daemon_status(&default_socket_path());
    let agent = agent_mode_reason(&config);
    let bin_path = installed_binary_path();

    if args.format == OutputFormat::Json {
        let status = serde_json::json!({
            "vault_path": vault_path,
            "vault_exists": vault_path.exists(),
            "unlocked": daemon.is_some(),
            "auto_lock_timeout_seconds": daemon.map(|d| d.2).unwrap_or(config.auto_lock_timeout_seconds),
            "remaining_seconds": daemon.map(|d| d.1),
            "agent_mode": agent.is_some(),
            "proxy_port": config.proxy_port,
            "agent_mode_reason": agent,
            "installed": is_installed(),
            "install_path": bin_path,
        });
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(ExitCode::SUCCESS);
    }

    println!("Vault Path:   {}", vault_path.display());
    println!("Exists:       {}", vault_path.exists());
    if is_installed() {
        println!("Installed:    Yes ({})", bin_path.display());
    } else {
        println!(
            "Installed:    No (run 'apiman install' to install to {})",
            bin_path.display()
        );
    }
    match daemon {
        Some((_, remaining, timeout)) => {
            println!("Session:      Unlocked (daemon running)");
            if timeout == 0 {
                println!("Auto-Lock:    Disabled (Always Unlocked)");
            } else {
                println!(
                    "Auto-Lock:    in {} (after {} idle)",
                    format_duration_short(remaining),
                    format_duration_short(timeout)
                );
            }
        }
        None => println!("Session:      Locked (no daemon)"),
    }
    match agent {
        Some(reason) => println!("Agent Mode:   On ({reason}); values are never printed"),
        None => println!("Agent Mode:   Off"),
    }
    Ok(ExitCode::SUCCESS)
}

fn handle_keys(custom_cfg: Option<&Path>) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let config = Config::load(custom_cfg)?;
    let (keymap, problems) = crate::tui::keymap::Keymap::from_config(&config.keybindings);
    println!("{:<18} {:<28} DESCRIPTION", "ACTION", "KEYS");
    for action in crate::tui::keymap::Action::ALL {
        println!(
            "{:<18} {:<28} {}",
            action.config_name(),
            keymap.keys_label(*action),
            action.description()
        );
    }
    if problems.is_empty() {
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!();
        for p in &problems {
            eprintln!("Config problem: {p}");
        }
        Ok(ExitCode::FAILURE)
    }
}

fn handle_daemon(args: DaemonArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    if args.run {
        run_daemon_loop(args.timeout, args.socket)?;
    }
    Ok(ExitCode::SUCCESS)
}

fn handle_proxy(
    custom_cfg: Option<&Path>,
    custom_vault: Option<&Path>,
    cmd: ProxyCommand,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    use crate::proxy::{
        PRESETS, ProxyServer, build_route, env_lines, find_preset, is_loopback_bind,
        parse_header_template, parse_query_template, serve, vault_routes_summary,
    };

    let config = Config::load(custom_cfg)?;
    match cmd {
        ProxyCommand::Add(args) => {
            if let Err(e) = refuse_in_agent_mode(&config, "change proxy routes") {
                return fail(e);
            }
            let preset = match args.preset.as_deref() {
                Some(name) => match find_preset(name) {
                    Some(p) => Some(p),
                    None => {
                        let names: Vec<&str> = PRESETS.iter().map(|p| p.name).collect();
                        return fail(format!(
                            "Unknown preset '{name}' (available: {})",
                            names.join(", ")
                        ));
                    }
                },
                None => None,
            };
            let Some(alias) = args
                .alias
                .clone()
                .or_else(|| preset.map(|p| p.name.to_string()))
            else {
                return fail(
                    "Give the route an alias (e.g. 'apiman proxy add stripe ...') or use --preset",
                );
            };
            let Some(secret) = args
                .secret
                .clone()
                .or_else(|| preset.map(|p| p.secret.to_string()))
            else {
                return fail("--secret is required without a preset");
            };
            let Some(upstream) = args
                .upstream
                .clone()
                .or_else(|| preset.map(|p| p.upstream.to_string()))
            else {
                return fail(
                    "--upstream is required without a preset (e.g. https://api.example.com)",
                );
            };
            let mut headers = Vec::new();
            for h in &args.headers {
                headers.push(parse_header_template(h)?);
            }
            let mut query = Vec::new();
            for q in &args.query {
                query.push(parse_query_template(q)?);
            }
            if headers.is_empty() && query.is_empty() {
                let (name, template) = preset
                    .map(|p| p.header)
                    .unwrap_or(("Authorization", "Bearer {secret}"));
                headers.push((name.to_string(), template.to_string()));
            }
            let route = build_route(
                &alias,
                &secret,
                args.project.as_deref(),
                &upstream,
                headers,
                query,
            )?;

            let mut ctx = load_session(custom_cfg, custom_vault, true)?;
            if ctx.vault.resolve_ref(&route.secret_ref()).is_err() {
                eprintln!(
                    "Warning: secret '{}' is not in the vault yet; add it with 'apiman set {}'",
                    route.secret_ref(),
                    route.secret
                );
            }
            let summary = format!(
                "{} -> {}",
                crate::proxy::local_base_url(ctx.config.proxy_port, &route),
                route.upstream
            );
            let alias = route.alias.clone();
            ctx.update(move |v| {
                v.proxy_routes.retain(|r| r.alias != route.alias);
                v.proxy_routes.push(route);
                v.proxy_routes.sort_by(|a, b| a.alias.cmp(&b.alias));
                Ok(())
            })?;
            eprintln!("Route '{alias}' saved: {summary}");
            Ok(ExitCode::SUCCESS)
        }
        ProxyCommand::Remove(args) => {
            if let Err(e) = refuse_in_agent_mode(&config, "change proxy routes") {
                return fail(e);
            }
            let alias = args.alias.trim().to_ascii_lowercase();
            let mut ctx = load_session(custom_cfg, custom_vault, true)?;
            let removed = ctx.update(|v| {
                let before = v.proxy_routes.len();
                v.proxy_routes.retain(|r| r.alias != alias);
                Ok(before != v.proxy_routes.len())
            })?;
            if !removed {
                return fail(format!("No route named '{alias}'"));
            }
            eprintln!("Route '{alias}' removed");
            Ok(ExitCode::SUCCESS)
        }
        ProxyCommand::List => {
            let ctx = load_session(custom_cfg, custom_vault, true)?;
            if ctx.vault.proxy_routes.is_empty() {
                println!("No proxy routes. Add one with 'apiman proxy add --preset openai'.");
                return Ok(ExitCode::SUCCESS);
            }
            println!(
                "{:<12} {:<38} {:<40} SECRET",
                "ALIAS", "LOCAL BASE URL", "UPSTREAM"
            );
            for r in &ctx.vault.proxy_routes {
                let injects: Vec<String> = r
                    .headers
                    .iter()
                    .map(|(n, _)| format!("header {n}"))
                    .chain(r.query.iter().map(|(k, _)| format!("query {k}")))
                    .collect();
                println!(
                    "{:<12} {:<38} {:<40} {} ({})",
                    r.alias,
                    crate::proxy::local_base_url(ctx.config.proxy_port, r),
                    r.upstream,
                    r.secret_ref(),
                    injects.join(", ")
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        ProxyCommand::Env => {
            let ctx = load_session(custom_cfg, custom_vault, true)?;
            if ctx.vault.proxy_routes.is_empty() {
                return fail("No proxy routes configured");
            }
            for r in &ctx.vault.proxy_routes {
                for line in env_lines(ctx.config.proxy_port, r) {
                    println!("{line}");
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        ProxyCommand::Start(args) => {
            if !is_loopback_bind(&args.bind) {
                return fail("The proxy only binds to loopback (127.0.0.1, ::1, localhost)");
            }
            let ctx = load_session(custom_cfg, custom_vault, true)?;
            let port = args.port.unwrap_or(ctx.config.proxy_port);
            eprintln!("apiman proxy listening on http://{}:{port}", args.bind);
            if ctx.vault.proxy_routes.is_empty() {
                eprintln!(
                    "No routes yet: add one with 'apiman proxy add --preset openai' (picked up live)."
                );
            }
            for line in vault_routes_summary(&ctx.vault, port) {
                eprintln!("{line}");
            }
            eprintln!(
                "Keys are fetched from the unlocked session per request; 'apiman lock' stops injection."
            );
            let server = ProxyServer::new(ctx.vault_path.clone(), ctx.socket_path.clone(), port);
            drop(ctx);
            serve(server, &args.bind)?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

pub const SKILL_MD: &str = include_str!("../docs/skills/SKILL.md");

fn handle_skill(args: SkillArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match args.install {
        Some(dir) => {
            let target = expand_path(&dir).join("apiman").join("SKILL.md");
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&target, SKILL_MD)?;
            eprintln!("Installed agent skill to '{}'", target.display());
        }
        None => print!("{SKILL_MD}"),
    }
    Ok(ExitCode::SUCCESS)
}
