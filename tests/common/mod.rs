#![allow(dead_code)]

use apiman::cli::SessionContext;
use apiman::config::Config;
use apiman::storage;
use apiman::tui::app::App;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

pub const BIN: &str = env!("CARGO_BIN_EXE_apiman");

/// Environment markers that switch on agent detection; scrubbed so tests
/// behave the same inside and outside coding agents.
const AGENT_VARS: &[&str] = &[
    "CLAUDECODE",
    "GEMINI_CLI",
    "CURSOR_AGENT",
    "CODEX_THREAD_ID",
    "CODEX_SANDBOX",
    "CODEX_CI",
    "AI_AGENT",
    "AGENT",
    "APIMAN_AGENT",
    "APIMAN_MASTER_PASSWORD",
    "APIMAN_PASSWORD",
    "NO_COLOR",
];

/// An isolated apiman world: private HOME/XDG config, vault, and daemon socket.
/// The daemon is locked on drop so no background process outlives the test.
pub struct Sandbox {
    pub dir: TempDir,
    pub home: PathBuf,
    pub vault: PathBuf,
    pub socket: PathBuf,
    pub password: String,
}

impl Sandbox {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".config")).unwrap();
        let vault = dir.path().join("vault.enc");
        let socket = dir.path().join("d.sock");
        Self {
            dir,
            home,
            vault,
            socket,
            password: "correct-horse-battery".to_string(),
        }
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    pub fn config_dir(&self) -> PathBuf {
        self.home.join(".config").join("apiman")
    }

    /// Bare command with an isolated environment and no vault/password.
    pub fn bare(&self) -> Command {
        let mut cmd = Command::new(BIN);
        for var in AGENT_VARS {
            cmd.env_remove(var);
        }
        cmd.env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("APIMAN_SOCKET", &self.socket)
            .stdin(Stdio::null());
        cmd
    }

    /// Command bound to this sandbox's vault, unlocked via the env password.
    pub fn cmd(&self) -> Command {
        let mut cmd = self.bare();
        cmd.arg("--vault").arg(&self.vault);
        cmd.env("APIMAN_MASTER_PASSWORD", &self.password);
        cmd
    }

    pub fn run(&self, args: &[&str]) -> Output {
        self.cmd().args(args).output().unwrap()
    }

    pub fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "apiman {args:?} failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    pub fn fails(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            !out.status.success(),
            "apiman {args:?} unexpectedly succeeded: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        String::from_utf8_lossy(&out.stderr).into_owned()
    }

    pub fn run_stdin(&self, mut cmd: Command, input: &str) -> Output {
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    /// `apiman init` through stdin, exactly like a user would.
    pub fn init(&self) {
        let mut cmd = self.bare();
        cmd.arg("--vault").arg(&self.vault).arg("init");
        let out = self.run_stdin(cmd, &format!("{0}\n{0}\n", self.password));
        assert!(
            out.status.success(),
            "init failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    pub fn write_config(&self, name: &str, json: serde_json::Value) -> PathBuf {
        let path = self.path(name);
        std::fs::write(&path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
        path
    }

    /// A vault built directly through the storage layer plus a TUI `App` on it.
    pub fn tui(&self, entries: &[(&str, &str, Option<&str>)]) -> App {
        self.tui_with_config(entries, Config::default())
    }

    pub fn tui_with_config(&self, entries: &[(&str, &str, Option<&str>)], config: Config) -> App {
        let (mut vault, key, params) = storage::init_vault(&self.password, &self.vault).unwrap();
        for (name, value, project) in entries {
            vault.set(
                name.to_string(),
                (*value).into(),
                project.map(str::to_string),
                Vec::new(),
                None,
            );
        }
        storage::save_vault(&vault, &key, &params, &self.vault).unwrap();
        App::new(self.session(config))
    }

    pub fn session(&self, config: Config) -> SessionContext {
        let (vault, key, params) =
            storage::load_vault_with_password(&self.password, &self.vault).unwrap();
        SessionContext::new(
            config,
            self.vault.clone(),
            self.socket.clone(),
            key,
            params,
            vault,
        )
    }

    pub fn stop_daemon(&self) {
        let _ = self.bare().arg("lock").output();
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        self.stop_daemon();
    }
}

pub fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::empty())
}

pub fn shift(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::SHIFT)
}

pub fn ctrl(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
}

pub fn type_text(app: &mut App, text: &str) {
    for c in text.chars() {
        apiman::tui::input::handle_key(app, key(KeyCode::Char(c)));
    }
}

pub fn press(app: &mut App, ev: KeyEvent) {
    apiman::tui::input::handle_key(app, ev);
}

/// Renders the app into an in-memory terminal and returns the screen text.
pub fn render(app: &App, width: u16, height: u16) -> String {
    let backend = ratatui::backend::TestBackend::new(width, height);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal.draw(|f| apiman::tui::ui::render(f, app)).unwrap();
    let buf = terminal.backend().buffer().clone();
    let mut out = String::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            out.push_str(buf[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

pub fn names(entries: &[&apiman::vault::SecretEntry]) -> Vec<String> {
    let mut v: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
    v.sort();
    v
}

pub fn file_mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}
