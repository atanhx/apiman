use directories::{BaseDirs, ProjectDirs};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const VAULT_FILE_NAME: &str = "apiman_vault.enc";
const LEGACY_VAULT_FILE_NAME: &str = "vault.enc";

/// Whether AI agents (and other automation) only ever see masked values.
/// When active, `get`/`export` print `[REDACTED:NAME]` instead of values and
/// `run` still injects the real values but masks them in the output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AgentMode {
    /// Agents see values like any other caller.
    #[default]
    Off,
    /// Mask for detected agents (Claude Code, Codex, Gemini CLI, Cursor, ...
    /// or APIMAN_AGENT=1).
    Auto,
    /// Mask for every CLI caller.
    On,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KeyList {
    One(String),
    Many(Vec<String>),
}

impl KeyList {
    pub fn specs(&self) -> Vec<&str> {
        match self {
            Self::One(s) => vec![s.as_str()],
            Self::Many(v) => v.iter().map(String::as_str).collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub vault_path: PathBuf,
    pub auto_lock_timeout_seconds: u64,
    pub default_project: String,
    pub clipboard_timeout_seconds: u64,
    pub agent_mode: AgentMode,
    pub proxy_port: u16,
    pub theme: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub keybindings: BTreeMap<String, KeyList>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            vault_path: default_config_dir().join(VAULT_FILE_NAME),
            auto_lock_timeout_seconds: 900,
            default_project: "global".to_string(),
            clipboard_timeout_seconds: 30,
            agent_mode: AgentMode::Off,
            proxy_port: crate::proxy::DEFAULT_PORT,
            theme: "ember".to_string(),
            keybindings: BTreeMap::new(),
        }
    }
}

pub fn default_config_dir() -> PathBuf {
    if let Some(proj_dirs) = ProjectDirs::from("", "", "apiman") {
        proj_dirs.config_dir().to_path_buf()
    } else if let Some(base_dirs) = BaseDirs::new() {
        base_dirs.home_dir().join(".config").join("apiman")
    } else {
        PathBuf::from(".config/apiman")
    }
}

pub fn default_socket_path() -> PathBuf {
    if let Ok(sock) = std::env::var("APIMAN_SOCKET")
        && !sock.trim().is_empty()
    {
        return PathBuf::from(sock);
    }
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        let dir = PathBuf::from(runtime_dir);
        if !dir.as_os_str().is_empty() && dir.is_dir() {
            return dir.join("apiman.sock");
        }
    }
    default_config_dir().join("daemon.sock")
}

pub fn expand_path(p: &Path) -> PathBuf {
    let p_str = p.to_string_lossy();
    let rest = if p_str == "~" {
        Some("")
    } else {
        p_str.strip_prefix("~/")
    };
    if let (Some(rest), Some(base)) = (rest, BaseDirs::new()) {
        return base.home_dir().join(rest);
    }
    p.to_path_buf()
}

impl Config {
    pub fn config_file_path() -> PathBuf {
        default_config_dir().join("config.json")
    }

    /// Loads the config from `custom` or the default location. A missing file
    /// yields defaults (and writes them out for the default location only); a
    /// malformed file is an error rather than being silently overwritten.
    pub fn load(custom: Option<&Path>) -> Result<Self, String> {
        let path = custom
            .map(expand_path)
            .unwrap_or_else(Self::config_file_path);
        let mut cfg = match fs::read_to_string(&path) {
            Ok(content) => {
                let mut cfg: Config = serde_json::from_str(&content)
                    .map_err(|e| format!("Invalid config file '{}': {e}", path.display()))?;
                cfg.vault_path = expand_path(&cfg.vault_path);
                cfg
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let cfg = Config::default();
                if custom.is_none() {
                    let _ = cfg.save_to(&path);
                }
                cfg
            }
            Err(e) => return Err(format!("Cannot read config file '{}': {e}", path.display())),
        };
        cfg.migrate_legacy_vault(&path);
        Ok(cfg)
    }

    /// Older releases named the default vault `vault.enc`. When the config
    /// still points at that default location, rename it once to the clearer
    /// `apiman_vault.enc` and update the config file accordingly.
    fn migrate_legacy_vault(&mut self, config_path: &Path) {
        let dir = default_config_dir();
        let legacy = dir.join(LEGACY_VAULT_FILE_NAME);
        let current = dir.join(VAULT_FILE_NAME);
        if self.vault_path != legacy && self.vault_path != current {
            return;
        }
        if !legacy.is_file() || current.exists() {
            return;
        }
        if fs::rename(&legacy, &current).is_ok() {
            eprintln!(
                "Note: renamed vault '{}' -> '{}'",
                legacy.display(),
                current.display()
            );
            if self.vault_path == legacy {
                self.vault_path = current;
                if config_path.exists() {
                    let _ = self.save_to(config_path);
                }
            }
        }
    }

    pub fn save_to(&self, path: &Path) -> Result<(), io::Error> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
        let data = serde_json::to_string_pretty(self)?;
        fs::write(path, data + "\n")?;
        Ok(())
    }

    pub fn save(&self) -> Result<(), io::Error> {
        self.save_to(&Self::config_file_path())
    }

    /// `default_project` as a vault scope (`None` = global).
    pub fn default_scope(&self) -> Option<String> {
        crate::vault::normalize_project(Some(&self.default_project))
    }
}
