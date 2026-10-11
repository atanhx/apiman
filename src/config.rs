use directories::{BaseDirs, ProjectDirs};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub vault_path: PathBuf,
    pub auto_lock_timeout_seconds: u64,
    pub default_project: String,
    pub clipboard_timeout_seconds: u64,
}

impl Default for Config {
    fn default() -> Self {
        let vault_path = default_config_dir().join("vault.enc");
        Self {
            vault_path,
            auto_lock_timeout_seconds: 900,
            default_project: "global".to_string(),
            clipboard_timeout_seconds: 30,
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
    if let Ok(sock) = std::env::var("APIMAN_SOCKET") {
        if !sock.trim().is_empty() {
            return PathBuf::from(sock);
        }
    }
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        let p = PathBuf::from(runtime_dir).join("apiman.sock");
        if let Some(parent) = p.parent() {
            if parent.exists() {
                return p;
            }
        }
    }
    default_config_dir().join("daemon.sock")
}

pub fn expand_path(p: &Path) -> PathBuf {
    let p_str = p.to_string_lossy();
    if p_str.starts_with("~/") {
        if let Some(base) = BaseDirs::new() {
            return base.home_dir().join(&p_str[2..]);
        }
    }
    p.to_path_buf()
}

impl Config {
    pub fn config_file_path() -> PathBuf {
        default_config_dir().join("config.json")
    }

    pub fn load_from(path: &Path) -> Option<Self> {
        if path.exists() {
            if let Ok(content) = fs::read_to_string(path) {
                if let Ok(mut cfg) = serde_json::from_str::<Config>(&content) {
                    cfg.vault_path = expand_path(&cfg.vault_path);
                    return Some(cfg);
                }
            }
        }
        None
    }

    pub fn load_or_default() -> Self {
        let path = Self::config_file_path();
        if let Some(cfg) = Self::load_from(&path) {
            return cfg;
        }

        let cfg = Config::default();
        let _ = cfg.save();
        cfg
    }

    pub fn save_to(&self, path: &Path) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }
        let data = serde_json::to_string_pretty(self)?;
        fs::write(path, data)?;
        Ok(())
    }

    pub fn save(&self) -> Result<(), std::io::Error> {
        self.save_to(&Self::config_file_path())
    }
}
