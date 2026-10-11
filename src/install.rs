use directories::BaseDirs;
use std::fs;
use std::path::{Path, PathBuf};

pub fn default_install_dir() -> PathBuf {
    if let Some(base) = BaseDirs::new() {
        base.home_dir().join(".local").join("bin")
    } else {
        PathBuf::from("/usr/local/bin")
    }
}

pub fn installed_binary_path() -> PathBuf {
    default_install_dir().join("apiman")
}

pub fn is_installed() -> bool {
    let p = installed_binary_path();
    p.exists() && p.is_file()
}

pub fn is_dir_in_path(dir: &Path) -> bool {
    if let Ok(path_var) = std::env::var("PATH") {
        for entry in std::env::split_paths(&path_var) {
            if normalize(&entry) == normalize(dir) {
                return true;
            }
        }
    }
    false
}

fn normalize(p: &Path) -> String {
    let s = p.to_string_lossy();
    let trimmed = s.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/".to_string();
    }
    trimmed.to_string()
}

pub fn resolve_install_dir(custom: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(dir) = custom {
        let dir = expand_tilde(dir);
        if dir.exists() && !dir.is_dir() {
            return Err(format!(
                "Install path '{}' exists and is not a directory.",
                dir.display()
            ));
        }
        return Ok(dir.to_path_buf());
    }
    Ok(default_install_dir())
}

pub fn install_binary_to(target_dir: &Path) -> Result<(PathBuf, bool), String> {
    let current_exe = std::env::current_exe().map_err(|e| format!("Cannot locate current binary: {e}"))?;
    let target_path = target_dir.join("apiman");

    if !target_dir.exists() {
        fs::create_dir_all(target_dir)
            .map_err(|e| format!("Failed to create directory '{}': {e}", target_dir.display()))?;
    }

    // Force install: remove any existing binary first.
    if target_path.exists() || target_path.is_symlink() {
        fs::remove_file(&target_path)
            .map_err(|e| format!("Failed to remove existing '{}': {e}", target_path.display()))?;
    }

    fs::copy(&current_exe, &target_path)
        .map_err(|e| format!("Failed to copy binary to '{}': {e}", target_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o755);
        let _ = fs::set_permissions(&target_path, perms);
    }

    let in_path = is_dir_in_path(target_dir);
    Ok((target_path, in_path))
}

pub fn install_binary() -> Result<(PathBuf, bool), String> {
    install_binary_to(&default_install_dir())
}

pub fn uninstall_binary(custom_dir: Option<&Path>) -> Result<PathBuf, String> {
    let target_path = match custom_dir {
        Some(dir) => expand_tilde(dir).join("apiman"),
        None => installed_binary_path(),
    };
    if !target_path.exists() {
        return Err(format!(
            "apiman is not installed at '{}'",
            target_path.display()
        ));
    }

    fs::remove_file(&target_path)
        .map_err(|e| format!("Failed to remove '{}': {e}", target_path.display()))?;

    Ok(target_path)
}

fn expand_tilde(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        if let Some(base) = BaseDirs::new() {
            return base.home_dir().join(rest);
        }
    }
    p.to_path_buf()
}
