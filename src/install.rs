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
    installed_binary_path().is_file()
}

pub fn is_dir_in_path(dir: &Path) -> bool {
    let Ok(path_var) = std::env::var("PATH") else {
        return false;
    };
    let want = canonical_or_self(dir);
    std::env::split_paths(&path_var).any(|entry| canonical_or_self(&entry) == want)
}

fn canonical_or_self(p: &Path) -> PathBuf {
    fs::canonicalize(p).unwrap_or_else(|_| {
        let s = p.to_string_lossy();
        let trimmed = s.trim_end_matches('/');
        PathBuf::from(if trimmed.is_empty() { "/" } else { trimmed })
    })
}

pub fn resolve_install_dir(custom: Option<&Path>) -> Result<PathBuf, String> {
    let dir = match custom {
        Some(d) => crate::config::expand_path(d),
        None => default_install_dir(),
    };
    let dir = std::path::absolute(&dir)
        .map_err(|e| format!("Invalid install path '{}': {e}", dir.display()))?;
    if dir.exists() && !dir.is_dir() {
        return Err(format!(
            "Install path '{}' exists and is not a directory.",
            dir.display()
        ));
    }
    Ok(dir)
}

pub struct InstallOutcome {
    pub path: PathBuf,
    pub in_path: bool,
    /// The running binary already is the installed one; nothing was copied.
    pub already_current: bool,
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

pub fn install_binary_to(target_dir: &Path) -> Result<InstallOutcome, String> {
    let current_exe =
        std::env::current_exe().map_err(|e| format!("Cannot locate current binary: {e}"))?;
    let target_path = target_dir.join("apiman");

    fs::create_dir_all(target_dir)
        .map_err(|e| format!("Failed to create directory '{}': {e}", target_dir.display()))?;

    let in_path = is_dir_in_path(target_dir);
    if same_file(&current_exe, &target_path) {
        return Ok(InstallOutcome {
            path: target_path,
            in_path,
            already_current: true,
        });
    }

    // Copy next to the target and rename over it: atomic, never leaves a
    // half-written binary, and works while the old binary is still running.
    let staging = target_dir.join(format!(".apiman.install-{}", std::process::id()));
    let result = (|| {
        fs::copy(&current_exe, &staging)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&staging, fs::Permissions::from_mode(0o755))?;
        }
        fs::rename(&staging, &target_path)
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&staging);
        return Err(format!(
            "Failed to install binary to '{}': {e}",
            target_path.display()
        ));
    }

    Ok(InstallOutcome {
        path: target_path,
        in_path,
        already_current: false,
    })
}

pub fn uninstall_binary(custom_dir: Option<&Path>) -> Result<PathBuf, String> {
    let target_path = resolve_install_dir(custom_dir)?.join("apiman");
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
