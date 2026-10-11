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
            if entry == dir {
                return true;
            }
        }
    }
    false
}

pub fn install_binary() -> Result<(PathBuf, bool), String> {
    let current_exe = std::env::current_exe().map_err(|e| format!("Cannot locate current binary: {e}"))?;
    let target_dir = default_install_dir();
    let target_path = target_dir.join("apiman");

    if !target_dir.exists() {
        fs::create_dir_all(&target_dir)
            .map_err(|e| format!("Failed to create directory '{}': {e}", target_dir.display()))?;
    }

    if target_path.exists() {
        let _ = fs::remove_file(&target_path);
    }

    fs::copy(&current_exe, &target_path)
        .map_err(|e| format!("Failed to copy binary to '{}': {e}", target_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o755);
        let _ = fs::set_permissions(&target_path, perms);
    }

    let in_path = is_dir_in_path(&target_dir);
    Ok((target_path, in_path))
}

pub fn uninstall_binary() -> Result<PathBuf, String> {
    let target_path = installed_binary_path();
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
