use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::tempdir;

fn apiman(binary: &str, vault: &Path, socket: &Path, password: &str) -> Command {
    let mut cmd = Command::new(binary);
    cmd.arg("--vault").arg(vault);
    cmd.env("APIMAN_MASTER_PASSWORD", password);
    cmd.env("APIMAN_SOCKET", socket);
    cmd
}

fn run_cmd(mut cmd: Command, extra_args: &[&str]) -> std::process::Output {
    cmd.args(extra_args);
    cmd.output().unwrap()
}

#[test]
fn test_apiman_end_to_end_lifecycle() {
    let dir = tempdir().unwrap();
    let vault_file: PathBuf = dir.path().join("e2e_vault.enc");
    let socket_file: PathBuf = dir.path().join("e2e_daemon.sock");
    let config_file: PathBuf = dir.path().join("e2e_config.json");
    std::fs::write(
        &config_file,
        format!(
            "{{\n  \"vault_path\": \"{}\",\n  \"auto_lock_timeout_seconds\": 900,\n  \"default_project\": \"global\",\n  \"clipboard_timeout_seconds\": 30\n}}",
            vault_file.display()
        ),
    )
    .unwrap();
    let binary = env!("CARGO_BIN_EXE_apiman");
    let master_password = "initial-secure-password-42";

    // 1. Initialize vault via `apiman init`
    let mut init_child = Command::new(binary);
    init_child
        .arg("--vault")
        .arg(&vault_file)
        .arg("init")
        .env("APIMAN_SOCKET", &socket_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut init_child = init_child.spawn().unwrap();

    {
        let mut stdin = init_child.stdin.take().unwrap();
        writeln!(stdin, "{master_password}").unwrap();
        writeln!(stdin, "{master_password}").unwrap();
    }

    let init_res = init_child.wait_with_output().unwrap();
    assert!(
        init_res.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init_res.stderr)
    );
    assert!(vault_file.exists());

    // 2. Set global secret
    let set_global = run_cmd(
        apiman(binary, &vault_file, &socket_file, master_password),
        &[
            "set",
            "OPENAI_KEY",
            "sk-openai-live-secret",
            "--tags",
            "ai,production",
            "--description",
            "Live OpenAI key",
        ],
    );
    assert!(set_global.status.success());

    // 3. Set project-scoped secret
    let set_proj = {
        let mut cmd = apiman(binary, &vault_file, &socket_file, master_password);
        cmd.args([
            "set",
            "DATABASE_URL",
            "postgres://user:pass@db:5432/main",
            "--project",
            "backend",
            "--tags",
            "db,infra",
        ]);
        cmd.output().unwrap()
    };
    assert!(set_proj.status.success());

    // 4. Retrieve global secret with --allow-view
    let get_global = run_cmd(
        apiman(binary, &vault_file, &socket_file, master_password),
        &["get", "OPENAI_KEY", "--allow-view"],
    );
    assert!(get_global.status.success());
    assert_eq!(
        String::from_utf8_lossy(&get_global.stdout).trim(),
        "sk-openai-live-secret"
    );

    // 5. Retrieve project-scoped secret WITHOUT specifying --project
    let get_auto = run_cmd(
        apiman(binary, &vault_file, &socket_file, master_password),
        &["get", "DATABASE_URL", "--allow-view"],
    );
    assert!(get_auto.status.success());
    assert_eq!(
        String::from_utf8_lossy(&get_auto.stdout).trim(),
        "postgres://user:pass@db:5432/main"
    );

    // 6. Case-insensitive retrieval test
    let get_case = run_cmd(
        apiman(binary, &vault_file, &socket_file, master_password),
        &["get", "openai_key", "--allow-view"],
    );
    assert!(get_case.status.success());
    assert_eq!(
        String::from_utf8_lossy(&get_case.stdout).trim(),
        "sk-openai-live-secret"
    );

    // 7. Piped retrieval (without --allow-view, output raw to stdout)
    let get_piped = run_cmd(
        apiman(binary, &vault_file, &socket_file, master_password),
        &["get", "OPENAI_KEY"],
    );
    assert!(get_piped.status.success());
    assert_eq!(
        String::from_utf8(get_piped.stdout).unwrap(),
        "sk-openai-live-secret"
    );

    // 8. List secrets in table and json formats
    let list_tbl = run_cmd(
        apiman(binary, &vault_file, &socket_file, master_password),
        &["list"],
    );
    assert!(list_tbl.status.success());
    let list_str = String::from_utf8_lossy(&list_tbl.stdout);
    assert!(list_str.contains("OPENAI_KEY"));
    assert!(list_str.contains("DATABASE_URL"));
    assert!(!list_str.contains("sk-openai-live-secret"));

    let list_json = run_cmd(
        apiman(binary, &vault_file, &socket_file, master_password),
        &["list", "--format", "json"],
    );
    assert!(list_json.status.success());
    let json_val: serde_json::Value = serde_json::from_slice(&list_json.stdout).unwrap();
    assert_eq!(json_val.as_array().unwrap().len(), 2);

    // 9. Run command with injected environment variables
    let run_cmd_out = run_cmd(
        apiman(binary, &vault_file, &socket_file, master_password),
        &["run", "--", "sh", "-c", "echo $OPENAI_KEY"],
    );
    assert!(run_cmd_out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&run_cmd_out.stdout).trim(),
        "sk-openai-live-secret"
    );

    // 10. Run with project scope
    let run_proj = run_cmd(
        apiman(binary, &vault_file, &socket_file, master_password),
        &[
            "run",
            "--project",
            "backend",
            "--",
            "sh",
            "-c",
            "echo $DATABASE_URL",
        ],
    );
    assert!(run_proj.status.success());
    assert_eq!(
        String::from_utf8_lossy(&run_proj.stdout).trim(),
        "postgres://user:pass@db:5432/main"
    );

    // 11. Run non-existent command: must fail with user-friendly error
    let run_bad = run_cmd(
        apiman(binary, &vault_file, &socket_file, master_password),
        &["run", "--", "NonExistentProgramXYZ"],
    );
    assert!(!run_bad.status.success());
    let bad_err = String::from_utf8_lossy(&run_bad.stderr);
    assert!(bad_err.contains("Command 'NonExistentProgramXYZ' was not found"));
    assert!(bad_err.contains("apiman get"));

    // 12. Change master password via `passwd`
    let new_password = "brand-new-master-password-999";
    let mut passwd_child = Command::new(binary);
    passwd_child
        .arg("--vault")
        .arg(&vault_file)
        .arg("passwd")
        .env("APIMAN_MASTER_PASSWORD", master_password)
        .env("APIMAN_SOCKET", &socket_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut passwd_child = passwd_child.spawn().unwrap();

    {
        let mut stdin = passwd_child.stdin.take().unwrap();
        writeln!(stdin, "{new_password}").unwrap();
        writeln!(stdin, "{new_password}").unwrap();
    }
    let passwd_res = passwd_child.wait_with_output().unwrap();
    assert!(
        passwd_res.status.success(),
        "passwd failed: {}",
        String::from_utf8_lossy(&passwd_res.stderr)
    );

    // 13. Lock daemon so password is actually re-verified (no cached key shortcut)
    let lock_res = run_cmd(
        apiman(binary, &vault_file, &socket_file, new_password),
        &["lock"],
    );
    assert!(lock_res.status.success());

    let get_with_new_pw = run_cmd(
        apiman(binary, &vault_file, &socket_file, new_password),
        &["get", "OPENAI_KEY", "--allow-view"],
    );
    assert!(get_with_new_pw.status.success());
    assert_eq!(
        String::from_utf8_lossy(&get_with_new_pw.stdout).trim(),
        "sk-openai-live-secret"
    );

    // Lock again to clear the new-key session before testing the old password
    let lock_res2 = run_cmd(
        apiman(binary, &vault_file, &socket_file, new_password),
        &["lock"],
    );
    assert!(lock_res2.status.success());

    let get_with_old_pw = run_cmd(
        apiman(binary, &vault_file, &socket_file, master_password),
        &["get", "OPENAI_KEY", "--allow-view"],
    );
    assert!(!get_with_old_pw.status.success());

    // 14. Delete secret
    let del_res = run_cmd(
        apiman(binary, &vault_file, &socket_file, new_password),
        &["delete", "OPENAI_KEY"],
    );
    assert!(del_res.status.success());

    let get_after_del = run_cmd(
        apiman(binary, &vault_file, &socket_file, new_password),
        &["get", "OPENAI_KEY", "--allow-view"],
    );
    assert!(!get_after_del.status.success());

    // 15. Timeout command: set, view, and disable auto-lock (isolated temp config)
    let mut timeout_set = Command::new(binary);
    timeout_set
        .arg("--config")
        .arg(&config_file)
        .arg("timeout")
        .arg("30m")
        .env("APIMAN_SOCKET", &socket_file);
    let timeout_set = timeout_set.output().unwrap();
    assert!(timeout_set.status.success());
    let timeout_set_err = String::from_utf8_lossy(&timeout_set.stderr);
    assert!(timeout_set_err.contains("30m"));

    let mut timeout_view = Command::new(binary);
    timeout_view
        .arg("--config")
        .arg(&config_file)
        .arg("timeout")
        .env("APIMAN_SOCKET", &socket_file);
    let timeout_view = timeout_view.output().unwrap();
    assert!(timeout_view.status.success());
    let timeout_view_out = String::from_utf8_lossy(&timeout_view.stdout);
    assert!(timeout_view_out.contains("Configured Timeout"));

    let mut timeout_none = Command::new(binary);
    timeout_none
        .arg("--config")
        .arg(&config_file)
        .arg("timeout")
        .arg("none")
        .env("APIMAN_SOCKET", &socket_file);
    let timeout_none = timeout_none.output().unwrap();
    assert!(timeout_none.status.success());
    let timeout_none_err = String::from_utf8_lossy(&timeout_none.stderr);
    assert!(timeout_none_err.contains("always unlocked"));

    let mut timeout_restore = Command::new(binary);
    timeout_restore
        .arg("--config")
        .arg(&config_file)
        .arg("timeout")
        .arg("15m")
        .env("APIMAN_SOCKET", &socket_file);
    let timeout_restore = timeout_restore.output().unwrap();
    assert!(timeout_restore.status.success());

    let saved_cfg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&config_file).unwrap()).unwrap();
    assert_eq!(saved_cfg["auto_lock_timeout_seconds"], 900);

    // 16. Status command check
    let status_res = run_cmd(
        apiman(binary, &vault_file, &socket_file, new_password),
        &["status"],
    );
    assert!(status_res.status.success());
    let status_str = String::from_utf8_lossy(&status_res.stdout);
    assert!(status_str.contains("Vault Path:"));
    assert!(status_str.contains("Installed:"));

    // Cleanup isolated daemon
    let _ = run_cmd(
        apiman(binary, &vault_file, &socket_file, new_password),
        &["lock"],
    );
}
