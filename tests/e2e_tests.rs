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

    // 17. Import secrets from a .env file
    let env_file = dir.path().join("import_test.env");
    std::fs::write(
        &env_file,
        "# sample service config\nexport EXPORTED_KEY=exported-value\nPLAIN=plainvalue\nQUOTED_DOUBLE=\"hello world # not a comment\"\nQUOTED_SINGLE='single quoted'\nESCAPED=\"line1\\nline2\"\nINLINE=somevalue # trailing comment\nEMPTY_PLACEHOLDER=\nINVALID LINE WITHOUT EQUALS\n123BADKEY=oops\nSPACED = spaced-value\n",
    )
    .unwrap();
    let import_res = {
        let mut cmd = apiman(binary, &vault_file, &socket_file, new_password);
        cmd.args([
            "import",
            env_file.to_str().unwrap(),
            "--project",
            "backend",
            "--tags",
            "e2etag",
        ]);
        cmd.output().unwrap()
    };
    assert!(import_res.status.success());
    let import_err = String::from_utf8_lossy(&import_res.stderr);
    assert!(import_err.contains("Imported 7"), "unexpected: {import_err}");

    let get_quoted = run_cmd(
        apiman(binary, &vault_file, &socket_file, new_password),
        &["get", "QUOTED_DOUBLE", "--allow-view"],
    );
    assert!(get_quoted.status.success());
    assert_eq!(
        String::from_utf8_lossy(&get_quoted.stdout).trim(),
        "hello world # not a comment"
    );

    let get_exported = run_cmd(
        apiman(binary, &vault_file, &socket_file, new_password),
        &["get", "EXPORTED_KEY", "--allow-view"],
    );
    assert!(get_exported.status.success());
    assert_eq!(
        String::from_utf8_lossy(&get_exported.stdout).trim(),
        "exported-value"
    );

    let get_escaped = run_cmd(
        apiman(binary, &vault_file, &socket_file, new_password),
        &["get", "ESCAPED", "--allow-view"],
    );
    assert!(get_escaped.status.success());
    assert_eq!(
        String::from_utf8_lossy(&get_escaped.stdout).trim(),
        "line1\nline2"
    );

    // Importing a .env.example with only placeholders imports nothing
    let example_file = dir.path().join("placeholders.env");
    std::fs::write(&example_file, "FUTURE_KEY=\nANOTHER_ONE=\n").unwrap();
    let import_example = {
        let mut cmd = apiman(binary, &vault_file, &socket_file, new_password);
        cmd.args(["import", example_file.to_str().unwrap()]);
        cmd.output().unwrap()
    };
    assert!(import_example.status.success());
    assert!(String::from_utf8_lossy(&import_example.stderr).contains("Imported 0"));

    // 18. Export secrets to .env file and example template
    let export_file = dir.path().join("exported.env");
    let export_res = {
        let mut cmd = apiman(binary, &vault_file, &socket_file, new_password);
        cmd.args([
            "export",
            "--project",
            "backend",
            "--output",
            export_file.to_str().unwrap(),
        ]);
        cmd.output().unwrap()
    };
    assert!(export_res.status.success());
    let exported_text = std::fs::read_to_string(&export_file).unwrap();
    assert!(exported_text.contains("PLAIN=plainvalue"));
    assert!(exported_text.contains("QUOTED_DOUBLE=\"hello world # not a comment\""));
    assert!(exported_text.contains("ESCAPED=\"line1\\nline2\""));
    assert!(exported_text.contains("DATABASE_URL="));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&export_file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    let example_out = dir.path().join("exported.env.example");
    let export_example_res = {
        let mut cmd = apiman(binary, &vault_file, &socket_file, new_password);
        cmd.args([
            "export",
            "--project",
            "backend",
            "--format",
            "example",
            "--output",
            example_out.to_str().unwrap(),
        ]);
        cmd.output().unwrap()
    };
    assert!(export_example_res.status.success());
    let example_text = std::fs::read_to_string(&example_out).unwrap();
    assert!(example_text.contains("PLAIN=\n"));
    assert!(!example_text.contains("plainvalue"));
    assert!(!example_text.contains("exported-value"));

    // 19. Export directly into a directory (default filename is used)
    let export_dir = dir.path().join("export-target");
    std::fs::create_dir_all(&export_dir).unwrap();
    let export_to_dir = {
        let mut cmd = apiman(binary, &vault_file, &socket_file, new_password);
        cmd.args([
            "export",
            "--project",
            "backend",
            "--output",
            &format!("{}/", export_dir.display()),
        ]);
        cmd.output().unwrap()
    };
    assert!(export_to_dir.status.success());
    let dir_exported = export_dir.join("apiman-export.env");
    assert!(dir_exported.is_file());
    let dir_text = std::fs::read_to_string(&dir_exported).unwrap();
    assert!(dir_text.contains("PLAIN=plainvalue"));

    // Cleanup isolated daemon
    let _ = run_cmd(
        apiman(binary, &vault_file, &socket_file, new_password),
        &["lock"],
    );
}

#[test]
fn test_install_to_custom_dir() {
    let dir = tempdir().unwrap();
    let custom_dir = dir.path().join("custom-bin");
    let binary = env!("CARGO_BIN_EXE_apiman");

    // Install into a directory that does not exist yet (must be created)
    let install_res = Command::new(binary)
        .arg("install")
        .arg(custom_dir.to_str().unwrap())
        .output()
        .unwrap();
    assert!(install_res.status.success());
    let install_err = String::from_utf8_lossy(&install_res.stderr);
    assert!(install_err.contains("Installed apiman binary"));

    let installed = custom_dir.join("apiman");
    assert!(installed.is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&installed).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
    }

    // Force reinstall over the existing binary
    let reinstall_res = Command::new(binary)
        .arg("install")
        .arg(custom_dir.to_str().unwrap())
        .output()
        .unwrap();
    assert!(reinstall_res.status.success());
    assert!(installed.is_file());

    // A directory outside PATH must trigger the PATH warning
    let warning_text = String::from_utf8_lossy(&install_res.stderr);
    if !is_dir_in_test_path(&custom_dir) {
        assert!(warning_text.contains("not in your PATH"));
    }
}

fn is_dir_in_test_path(dir: &std::path::Path) -> bool {
    if let Ok(path_var) = std::env::var("PATH") {
        for entry in std::env::split_paths(&path_var) {
            if entry == dir {
                return true;
            }
        }
    }
    false
}

#[test]
fn test_stale_daemon_self_heal() {    let dir = tempdir().unwrap();
    let vault_file: PathBuf = dir.path().join("stale_vault.enc");
    let socket_file: PathBuf = dir.path().join("stale_daemon.sock");
    let binary = env!("CARGO_BIN_EXE_apiman");
    let password = "stale-test-password";

    // Init vault and store one secret (spawns a healthy daemon on the isolated socket)
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
        writeln!(stdin, "{password}").unwrap();
        writeln!(stdin, "{password}").unwrap();
    }
    assert!(init_child.wait_with_output().unwrap().status.success());

    let set_res = {
        let mut cmd = Command::new(binary);
        cmd.arg("--vault")
            .arg(&vault_file)
            .args(["set", "HEAL_KEY", "heal-value"])
            .env("APIMAN_MASTER_PASSWORD", password)
            .env("APIMAN_SOCKET", &socket_file);
        cmd.output().unwrap()
    };
    assert!(set_res.status.success());

    // Kill the healthy daemon, then seed a stale one holding a wrong key
    let mut lock_cmd = Command::new(binary);
    lock_cmd
        .arg("lock")
        .env("APIMAN_SOCKET", &socket_file);
    assert!(lock_cmd.output().unwrap().status.success());

    let mut seed_child = Command::new(binary);
    seed_child
        .args([
            "daemon",
            "--run",
            "--timeout",
            "900",
            "--socket",
            socket_file.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut seed_child = seed_child.spawn().unwrap();
    {
        let mut stdin = seed_child.stdin.take().unwrap();
        stdin.write_all(b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX").unwrap();
    }
    // Give the stale daemon a moment to bind the socket
    std::thread::sleep(std::time::Duration::from_millis(800));

    // Correct password must still work despite the stale daemon key
    let get_ok = {
        let mut cmd = Command::new(binary);
        cmd.arg("--vault")
            .arg(&vault_file)
            .args(["get", "HEAL_KEY", "--allow-view"])
            .env("APIMAN_MASTER_PASSWORD", password)
            .env("APIMAN_SOCKET", &socket_file);
        cmd.output().unwrap()
    };
    assert!(get_ok.status.success());
    assert_eq!(
        String::from_utf8_lossy(&get_ok.stdout).trim(),
        "heal-value"
    );

    // The stale daemon must have been replaced: even a wrong password now unlocks via cache
    let get_cached = {
        let mut cmd = Command::new(binary);
        cmd.arg("--vault")
            .arg(&vault_file)
            .args(["get", "HEAL_KEY", "--allow-view"])
            .env("APIMAN_MASTER_PASSWORD", "definitely-wrong-password")
            .env("APIMAN_SOCKET", &socket_file);
        cmd.output().unwrap()
    };
    assert!(
        get_cached.status.success(),
        "daemon still holds stale key: {}",
        String::from_utf8_lossy(&get_cached.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&get_cached.stdout).trim(),
        "heal-value"
    );

    let mut lock_cmd = Command::new(binary);
    lock_cmd
        .arg("lock")
        .env("APIMAN_SOCKET", &socket_file);
    let _ = lock_cmd.output();
}

#[test]
fn test_tui_reveal_all_and_path_completion() {
    use apiman::tui::{app::App, input::handle_key};
    use apiman::{cli::SessionContext, config::Config, storage};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let dir = tempdir().unwrap();
    let vault_file: PathBuf = dir.path().join("reveal_vault.enc");
    let socket_file: PathBuf = dir.path().join("reveal_daemon.sock");
    let password = "reveal-test-password";

    // Build a real vault on disk through the storage layer
    let (mut vault, key, salt) =
        storage::init_vault(password, &vault_file).unwrap();
    vault.set(
        "FIRST_KEY".to_string(),
        "first-value".into(),
        None,
        Vec::new(),
        None,
    );
    vault.set(
        "SECOND_KEY".to_string(),
        "second-value".into(),
        Some("proj".to_string()),
        Vec::new(),
        None,
    );
    storage::save_vault(&vault, &key, &salt, &vault_file).unwrap();

    // Reload exactly like the CLI does after unlocking
    let (vault, key, salt) =
        storage::load_vault_with_password(password, &vault_file).unwrap();
    let ctx = SessionContext {
        config: Config::default(),
        vault_path: vault_file,
        socket_path: socket_file,
        master_key: key,
        salt,
        vault,
    };
    use apiman::tui::app::{complete_path, TextField};
    let mut app = App::new(ctx);
    assert_eq!(app.filtered_indices.len(), 2);
    assert!(app.revealed_entries.is_empty());

    // Reveal-all toggles every visible entry, second toggle masks them again
    app.toggle_reveal_all();
    assert_eq!(app.revealed_entries.len(), 2);
    app.toggle_reveal_all();
    assert!(app.revealed_entries.is_empty());

    // Same behavior through the actual keybindings: `*`, `V`, and Shift+Space
    let plain_space = KeyEvent::new(KeyCode::Char(' '), KeyModifiers::empty());
    let shift_space = KeyEvent::new(KeyCode::Char(' '), KeyModifiers::SHIFT);
    handle_key(&mut app, KeyEvent::new(KeyCode::Char('*'), KeyModifiers::empty()));
    assert_eq!(app.revealed_entries.len(), 2);
    handle_key(&mut app, KeyEvent::new(KeyCode::Char('V'), KeyModifiers::empty()));
    assert!(app.revealed_entries.is_empty());
    handle_key(&mut app, shift_space);
    assert_eq!(app.revealed_entries.len(), 2);
    // Plain Space without Shift still toggles only the single selected entry
    handle_key(&mut app, plain_space);
    assert_eq!(app.revealed_entries.len(), 1);

    // Reveal-all respects the active search filter
    app.search_query = TextField::new("first".to_string());
    app.update_filtered_indices();
    assert_eq!(app.filtered_indices.len(), 1);
    let visible_id = app.selected_entry().unwrap().id.clone();
    assert_eq!(app.selected_entry().unwrap().name, "FIRST_KEY");
    app.toggle_reveal_all();
    assert!(app.revealed_entries.contains(&visible_id));

    // Path completion: single match completes, multi-match extends common prefix
    let comp_dir = dir.path().join("complete");
    std::fs::create_dir_all(&comp_dir).unwrap();
    std::fs::write(comp_dir.join("alpha.env"), "A=1").unwrap();
    std::fs::write(comp_dir.join("alphabet.env"), "B=2").unwrap();
    std::fs::write(comp_dir.join("beta.env"), "C=3").unwrap();
    let base = comp_dir.to_string_lossy().to_string();

    let (done, msg) = complete_path(&format!("{base}/alp"));
    assert_eq!(done, format!("{base}/alpha"));
    assert!(msg.contains("2 matches"), "unexpected: {msg}");

    let (done, msg) = complete_path(&format!("{base}/alpha.env"));
    assert_eq!(done, format!("{base}/alpha.env"));
    assert!(msg.contains("Completed"), "unexpected: {msg}");

    let (done, msg) = complete_path(&format!("{base}/bet"));
    assert_eq!(done, format!("{base}/beta.env"));
    assert!(msg.contains("Completed"), "unexpected: {msg}");

    let (same, msg) = complete_path(&format!("{base}/zzz"));
    assert_eq!(same, format!("{base}/zzz"));
    assert_eq!(msg, "No matches");
}

#[test]
fn test_tui_multiselect_bulk_edit() {
    use apiman::tui::{app::App, input::handle_key};
    use apiman::{cli::SessionContext, config::Config, storage};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::empty())
    }
    fn shifted(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::SHIFT)
    }

    let dir = tempdir().unwrap();
    let vault_file: PathBuf = dir.path().join("bulk_vault.enc");
    let socket_file: PathBuf = dir.path().join("bulk_daemon.sock");
    let password = "bulk-test-password";

    let (mut vault, key, salt) = storage::init_vault(password, &vault_file).unwrap();
    for name in ["AAA_KEY", "BBB_KEY", "CCC_KEY"] {
        vault.set(
            name.to_string(),
            format!("{name}-value").as_str().into(),
            None,
            Vec::new(),
            None,
        );
    }
    storage::save_vault(&vault, &key, &salt, &vault_file).unwrap();

    let (vault, key, salt) = storage::load_vault_with_password(password, &vault_file).unwrap();
    let ctx = SessionContext {
        config: Config::default(),
        vault_path: vault_file,
        socket_path: socket_file,
        master_key: key,
        salt,
        vault,
    };
    let mut app = App::new(ctx);
    assert_eq!(app.filtered_indices.len(), 3);

    // Shift+Down grows the group selection, Shift+Up shrinks it again
    handle_key(&mut app, shifted(KeyCode::Down));
    assert_eq!(app.marked.len(), 2);
    assert!(app.in_group_mode());
    handle_key(&mut app, shifted(KeyCode::Down));
    assert_eq!(app.marked.len(), 3);
    handle_key(&mut app, shifted(KeyCode::Up));
    assert_eq!(app.marked.len(), 2);

    // Plain navigation exits group mode
    handle_key(&mut app, press(KeyCode::Down));
    assert!(!app.in_group_mode());

    // Select all three again and open bulk edit with `e`
    handle_key(&mut app, press(KeyCode::Home));
    handle_key(&mut app, shifted(KeyCode::Down));
    handle_key(&mut app, shifted(KeyCode::Down));
    assert_eq!(app.marked.len(), 3);
    handle_key(&mut app, press(KeyCode::Char('e')));
    assert_eq!(app.active_modal, apiman::tui::app::ActiveModal::BulkEdit);

    // Fill bulk form via keystrokes (exercises cursor insertion too)
    for c in "webapp".chars() {
        handle_key(&mut app, press(KeyCode::Char(c)));
    }
    handle_key(&mut app, press(KeyCode::Tab));
    for c in "prod,api".chars() {
        handle_key(&mut app, press(KeyCode::Char(c)));
    }
    handle_key(&mut app, press(KeyCode::Enter));
    assert_eq!(app.active_modal, apiman::tui::app::ActiveModal::None);
    assert!(!app.in_group_mode());

    // All entries moved to the project with replaced tags, values untouched
    for name in ["AAA_KEY", "BBB_KEY", "CCC_KEY"] {
        let entry = app.ctx.vault.get(name, Some("webapp")).unwrap();
        assert_eq!(entry.value.expose_secret(), format!("{name}-value"));
        assert_eq!(entry.tags, vec!["prod".to_string(), "api".to_string()]);
    }

    // Group delete removes every selected entry at once
    handle_key(&mut app, press(KeyCode::Home));
    handle_key(&mut app, shifted(KeyCode::Down));
    handle_key(&mut app, shifted(KeyCode::Down));
    handle_key(&mut app, press(KeyCode::Char('d')));
    handle_key(&mut app, press(KeyCode::Char('y')));
    assert_eq!(app.ctx.vault.entries.len(), 0);

    // Esc clears an active group selection without deleting
    let (mut vault, key, salt) =
        storage::init_vault(password, &dir.path().join("bulk2.enc")).unwrap();
    vault.set("SOLO".to_string(), "solo-value".into(), None, Vec::new(), None);
    let ctx = SessionContext {
        config: Config::default(),
        vault_path: dir.path().join("bulk2.enc"),
        socket_path: dir.path().join("bulk2.sock"),
        master_key: key,
        salt,
        vault,
    };
    let mut app = App::new(ctx);
    handle_key(&mut app, shifted(KeyCode::Down));
    assert!(app.in_group_mode());
    handle_key(&mut app, press(KeyCode::Esc));
    assert!(!app.in_group_mode());
    assert_eq!(app.ctx.vault.entries.len(), 1);
}
