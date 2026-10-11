mod common;

use apiman::tui::app::{ActiveModal, TextField, complete_path};
use common::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::io::Write;
use std::process::Stdio;

#[test]
fn test_apiman_end_to_end_lifecycle() {
    let sb = Sandbox::new();
    sb.init();
    assert!(sb.vault.exists());

    // Global and project-scoped secrets
    sb.ok(&[
        "set",
        "OPENAI_KEY",
        "sk-openai-live-secret",
        "--tags",
        "ai,production",
        "--description",
        "Live OpenAI key",
    ]);
    sb.ok(&[
        "set",
        "DATABASE_URL",
        "postgres://user:pass@db:5432/main",
        "--project",
        "backend",
        "--tags",
        "db,infra",
    ]);

    assert_eq!(
        sb.ok(&["get", "OPENAI_KEY", "--allow-view"]),
        "sk-openai-live-secret"
    );
    // Project secret resolves without --project, and names are case-insensitive
    assert_eq!(
        sb.ok(&["get", "DATABASE_URL", "--allow-view"]),
        "postgres://user:pass@db:5432/main"
    );
    assert_eq!(
        sb.ok(&["get", "openai_key", "--allow-view"]),
        "sk-openai-live-secret"
    );
    // Piped output is the raw value with no trailing newline
    assert_eq!(sb.ok(&["get", "OPENAI_KEY"]), "sk-openai-live-secret");

    let table = sb.ok(&["list"]);
    assert!(table.contains("OPENAI_KEY") && table.contains("DATABASE_URL"));
    assert!(!table.contains("sk-openai-live-secret"));
    let json: serde_json::Value =
        serde_json::from_str(&sb.ok(&["list", "--format", "json"])).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 2);

    assert_eq!(
        sb.ok(&["run", "--", "sh", "-c", "echo $OPENAI_KEY"]).trim(),
        "sk-openai-live-secret"
    );
    assert_eq!(
        sb.ok(&[
            "run",
            "--project",
            "backend",
            "--",
            "sh",
            "-c",
            "echo $DATABASE_URL"
        ])
        .trim(),
        "postgres://user:pass@db:5432/main"
    );

    let bad = sb.fails(&["run", "--", "NonExistentProgramXYZ"]);
    assert!(bad.contains("Command 'NonExistentProgramXYZ' was not found"));
    assert!(bad.contains("apiman get"));

    // passwd re-encrypts; old password stops working, new one works
    let new_password = "brand-new-master-password-999";
    let mut passwd = sb.cmd();
    passwd.arg("passwd");
    let out = sb.run_stdin(passwd, &format!("{new_password}\n{new_password}\n"));
    assert!(
        out.status.success(),
        "passwd failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    sb.stop_daemon();
    let mut with_new = sb.cmd();
    with_new.env("APIMAN_MASTER_PASSWORD", new_password).args([
        "get",
        "OPENAI_KEY",
        "--allow-view",
    ]);
    let out = with_new.output().unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "sk-openai-live-secret"
    );

    sb.stop_daemon();
    assert!(
        !sb.run(&["get", "OPENAI_KEY", "--allow-view"])
            .status
            .success()
    );

    let new = |args: &[&str]| {
        let mut c = sb.cmd();
        c.env("APIMAN_MASTER_PASSWORD", new_password).args(args);
        c.output().unwrap()
    };

    assert!(new(&["delete", "OPENAI_KEY"]).status.success());
    assert!(!new(&["get", "OPENAI_KEY", "--allow-view"]).status.success());

    // Timeout: set, view, disable, restore (isolated config file)
    let config = sb.write_config(
        "cfg.json",
        serde_json::json!({ "vault_path": sb.vault, "auto_lock_timeout_seconds": 900 }),
    );
    let timeout = |arg: Option<&str>| {
        let mut c = sb.bare();
        c.arg("--config").arg(&config).arg("timeout");
        if let Some(a) = arg {
            c.arg(a);
        }
        c.output().unwrap()
    };
    let set = timeout(Some("30m"));
    assert!(set.status.success());
    assert!(String::from_utf8_lossy(&set.stderr).contains("30m"));
    let view = timeout(None);
    assert!(String::from_utf8_lossy(&view.stdout).contains("Configured Timeout"));
    let none = timeout(Some("none"));
    assert!(String::from_utf8_lossy(&none.stderr).contains("always unlocked"));
    assert!(timeout(Some("15m")).status.success());
    let saved: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&config).unwrap()).unwrap();
    assert_eq!(saved["auto_lock_timeout_seconds"], 900);
    assert!(!timeout(Some("99999999999999999999d")).status.success());

    let status = String::from_utf8_lossy(&new(&["status"]).stdout).into_owned();
    assert!(status.contains("Vault Path:") && status.contains("Installed:"));

    // Import a .env file covering the supported syntax
    let env_file = sb.path("import_test.env");
    std::fs::write(
        &env_file,
        "# sample service config\nexport EXPORTED_KEY=exported-value\nPLAIN=plainvalue\nQUOTED_DOUBLE=\"hello world # not a comment\"\nQUOTED_SINGLE='single quoted'\nESCAPED=\"line1\\nline2\"\nINLINE=somevalue # trailing comment\nEMPTY_PLACEHOLDER=\nINVALID LINE WITHOUT EQUALS\n123BADKEY=oops\nSPACED = spaced-value\n",
    )
    .unwrap();
    let import = new(&[
        "import",
        env_file.to_str().unwrap(),
        "--project",
        "backend",
        "--tags",
        "e2etag",
    ]);
    assert!(import.status.success());
    let import_err = String::from_utf8_lossy(&import.stderr);
    assert!(
        import_err.contains("Imported 7"),
        "unexpected: {import_err}"
    );

    let get = |name: &str| {
        String::from_utf8_lossy(&new(&["get", name, "--allow-view"]).stdout).into_owned()
    };
    assert_eq!(get("QUOTED_DOUBLE"), "hello world # not a comment");
    assert_eq!(get("EXPORTED_KEY"), "exported-value");
    assert_eq!(get("ESCAPED"), "line1\nline2");
    assert_eq!(get("INLINE"), "somevalue");
    assert_eq!(get("SPACED"), "spaced-value");

    let placeholders = sb.path("placeholders.env");
    std::fs::write(&placeholders, "FUTURE_KEY=\nANOTHER_ONE=\n").unwrap();
    let out = new(&["import", placeholders.to_str().unwrap()]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("Imported 0"));

    // Export to file (0600) and the keys-only example template
    let export_file = sb.path("exported.env");
    assert!(
        new(&[
            "export",
            "--project",
            "backend",
            "--output",
            export_file.to_str().unwrap()
        ])
        .status
        .success()
    );
    let exported = std::fs::read_to_string(&export_file).unwrap();
    assert!(exported.contains("PLAIN=plainvalue"));
    assert!(exported.contains("QUOTED_DOUBLE='hello world # not a comment'"));
    assert!(exported.contains("ESCAPED=\"line1\\nline2\""));
    assert!(exported.contains("DATABASE_URL="));
    assert_eq!(file_mode(&export_file), 0o600);

    let example = sb.path("exported.env.example");
    assert!(
        new(&[
            "export",
            "--project",
            "backend",
            "--format",
            "example",
            "--output",
            example.to_str().unwrap()
        ])
        .status
        .success()
    );
    let example_text = std::fs::read_to_string(&example).unwrap();
    assert!(example_text.contains("PLAIN=\n"));
    assert!(!example_text.contains("plainvalue") && !example_text.contains("exported-value"));

    // Exporting into a directory uses the default file name
    let export_dir = sb.path("export-target");
    std::fs::create_dir_all(&export_dir).unwrap();
    assert!(
        new(&[
            "export",
            "--project",
            "backend",
            "--output",
            &format!("{}/", export_dir.display())
        ])
        .status
        .success()
    );
    let dir_text = std::fs::read_to_string(export_dir.join("apiman-export.env")).unwrap();
    assert!(dir_text.contains("PLAIN=plainvalue"));
}

#[test]
fn test_install_to_custom_dir() {
    let sb = Sandbox::new();
    let custom_dir = sb.path("custom-bin");

    let install = sb
        .bare()
        .args(["install", custom_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(install.status.success());
    let install_err = String::from_utf8_lossy(&install.stderr);
    assert!(install_err.contains("Installed apiman binary"));
    // A directory outside PATH triggers the PATH warning
    assert!(install_err.contains("not in your PATH"));

    let installed = custom_dir.join("apiman");
    assert!(installed.is_file());
    assert_eq!(file_mode(&installed), 0o755);

    // Force reinstall over the existing binary
    assert!(
        sb.bare()
            .args(["install", custom_dir.to_str().unwrap()])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(installed.is_file());
}

#[test]
fn test_stale_daemon_self_heal() {
    let sb = Sandbox::new();
    sb.init();
    sb.ok(&["set", "HEAL_KEY", "heal-value"]);
    sb.stop_daemon();

    // Seed a daemon holding a wrong key on the same socket
    let mut seed = sb
        .bare()
        .args([
            "daemon",
            "--run",
            "--timeout",
            "900",
            "--socket",
            sb.socket.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    seed.stdin
        .take()
        .unwrap()
        .write_all(b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
        .unwrap();
    for _ in 0..40 {
        if sb.socket.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    // Correct password still works despite the stale key...
    assert_eq!(sb.ok(&["get", "HEAL_KEY", "--allow-view"]), "heal-value");

    // ...and the stale daemon was replaced: a wrong password now unlocks via cache
    let out = sb
        .cmd()
        .env("APIMAN_MASTER_PASSWORD", "definitely-wrong-password")
        .args(["get", "HEAL_KEY", "--allow-view"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "daemon still holds stale key: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "heal-value");
    let _ = seed.wait();
}

#[test]
fn test_tui_pin_interleaved_and_group_space() {
    let sb = Sandbox::new();
    let mut app = sb.tui(&[
        ("K1", "K1-value", None),
        ("K2", "K2-value", None),
        ("K3", "K3-value", None),
        ("K4", "K4-value", None),
    ]);

    // Tab pins K1 and advances; plain Down keeps the pin; Tab pins K3 -> {K1, K3}
    press(&mut app, key(KeyCode::Tab));
    assert!(app.in_group_mode());
    assert_eq!(app.marked.len(), 1);
    press(&mut app, key(KeyCode::Down));
    assert_eq!(app.marked.len(), 1);
    assert_eq!(app.selected_index, 2);
    press(&mut app, key(KeyCode::Tab));
    assert_eq!(names(&app.marked_entries()), vec!["K1", "K3"]);

    // Shift+Down extends from the cursor and unions with pins
    press(&mut app, shift(KeyCode::Down));
    assert_eq!(app.marked.len(), 3);

    // Plain navigation commits instead of deselecting
    press(&mut app, key(KeyCode::Down));
    press(&mut app, key(KeyCode::Up));
    assert_eq!(app.marked.len(), 3);

    // Export writes exactly the marked entries
    let target = sb.path("pinned-export.env");
    app.path_form.path.text = target.to_string_lossy().to_string();
    app.path_form.export_example = false;
    app.run_export().unwrap();
    let text = std::fs::read_to_string(&target).unwrap();
    assert!(text.contains("K1=") && text.contains("K3=") && text.contains("K4="));
    assert!(!text.contains("K2="));

    // Space in group mode reveals exactly the marked entries, then masks them
    press(&mut app, key(KeyCode::Char(' ')));
    assert_eq!(app.revealed_entries.len(), 3);
    press(&mut app, key(KeyCode::Char(' ')));
    assert!(app.revealed_entries.is_empty());

    // Bulk edit applies to the interleaved pins only
    press(&mut app, key(KeyCode::Esc));
    assert!(!app.in_group_mode());
    press(&mut app, key(KeyCode::Home));
    press(&mut app, key(KeyCode::Tab));
    press(&mut app, key(KeyCode::Down));
    press(&mut app, key(KeyCode::Tab));
    press(&mut app, key(KeyCode::Char('e')));
    assert_eq!(app.active_modal, ActiveModal::BulkEdit);
    type_text(&mut app, "teamp");
    press(&mut app, key(KeyCode::Tab));
    type_text(&mut app, "shared");
    press(&mut app, key(KeyCode::Enter));
    for name in ["K1", "K3"] {
        let entry = app.ctx.vault.find_in_scope(name, Some("teamp")).unwrap();
        assert_eq!(entry.tags, vec!["shared".to_string()]);
    }
    for name in ["K2", "K4"] {
        let entry = app.ctx.vault.get(name, None).unwrap();
        assert!(entry.is_global());
        assert_eq!(entry.value.expose_secret(), format!("{name}-value"));
    }
}

#[test]
fn test_tui_reveal_all_and_path_completion() {
    let sb = Sandbox::new();
    let mut app = sb.tui(&[
        ("FIRST_KEY", "first-value", None),
        ("SECOND_KEY", "second-value", Some("proj")),
    ]);
    assert_eq!(app.filtered_indices.len(), 2);

    app.toggle_reveal_all();
    assert_eq!(app.revealed_entries.len(), 2);
    app.toggle_reveal_all();
    assert!(app.revealed_entries.is_empty());

    // `*`, `V` and Shift+Space all reveal everything; plain Space toggles one
    press(&mut app, key(KeyCode::Char('*')));
    assert_eq!(app.revealed_entries.len(), 2);
    press(&mut app, key(KeyCode::Char('V')));
    assert!(app.revealed_entries.is_empty());
    press(&mut app, shift(KeyCode::Char(' ')));
    assert_eq!(app.revealed_entries.len(), 2);
    press(&mut app, key(KeyCode::Char(' ')));
    assert_eq!(app.revealed_entries.len(), 1);

    // Reveal-all respects the active search filter
    app.search_query = TextField::new("first".to_string());
    app.update_filtered_indices();
    assert_eq!(app.filtered_indices.len(), 1);
    assert_eq!(app.selected_entry().unwrap().name, "FIRST_KEY");
    let visible_id = app.selected_entry().unwrap().id.clone();
    app.revealed_entries.clear();
    app.toggle_reveal_all();
    assert!(app.revealed_entries.contains(&visible_id));
    assert_eq!(app.revealed_entries.len(), 1);

    // Path completion: single match completes, multi-match extends common prefix
    let comp_dir = sb.path("complete");
    std::fs::create_dir_all(&comp_dir).unwrap();
    for (f, c) in [
        ("alpha.env", "A=1"),
        ("alphabet.env", "B=2"),
        ("beta.env", "C=3"),
    ] {
        std::fs::write(comp_dir.join(f), c).unwrap();
    }
    let base = comp_dir.to_string_lossy().to_string();
    let (done, msg) = complete_path(&format!("{base}/alp"));
    assert_eq!(done, format!("{base}/alpha"));
    assert!(msg.contains("2 matches"), "unexpected: {msg}");
    let (done, msg) = complete_path(&format!("{base}/bet"));
    assert_eq!(done, format!("{base}/beta.env"));
    assert!(msg.contains("Completed"));
    let (same, msg) = complete_path(&format!("{base}/zzz"));
    assert_eq!(same, format!("{base}/zzz"));
    assert_eq!(msg, "No matches");
}

#[test]
fn test_tui_multiselect_bulk_edit() {
    let sb = Sandbox::new();
    let mut app = sb.tui(&[
        ("AAA_KEY", "AAA_KEY-value", None),
        ("BBB_KEY", "BBB_KEY-value", None),
        ("CCC_KEY", "CCC_KEY-value", None),
    ]);

    press(&mut app, shift(KeyCode::Down));
    assert_eq!(app.marked.len(), 2);
    press(&mut app, shift(KeyCode::Down));
    assert_eq!(app.marked.len(), 3);
    press(&mut app, shift(KeyCode::Up));
    assert_eq!(app.marked.len(), 2);

    press(&mut app, key(KeyCode::Down));
    assert_eq!(app.marked.len(), 2);
    press(&mut app, key(KeyCode::Esc));
    assert!(!app.in_group_mode());

    press(&mut app, key(KeyCode::Home));
    press(&mut app, shift(KeyCode::Down));
    press(&mut app, shift(KeyCode::Down));
    press(&mut app, key(KeyCode::Char('e')));
    assert_eq!(app.active_modal, ActiveModal::BulkEdit);
    type_text(&mut app, "webapp");
    press(&mut app, key(KeyCode::Tab));
    type_text(&mut app, "prod,api");
    press(&mut app, key(KeyCode::Enter));
    assert_eq!(app.active_modal, ActiveModal::None);
    assert!(!app.in_group_mode());
    for name in ["AAA_KEY", "BBB_KEY", "CCC_KEY"] {
        let entry = app.ctx.vault.find_in_scope(name, Some("webapp")).unwrap();
        assert_eq!(entry.value.expose_secret(), format!("{name}-value"));
        assert_eq!(entry.tags, vec!["prod".to_string(), "api".to_string()]);
    }

    // Group delete removes every selected entry, and it is persisted
    press(&mut app, key(KeyCode::Home));
    press(&mut app, shift(KeyCode::Down));
    press(&mut app, shift(KeyCode::Down));
    press(&mut app, key(KeyCode::Char('d')));
    press(&mut app, key(KeyCode::Char('y')));
    assert!(app.ctx.vault.entries.is_empty());
    let (on_disk, _, _) =
        apiman::storage::load_vault_with_password(&sb.password, &sb.vault).unwrap();
    assert!(on_disk.entries.is_empty());
}

#[test]
fn test_cli_delete_resolution_run_hygiene_and_validation() {
    let sb = Sandbox::new();
    sb.init();

    sb.ok(&["set", "CaseKey", "case-value", "--project", "MyProj"]);
    // A unique name resolves case-insensitively across projects
    sb.ok(&["delete", "casekey"]);
    assert!(!sb.run(&["get", "CaseKey", "--allow-view"]).status.success());
    assert!(!sb.run(&["delete", "NoSuchKey"]).status.success());

    // Names that would corrupt .env output or env injection are rejected
    assert!(!sb.run(&["set", "BAD=NAME", "x"]).status.success());
    assert!(!sb.run(&["set", "BAD NAME", "x"]).status.success());
    assert!(!sb.run(&["set", "BAD/NAME", "x"]).status.success());
    assert!(!sb.run(&["set", "EMPTY_VALUE", ""]).status.success());

    // `run` never leaks the master password into the child
    sb.ok(&["set", "PING", "pong"]);
    let out = sb.ok(&[
        "run",
        "--",
        "sh",
        "-c",
        "echo [$APIMAN_MASTER_PASSWORD][$APIMAN_PASSWORD][$PING]",
    ]);
    assert_eq!(out.trim(), "[][][pong]");

    let bom = sb.path("bom.env");
    std::fs::write(&bom, "\u{FEFF}BOM_KEY=bom-value\n").unwrap();
    sb.ok(&["import", bom.to_str().unwrap()]);
    assert_eq!(sb.ok(&["get", "BOM_KEY", "--allow-view"]), "bom-value");

    // `status --config` honors a custom config file
    let cfg = sb.write_config(
        "custom.json",
        serde_json::json!({ "vault_path": sb.vault, "auto_lock_timeout_seconds": 60 }),
    );
    let status = sb
        .bare()
        .arg("--config")
        .arg(&cfg)
        .arg("status")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&status.stdout).contains("vault.enc"));

    // Install + uninstall roundtrip
    let bindir = sb.path("bin");
    assert!(
        sb.bare()
            .args(["install", bindir.to_str().unwrap()])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(bindir.join("apiman").is_file());
    assert!(
        sb.bare()
            .args(["uninstall", bindir.to_str().unwrap()])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(!bindir.join("apiman").exists());
}

#[test]
fn test_tui_ctrl_key_guards() {
    let sb = Sandbox::new();
    let mut app = sb.tui(&[("GUARD_KEY", "guard-value", None)]);

    // Ctrl+D must not open delete; Ctrl+E must not open the editor
    press(
        &mut app,
        KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL),
    );
    assert_eq!(app.active_modal, ActiveModal::None);
    assert_eq!(app.ctx.vault.entries.len(), 1);
    press(
        &mut app,
        KeyEvent::new(KeyCode::Char('e'), KeyModifiers::CONTROL),
    );
    assert_eq!(app.active_modal, ActiveModal::None);

    // Ctrl+C quits even from inside a modal
    press(&mut app, key(KeyCode::Char('a')));
    assert_eq!(app.active_modal, ActiveModal::Add);
    press(&mut app, ctrl('c'));
    assert!(app.should_quit);
}
