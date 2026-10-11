mod common;

use common::*;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    cond()
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn vault_header_is_authenticated_and_tampering_is_detected() {
    let sb = Sandbox::new();
    sb.init();
    sb.ok(&["set", "TAMPER_KEY", "tamper-value"]);

    let original = std::fs::read(&sb.vault).unwrap();
    assert_eq!(&original[..8], b"APIMAN02");
    assert_eq!(file_mode(&sb.vault), 0o600);

    // Flipping a salt byte must fail both via the cached session key (AAD)
    // and via password derivation.
    let mut tampered = original.clone();
    tampered[25] ^= 0x01;
    std::fs::write(&sb.vault, &tampered).unwrap();
    assert!(
        !sb.run(&["get", "TAMPER_KEY", "--allow-view"])
            .status
            .success()
    );
    sb.stop_daemon();
    let err = sb.fails(&["get", "TAMPER_KEY", "--allow-view"]);
    assert!(
        err.contains("Authentication failed") || err.contains("Incorrect"),
        "{err}"
    );

    // Absurd KDF parameters in the header are refused instead of allocating.
    let mut huge = original.clone();
    huge[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    std::fs::write(&sb.vault, &huge).unwrap();
    assert!(
        sb.fails(&["get", "TAMPER_KEY", "--allow-view"])
            .contains("Unsupported key derivation")
    );

    std::fs::write(&sb.vault, &original).unwrap();
    assert_eq!(
        sb.ok(&["get", "TAMPER_KEY", "--allow-view"]),
        "tamper-value"
    );
}

#[test]
fn legacy_v1_vault_opens_and_is_upgraded_on_write() {
    use argon2::{Algorithm, Argon2, Params, Version};
    use chacha20poly1305::{
        XChaCha20Poly1305, XNonce,
        aead::{Aead, KeyInit},
    };

    let sb = Sandbox::new();
    let salt = [7u8; 32];
    let nonce = [9u8; 24];
    let mut key = [0u8; 32];
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(65536, 3, 4, Some(32)).unwrap(),
    )
    .hash_password_into(sb.password.as_bytes(), &salt, &mut key)
    .unwrap();
    let json = serde_json::json!({"version": 1, "entries": [{
        "id": "legacy-1", "name": "LEGACY_KEY", "project": null, "value": "legacy-value",
        "tags": [], "description": null, "created_at": 1, "updated_at": 1
    }]});
    let ct = XChaCha20Poly1305::new_from_slice(&key)
        .unwrap()
        .encrypt(
            XNonce::from_slice(&nonce),
            serde_json::to_vec(&json).unwrap().as_slice(),
        )
        .unwrap();
    let mut envelope = b"APIMAN01".to_vec();
    envelope.extend_from_slice(&salt);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ct);
    std::fs::write(&sb.vault, envelope).unwrap();

    assert_eq!(
        sb.ok(&["get", "LEGACY_KEY", "--allow-view"]),
        "legacy-value"
    );
    sb.ok(&["set", "NEW_KEY", "new-value"]);
    assert_eq!(&std::fs::read(&sb.vault).unwrap()[..8], b"APIMAN02");

    sb.stop_daemon();
    assert_eq!(
        sb.ok(&["get", "LEGACY_KEY", "--allow-view"]),
        "legacy-value"
    );
    assert_eq!(sb.ok(&["get", "NEW_KEY", "--allow-view"]), "new-value");
}

#[test]
fn weak_master_passwords_are_rejected() {
    let sb = Sandbox::new();
    let mut cmd = sb.bare();
    cmd.arg("--vault").arg(&sb.vault).arg("init");
    let out = sb.run_stdin(cmd, "short\nshort\n");
    assert!(!out.status.success());
    assert!(stderr(&out).contains("at least 8"));
    assert!(!sb.vault.exists());

    let mut cmd = sb.bare();
    cmd.arg("--vault").arg(&sb.vault).arg("init");
    let out = sb.run_stdin(cmd, "long-enough-1\nlong-enough-2\n");
    assert!(stderr(&out).contains("do not match"));
    assert!(!sb.vault.exists());
}

#[test]
fn default_vault_name_and_legacy_vault_migration() {
    // Fresh install: the default vault is apiman_vault.enc
    let fresh = Sandbox::new();
    let mut cmd = fresh.bare();
    cmd.arg("init");
    let out = fresh.run_stdin(cmd, &format!("{0}\n{0}\n", fresh.password));
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(fresh.config_dir().join("apiman_vault.enc").is_file());
    assert!(!fresh.config_dir().join("vault.enc").exists());

    // Upgrade: an old vault.enc plus a config pointing at it is renamed once
    let sb = Sandbox::new();
    let legacy = sb.config_dir().join("vault.enc");
    std::fs::create_dir_all(sb.config_dir()).unwrap();
    let (mut vault, key, params) = apiman::storage::init_vault(&sb.password, &legacy).unwrap();
    vault.set("OLD_KEY".into(), "old-value".into(), None, Vec::new(), None);
    apiman::storage::save_vault(&vault, &key, &params, &legacy).unwrap();
    std::fs::write(
        sb.config_dir().join("config.json"),
        serde_json::json!({ "vault_path": legacy, "auto_lock_timeout_seconds": 900 }).to_string(),
    )
    .unwrap();

    let out = sb
        .bare()
        .env("APIMAN_MASTER_PASSWORD", &sb.password)
        .args(["get", "OLD_KEY"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "old-value");
    assert!(stderr(&out).contains("renamed vault"));
    assert!(!legacy.exists());
    assert!(sb.config_dir().join("apiman_vault.enc").is_file());
    let cfg = std::fs::read_to_string(sb.config_dir().join("config.json")).unwrap();
    assert!(cfg.contains("apiman_vault.enc"), "{cfg}");

    // Malformed config is reported, never silently overwritten
    std::fs::write(sb.config_dir().join("config.json"), "{ not json").unwrap();
    let out = sb.bare().arg("status").output().unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("Invalid config file"));
    assert_eq!(
        std::fs::read_to_string(sb.config_dir().join("config.json")).unwrap(),
        "{ not json"
    );
}

#[test]
fn scope_resolution_is_strict_and_never_guesses() {
    let sb = Sandbox::new();
    sb.init();
    sb.ok(&["set", "SHARED", "global-value"]);
    sb.ok(&["set", "DUP", "p1-value", "--project", "p1"]);
    sb.ok(&["set", "DUP", "p2-value", "--project", "p2"]);

    assert!(
        sb.fails(&["get", "DUP", "--allow-view"])
            .contains("several projects (p1, p2)")
    );
    assert_eq!(
        sb.ok(&["get", "DUP", "--project", "P1", "--allow-view"]),
        "p1-value"
    );
    assert_eq!(
        sb.ok(&["get", "apiman://p2/DUP", "--allow-view"]),
        "p2-value"
    );
    // An explicit project falls back to global, never to another project
    assert_eq!(
        sb.ok(&["get", "SHARED", "--project", "p1", "--allow-view"]),
        "global-value"
    );
    assert!(
        sb.fails(&["get", "DUP", "--project", "p3", "--allow-view"])
            .contains("not found in scope 'p3'")
    );
    assert!(
        sb.fails(&["get", "DUP", "--project", "global", "--allow-view"])
            .contains("not found")
    );

    // delete --project only touches that project
    assert!(
        sb.fails(&["delete", "SHARED", "--project", "p1"])
            .contains("not found in scope 'p1'")
    );
    assert_eq!(sb.ok(&["get", "SHARED", "--allow-view"]), "global-value");
    assert!(sb.fails(&["delete", "DUP"]).contains("several projects"));
    sb.ok(&["delete", "DUP", "--project", "p2"]);
    assert_eq!(sb.ok(&["get", "DUP", "--allow-view"]), "p1-value");

    // Project names match case-insensitively on update, so no duplicates appear
    sb.ok(&["set", "DUP", "updated", "--project", "P1"]);
    let list: serde_json::Value =
        serde_json::from_str(&sb.ok(&["list", "--format", "json"])).unwrap();
    let dups: Vec<_> = list
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["name"] == "DUP")
        .collect();
    assert_eq!(dups.len(), 1);
    assert_eq!(dups[0]["reference"], "apiman://p1/DUP");

    // Description can be cleared, and an empty value is refused
    sb.ok(&["set", "SHARED", "v2", "--description", "note"]);
    sb.ok(&["set", "SHARED", "v3", "--description", ""]);
    let list: serde_json::Value =
        serde_json::from_str(&sb.ok(&["list", "--format", "json"])).unwrap();
    let shared = list
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "SHARED")
        .unwrap();
    assert!(shared["description"].is_null());
    assert!(sb.fails(&["set", "SHARED", ""]).contains("cannot be empty"));
}

#[test]
fn multiline_values_and_dotenv_round_trip() {
    let sb = Sandbox::new();
    sb.init();

    // Piped stdin keeps every line (PEM keys), minus one trailing newline
    let pem = "-----BEGIN KEY-----\nAAAA\nBBBB\n-----END KEY-----";
    let mut cmd = sb.cmd();
    cmd.args(["set", "TLS_KEY"]);
    let out = sb.run_stdin(cmd, &format!("{pem}\n"));
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(sb.ok(&["get", "TLS_KEY"]), pem);

    let env_file = sb.path("in.env");
    std::fs::write(
        &env_file,
        "MULTI=\"first\nsecond\"\nAFTER=still-parsed\nPLACEHOLDER= # describe the key here\nHASHED=#not-a-comment\nAPOSTROPHE=it's # trailing\nDOLLAR='pa$$word'\nTAB=\"a\\tb\"\n",
    )
    .unwrap();
    let out = sb.run(&["import", env_file.to_str().unwrap(), "--project", "src"]);
    assert!(stderr(&out).contains("Imported 6"), "{}", stderr(&out));
    let get = |name: &str| sb.ok(&["get", name, "--project", "src"]);
    assert_eq!(get("MULTI"), "first\nsecond");
    assert_eq!(get("AFTER"), "still-parsed");
    assert_eq!(get("HASHED"), "#not-a-comment");
    assert_eq!(get("APOSTROPHE"), "it's");
    assert_eq!(get("DOLLAR"), "pa$$word");
    assert_eq!(get("TAB"), "a\tb");

    // .env export re-imports to identical values
    let exported = sb.path("out.env");
    sb.ok(&[
        "export",
        "--project",
        "src",
        "--output",
        exported.to_str().unwrap(),
    ]);
    let text = std::fs::read_to_string(&exported).unwrap();
    assert!(text.contains("DOLLAR='pa$$word'"), "{text}");
    sb.ok(&["import", exported.to_str().unwrap(), "--project", "copy"]);
    for name in [
        "MULTI",
        "AFTER",
        "HASHED",
        "APOSTROPHE",
        "DOLLAR",
        "TAB",
        "TLS_KEY",
    ] {
        assert_eq!(
            sb.ok(&["get", name, "--project", "copy"]),
            sb.ok(&["get", name, "--project", "src"]),
            "{name}"
        );
    }

    // Shell format survives eval byte for byte
    let shell = sb.ok(&["export", "--project", "src", "--format", "shell"]);
    let script = sb.path("env.sh");
    std::fs::write(&script, shell).unwrap();
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!(
            ". '{}' && printf '%s|%s|%s' \"$DOLLAR\" \"$APOSTROPHE\" \"$MULTI\"",
            script.display()
        ))
        .output()
        .unwrap();
    assert_eq!(stdout(&out), "pa$$word|it's|first\nsecond");

    // Paths with ~ are expanded for import
    std::fs::write(sb.home.join("home.env"), "FROM_HOME=yes\n").unwrap();
    sb.ok(&["import", "~/home.env"]);
    assert_eq!(sb.ok(&["get", "FROM_HOME"]), "yes");
}

#[test]
fn export_scopes_refs_and_references_in_run() {
    let sb = Sandbox::new();
    sb.init();
    sb.ok(&["set", "GLOBAL_ONLY", "g-value"]);
    sb.ok(&["set", "API_KEY", "api-secret-value", "--project", "web"]);
    sb.ok(&["set", "OTHER", "other-value", "--project", "worker"]);

    // .env.example matches what `export` and `run` would provide for that scope
    let example = sb.ok(&["export", "--format", "example"]);
    assert!(example.contains("GLOBAL_ONLY=") && !example.contains("API_KEY="));
    let example = sb.ok(&["export", "--format", "example", "--project", "web"]);
    assert!(
        example.contains("API_KEY=")
            && example.contains("GLOBAL_ONLY=")
            && !example.contains("OTHER=")
    );

    // refs format: safe to commit, resolved by run --env-file
    let refs_file = sb.path(".env.apiman");
    sb.ok(&[
        "export",
        "--project",
        "web",
        "--format",
        "refs",
        "--output",
        refs_file.to_str().unwrap(),
    ]);
    let refs = std::fs::read_to_string(&refs_file).unwrap();
    assert!(
        refs.contains("API_KEY=apiman://web/API_KEY")
            && refs.contains("GLOBAL_ONLY=apiman://GLOBAL_ONLY")
    );
    assert!(!refs.contains("api-secret-value"));
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&refs_file)
        .unwrap();
    writeln!(f, "PORT=8080").unwrap();

    let out = sb.ok(&[
        "run",
        "--env-file",
        refs_file.to_str().unwrap(),
        "--",
        "sh",
        "-c",
        "echo $API_KEY,$GLOBAL_ONLY,$PORT,${OTHER:-none}",
    ]);
    assert_eq!(out.trim(), "api-secret-value,g-value,8080,none");

    // References already in the environment are resolved as well
    let out = sb
        .cmd()
        .env("MY_TOKEN", "apiman://worker/OTHER")
        .args([
            "run",
            "--only",
            "GLOBAL_ONLY",
            "--",
            "sh",
            "-c",
            "echo $MY_TOKEN,$GLOBAL_ONLY,${API_KEY:-none}",
        ])
        .output()
        .unwrap();
    assert_eq!(stdout(&out).trim(), "other-value,g-value,none");

    // A broken reference fails closed: the program never runs
    let marker = sb.path("ran");
    let out = sb
        .cmd()
        .env("BROKEN", "apiman://nope/MISSING")
        .args(["run", "--", "touch", marker.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("BROKEN"));
    assert!(!marker.exists());

    // Export to a project without entries warns
    let out = sb.run(&["export", "--project", "typo", "--format", "example"]);
    assert!(stderr(&out).contains("no entries in project 'typo'"));
}

#[test]
fn run_least_privilege_exit_codes_and_masking() {
    let sb = Sandbox::new();
    sb.init();
    sb.ok(&["set", "TOKEN", "abcdef-123456-secret"]);
    sb.ok(&["set", "UNRELATED", "unrelated-secret"]);

    let out = sb.ok(&[
        "run",
        "--only",
        "TOKEN",
        "--",
        "sh",
        "-c",
        "echo ${TOKEN:+set},${UNRELATED:-absent}",
    ]);
    assert_eq!(out.trim(), "set,absent");

    let out = sb.run(&["run", "--", "sh", "-c", "exit 7"]);
    assert_eq!(out.status.code(), Some(7));
    let out = sb.run(&["run", "--mask", "--", "sh", "-c", "exit 9"]);
    assert_eq!(out.status.code(), Some(9));

    // Masked: the program gets the real value, its output does not show it,
    // even when the value is written in pieces across reads.
    let seen = sb.path("seen");
    let script = format!(
        "printf '%s' \"$TOKEN\" > '{}'; echo \"out:$TOKEN\"; echo \"err:$TOKEN\" >&2; printf 'abcdef-123'; sleep 0.3; printf '456-secret\\n'",
        seen.display()
    );
    let out = sb.run(&[
        "run", "--mask", "--only", "TOKEN", "--", "sh", "-c", &script,
    ]);
    assert!(out.status.success());
    assert_eq!(
        std::fs::read_to_string(&seen).unwrap(),
        "abcdef-123456-secret"
    );
    let (o, e) = (stdout(&out), stderr(&out));
    assert!(
        !o.contains("abcdef-123456-secret") && !e.contains("abcdef-123456-secret"),
        "{o}{e}"
    );
    assert!(o.contains("out:[REDACTED:TOKEN]"), "{o}");
    assert!(o.ends_with("[REDACTED:TOKEN]\n"), "{o}");
    assert!(e.contains("err:[REDACTED:TOKEN]"));

    // Unknown --only names fail before anything runs
    assert!(
        sb.fails(&["run", "--only", "NOPE", "--", "true"])
            .contains("not found")
    );
}

#[test]
fn session_daemon_survives_ctrl_c_and_reports_real_time_left() {
    let sb = Sandbox::new();
    sb.init();
    sb.ok(&["set", "K", "value-for-daemon"]);
    sb.stop_daemon();

    // `run` unlocks (spawning the daemon), then its whole process group gets
    // SIGINT exactly like Ctrl+C in a terminal. The daemon must survive.
    use std::os::unix::process::CommandExt;
    let mut job = sb
        .cmd()
        .args(["run", "--", "sleep", "5"])
        .process_group(0)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(wait_until(Duration::from_secs(10), || sb.socket.exists()));
    std::thread::sleep(Duration::from_millis(300));
    unsafe {
        libc::kill(-(job.id() as i32), libc::SIGINT);
    }
    let _ = job.wait();

    let status: serde_json::Value =
        serde_json::from_str(&sb.ok(&["status", "--format", "json"])).unwrap();
    assert_eq!(
        status["unlocked"], true,
        "daemon died with the terminal job: {status}"
    );

    // Status no longer resets the idle timer, so the countdown moves
    let first = status["remaining_seconds"].as_u64().unwrap();
    std::thread::sleep(Duration::from_millis(2100));
    let status: serde_json::Value =
        serde_json::from_str(&sb.ok(&["status", "--format", "json"])).unwrap();
    assert!(
        status["remaining_seconds"].as_u64().unwrap() < first,
        "{status}"
    );
}

#[test]
fn daemon_auto_locks_after_inactivity() {
    let sb = Sandbox::new();
    sb.init();
    let cfg = sb.write_config(
        "cfg.json",
        serde_json::json!({ "vault_path": sb.vault, "auto_lock_timeout_seconds": 1 }),
    );
    sb.stop_daemon();
    let out = sb
        .cmd()
        .arg("--config")
        .arg(&cfg)
        .arg("unlock")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(sb.socket.exists());
    assert!(
        wait_until(Duration::from_secs(5), || !sb.socket.exists()),
        "daemon did not auto-lock"
    );
    let status: serde_json::Value =
        serde_json::from_str(&sb.ok(&["status", "--format", "json"])).unwrap();
    assert_eq!(status["unlocked"], false);
}

#[test]
fn install_is_atomic_and_never_deletes_the_running_binary() {
    let sb = Sandbox::new();
    let bindir = sb.path("bin");
    assert!(
        sb.bare()
            .args(["install", bindir.to_str().unwrap()])
            .output()
            .unwrap()
            .status
            .success()
    );
    let installed = bindir.join("apiman");

    // Re-installing from the installed binary itself used to delete it
    let out = std::process::Command::new(&installed)
        .env("HOME", &sb.home)
        .args(["install", bindir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stderr(&out).contains("already installed"));
    assert!(installed.is_file());
    assert_eq!(file_mode(&installed), 0o755);

    // Relative directories are reported as absolute paths
    let out = sb
        .bare()
        .current_dir(sb.dir.path())
        .args(["install", "relbin"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(
        stderr(&out).contains(&sb.path("relbin").join("apiman").display().to_string()),
        "{}",
        stderr(&out)
    );
}

fn fake_clipboard(sb: &Sandbox) -> (std::path::PathBuf, String) {
    let bin = sb.path("fakebin");
    std::fs::create_dir_all(&bin).unwrap();
    let write_script = |name: &str, body: &str| {
        let p = bin.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    write_script(
        "wl-copy",
        "if [ \"$1\" = \"--clear\" ]; then : > \"$FAKE_CLIPBOARD\"; else cat > \"$FAKE_CLIPBOARD\"; fi",
    );
    write_script(
        "wl-paste",
        "[ -s \"$FAKE_CLIPBOARD\" ] || exit 1; cat \"$FAKE_CLIPBOARD\"",
    );
    let path = format!("{}:/usr/bin:/bin", bin.display());
    (sb.path("clipboard"), path)
}

#[test]
fn copy_clears_the_clipboard_only_if_unchanged() {
    let sb = Sandbox::new();
    sb.init();
    sb.ok(&["set", "CLIP_KEY", "clip-secret-value"]);
    let cfg = sb.write_config(
        "cfg.json",
        serde_json::json!({ "vault_path": sb.vault, "clipboard_timeout_seconds": 1 }),
    );
    let (clip, path) = fake_clipboard(&sb);
    let copy = || {
        sb.cmd()
            .arg("--config")
            .arg(&cfg)
            .env("PATH", &path)
            .env("FAKE_CLIPBOARD", &clip)
            .env_remove("WAYLAND_DISPLAY")
            .env_remove("DISPLAY")
            .args(["copy", "CLIP_KEY"])
            .output()
            .unwrap()
    };

    let out = copy();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stderr(&out).contains("clears in 1s"), "{}", stderr(&out));
    assert_eq!(std::fs::read_to_string(&clip).unwrap(), "clip-secret-value");
    assert!(
        wait_until(Duration::from_secs(5), || std::fs::read_to_string(&clip)
            .unwrap()
            .is_empty()),
        "clipboard was not cleared"
    );

    // Something the user copied afterwards is left alone
    assert!(copy().status.success());
    std::fs::write(&clip, "user copied this").unwrap();
    std::thread::sleep(Duration::from_millis(2500));
    assert_eq!(std::fs::read_to_string(&clip).unwrap(), "user copied this");
}

#[test]
fn agent_mode_masks_values_but_programs_get_real_ones() {
    let sb = Sandbox::new();
    sb.init();
    sb.ok(&["set", "AGENT_KEY", "sk-agent-real-value"]);

    // Default (agent_mode off): agents see values like anyone else
    let out = sb
        .cmd()
        .env("CLAUDECODE", "1")
        .args(["get", "AGENT_KEY"])
        .output()
        .unwrap();
    assert_eq!(stdout(&out), "sk-agent-real-value");

    let cfg = sb.write_config(
        "agent.json",
        serde_json::json!({ "vault_path": sb.vault, "agent_mode": "auto" }),
    );
    let agent = |marker: (&str, &str), args: &[&str]| {
        sb.cmd()
            .arg("--config")
            .arg(&cfg)
            .env(marker.0, marker.1)
            .args(args)
            .output()
            .unwrap()
    };
    let cc = ("CLAUDECODE", "1");

    let out = agent(cc, &["get", "AGENT_KEY", "--allow-view"]);
    assert!(out.status.success());
    assert_eq!(stdout(&out).trim(), "[REDACTED:AGENT_KEY]");
    assert!(stderr(&out).contains("Claude Code"));
    for marker in [
        ("APIMAN_AGENT", "1"),
        ("CODEX_SANDBOX", "seatbelt"),
        ("GEMINI_CLI", "1"),
    ] {
        assert_eq!(
            stdout(&agent(marker, &["get", "AGENT_KEY"])).trim(),
            "[REDACTED:AGENT_KEY]"
        );
    }
    // Without a marker, auto mode shows values
    let out = sb
        .cmd()
        .arg("--config")
        .arg(&cfg)
        .args(["get", "AGENT_KEY"])
        .output()
        .unwrap();
    assert_eq!(stdout(&out), "sk-agent-real-value");

    let out = agent(cc, &["export"]);
    assert!(stdout(&out).contains("AGENT_KEY=[REDACTED:AGENT_KEY]"));
    assert!(!stdout(&out).contains("sk-agent-real-value"));
    let target = sb.path("agent.env");
    assert!(
        !agent(cc, &["export", "--output", target.to_str().unwrap()])
            .status
            .success()
    );
    assert!(!target.exists());
    assert!(stderr(&agent(cc, &["copy", "AGENT_KEY"])).contains("agent mode"));
    assert!(
        !agent(cc, &["proxy", "add", "--preset", "openai"])
            .status
            .success()
    );

    // run: real value inside the program, masked in what the agent reads
    let seen = sb.path("seen");
    let out = agent(
        cc,
        &[
            "run",
            "--only",
            "AGENT_KEY",
            "--",
            "sh",
            "-c",
            &format!(
                "printf %s \"$AGENT_KEY\" > '{}'; echo $AGENT_KEY",
                seen.display()
            ),
        ],
    );
    assert!(out.status.success());
    assert_eq!(
        std::fs::read_to_string(&seen).unwrap(),
        "sk-agent-real-value"
    );
    assert_eq!(stdout(&out).trim(), "[REDACTED:AGENT_KEY]");

    let status: serde_json::Value =
        serde_json::from_str(&stdout(&agent(cc, &["status", "--format", "json"]))).unwrap();
    assert_eq!(status["agent_mode"], true);
}

struct Upstream {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
}

/// Minimal HTTP upstream that records request heads and echoes X-Api-Key.
fn start_upstream() -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut head = String::new();
            let mut content_length = 0;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    content_length = v.trim().parse().unwrap_or(0);
                }
                head.push_str(&line);
            }
            let mut body = vec![0; content_length];
            let _ = reader.read_exact(&mut body);
            let key = head
                .lines()
                .find_map(|l| {
                    l.strip_prefix("x-api-key: ")
                        .or_else(|| l.strip_prefix("X-Api-Key: "))
                })
                .unwrap_or("")
                .to_string();
            log.lock()
                .unwrap()
                .push(format!("{head}\n{}", String::from_utf8_lossy(&body)));
            let reply = format!("{{\"echo\":\"{key}\"}}");
            let mut stream = stream;
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                reply.len()
            );
        }
    });
    Upstream { port, seen }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn http(port: u16, request: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut out = String::new();
    let _ = stream.read_to_string(&mut out);
    out
}

#[test]
fn proxy_injects_the_key_upstream_and_never_returns_it() {
    let sb = Sandbox::new();
    sb.init();
    sb.ok(&["set", "UPKEY", "sk-upstream-real-key"]);
    let upstream = start_upstream();

    // Only https, or http to loopback, may receive a key
    assert!(
        sb.fails(&[
            "proxy",
            "add",
            "evil",
            "--secret",
            "UPKEY",
            "--upstream",
            "http://example.com"
        ])
        .contains("https")
    );
    assert!(
        sb.fails(&[
            "proxy",
            "add",
            "x",
            "--secret",
            "UPKEY",
            "--upstream",
            "https://user@example.com"
        ])
        .contains("Invalid upstream")
    );
    assert!(
        sb.fails(&[
            "proxy",
            "add",
            "nokey",
            "--secret",
            "UPKEY",
            "--upstream",
            "https://example.com",
            "--header",
            "X-Static: 1"
        ])
        .contains("never sends the secret")
    );

    sb.ok(&[
        "proxy",
        "add",
        "echo",
        "--secret",
        "UPKEY",
        "--upstream",
        &format!("http://127.0.0.1:{}", upstream.port),
        "--header",
        "X-Api-Key: {secret}",
        "--query",
        "key={secret}",
    ]);
    sb.ok(&["proxy", "add", "--preset", "openai"]);
    let list = sb.ok(&["proxy", "list"]);
    assert!(
        list.contains("echo")
            && list.contains("apiman://UPKEY")
            && !list.contains("sk-upstream-real-key")
    );
    let env = sb.ok(&["proxy", "env"]);
    assert!(
        env.contains("OPENAI_BASE_URL=http://127.0.0.1:8787/openai/v1"),
        "{env}"
    );

    let port = free_port();
    let _proxy = KillOnDrop(
        sb.cmd()
            .args(["proxy", "start", "--port", &port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    assert!(wait_until(Duration::from_secs(5), || TcpStream::connect((
        "127.0.0.1",
        port
    ))
    .is_ok()));

    let host = format!("Host: 127.0.0.1:{port}\r\n");
    let reply = http(
        port,
        &format!(
            "POST /echo/v1/things?x=1 HTTP/1.1\r\n{host}X-Api-Key: placeholder\r\nContent-Length: 4\r\nConnection: close\r\n\r\nping"
        ),
    );
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    assert!(reply.contains("[REDACTED:UPKEY]"), "{reply}");
    assert!(!reply.contains("sk-upstream-real-key"), "{reply}");

    let seen = upstream.seen.lock().unwrap().join("\n---\n");
    assert!(
        seen.contains("POST /v1/things?x=1&key=sk-upstream-real-key"),
        "{seen}"
    );
    assert!(
        seen.to_ascii_lowercase()
            .contains("x-api-key: sk-upstream-real-key"),
        "{seen}"
    );
    assert!(
        !seen.contains("placeholder"),
        "client credential leaked upstream: {seen}"
    );
    assert!(seen.contains("ping"));

    // Browser pages and DNS-rebinding hosts are refused
    let reply = http(
        port,
        &format!(
            "GET /echo/x HTTP/1.1\r\n{host}Origin: http://evil.test\r\nConnection: close\r\n\r\n"
        ),
    );
    assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
    let reply = http(
        port,
        &format!("GET /echo/x HTTP/1.1\r\nHost: evil.test:{port}\r\nConnection: close\r\n\r\n"),
    );
    assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
    let reply = http(
        port,
        &format!("GET /nope/x HTTP/1.1\r\n{host}Connection: close\r\n\r\n"),
    );
    assert!(reply.starts_with("HTTP/1.1 404"), "{reply}");

    // Locking the vault stops key injection immediately
    sb.stop_daemon();
    let reply = http(
        port,
        &format!("GET /echo/x HTTP/1.1\r\n{host}Connection: close\r\n\r\n"),
    );
    assert!(reply.starts_with("HTTP/1.1 423"), "{reply}");
    assert!(
        sb.fails(&["proxy", "start", "--bind", "0.0.0.0"])
            .contains("loopback")
    );
}

#[test]
fn keys_completions_and_skill_commands() {
    let sb = Sandbox::new();
    let out = sb.bare().arg("keys").output().unwrap();
    assert!(out.status.success());
    assert!(stdout(&out).contains("copy") && stdout(&out).contains("Ctrl+K"));

    let cfg = sb.write_config(
        "keys.json",
        serde_json::json!({ "keybindings": {
            "copy": "y", "delete": ["c"], "nonsense": "x", "lock": "ctrl+c", "quit": "hyper+q"
        }}),
    );
    let out = sb
        .bare()
        .arg("--config")
        .arg(&cfg)
        .arg("keys")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let (o, e) = (stdout(&out), stderr(&out));
    assert!(
        o.lines()
            .any(|l| l.starts_with("copy") && l.contains(" y ")),
        "{o}"
    );
    assert!(
        o.lines()
            .any(|l| l.starts_with("delete") && l.contains(" c ")),
        "{o}"
    );
    assert!(e.contains("unknown action 'nonsense'"), "{e}");
    assert!(e.contains("Ctrl+C is reserved"), "{e}");
    assert!(e.contains("unknown modifier 'hyper'"), "{e}");

    let out = sb.bare().args(["completions", "bash"]).output().unwrap();
    assert!(out.status.success() && stdout(&out).contains("apiman"));

    let skill = sb.bare().arg("skill").output().unwrap();
    let text = stdout(&skill);
    assert!(text.starts_with("---\nname: apiman\n"), "{text}");
    let repo_skill =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/skills/SKILL.md"))
            .unwrap();
    assert_eq!(text, repo_skill);
    let dest = sb.path("skills");
    assert!(
        sb.bare()
            .args(["skill", "--install", dest.to_str().unwrap()])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(
        std::fs::read_to_string(dest.join("apiman/SKILL.md")).unwrap(),
        repo_skill
    );

    // Piped help carries no color codes; NO_COLOR is honored
    let help = sb.bare().arg("--help").output().unwrap();
    assert!(!stdout(&help).contains('\u{1b}'));
    assert!(stdout(&help).contains("Examples:"));
}
