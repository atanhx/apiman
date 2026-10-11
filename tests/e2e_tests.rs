use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::tempdir;

#[test]
fn test_apiman_end_to_end_lifecycle() {
    let dir = tempdir().unwrap();
    let vault_file = dir.path().join("e2e_vault.enc");
    let binary = env!("CARGO_BIN_EXE_apiman");
    let master_password = "initial-secure-password-42";

    // 1. Initialize vault via `apiman init`
    let mut init_child = Command::new(binary)
        .arg("--vault")
        .arg(&vault_file)
        .arg("init")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    {
        let mut stdin = init_child.stdin.take().unwrap();
        // Send password twice
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
    let set_global = Command::new(binary)
        .arg("--vault")
        .arg(&vault_file)
        .arg("set")
        .arg("OPENAI_KEY")
        .arg("sk-openai-live-secret")
        .arg("--tags")
        .arg("ai,production")
        .arg("--description")
        .arg("Live OpenAI key")
        .env("APIMAN_MASTER_PASSWORD", master_password)
        .output()
        .unwrap();
    assert!(set_global.status.success());

    // 3. Set project-scoped secret
    let set_proj = Command::new(binary)
        .arg("--vault")
        .arg(&vault_file)
        .arg("set")
        .arg("DATABASE_URL")
        .arg("postgres://user:pass@db:5432/main")
        .arg("--project")
        .arg("backend")
        .arg("--tags")
        .arg("db,infra")
        .env("APIMAN_MASTER_PASSWORD", master_password)
        .output()
        .unwrap();
    assert!(set_proj.status.success());

    // 4. Retrieve global secret with --allow-view
    let get_global = Command::new(binary)
        .arg("--vault")
        .arg(&vault_file)
        .arg("get")
        .arg("OPENAI_KEY")
        .arg("--allow-view")
        .env("APIMAN_MASTER_PASSWORD", master_password)
        .output()
        .unwrap();
    assert!(get_global.status.success());
    assert_eq!(
        String::from_utf8_lossy(&get_global.stdout).trim(),
        "sk-openai-live-secret"
    );

    // 5. Retrieve project-scoped secret WITHOUT specifying --project (auto-resolution across projects)
    let get_auto = Command::new(binary)
        .arg("--vault")
        .arg(&vault_file)
        .arg("get")
        .arg("DATABASE_URL")
        .arg("--allow-view")
        .env("APIMAN_MASTER_PASSWORD", master_password)
        .output()
        .unwrap();
    assert!(get_auto.status.success());
    assert_eq!(
        String::from_utf8_lossy(&get_auto.stdout).trim(),
        "postgres://user:pass@db:5432/main"
    );

    // 6. Case-insensitive retrieval test
    let get_case = Command::new(binary)
        .arg("--vault")
        .arg(&vault_file)
        .arg("get")
        .arg("openai_key")
        .arg("--allow-view")
        .env("APIMAN_MASTER_PASSWORD", master_password)
        .output()
        .unwrap();
    assert!(get_case.status.success());
    assert_eq!(
        String::from_utf8_lossy(&get_case.stdout).trim(),
        "sk-openai-live-secret"
    );

    // 7. Piped retrieval (without --allow-view, output raw to stdout)
    let get_piped = Command::new(binary)
        .arg("--vault")
        .arg(&vault_file)
        .arg("get")
        .arg("OPENAI_KEY")
        .env("APIMAN_MASTER_PASSWORD", master_password)
        .output()
        .unwrap();
    assert!(get_piped.status.success());
    assert_eq!(
        String::from_utf8(get_piped.stdout).unwrap(),
        "sk-openai-live-secret"
    );

    // 8. List secrets in table and json formats
    let list_tbl = Command::new(binary)
        .arg("--vault")
        .arg(&vault_file)
        .arg("list")
        .env("APIMAN_MASTER_PASSWORD", master_password)
        .output()
        .unwrap();
    assert!(list_tbl.status.success());
    let list_str = String::from_utf8_lossy(&list_tbl.stdout);
    assert!(list_str.contains("OPENAI_KEY"));
    assert!(list_str.contains("DATABASE_URL"));
    assert!(!list_str.contains("sk-openai-live-secret")); // Values never printed in list

    let list_json = Command::new(binary)
        .arg("--vault")
        .arg(&vault_file)
        .arg("list")
        .arg("--format")
        .arg("json")
        .env("APIMAN_MASTER_PASSWORD", master_password)
        .output()
        .unwrap();
    assert!(list_json.status.success());
    let json_val: serde_json::Value = serde_json::from_slice(&list_json.stdout).unwrap();
    assert_eq!(json_val.as_array().unwrap().len(), 2);

    // 9. Run command with injected environment variables
    let run_cmd = Command::new(binary)
        .arg("--vault")
        .arg(&vault_file)
        .arg("run")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("echo $OPENAI_KEY")
        .env("APIMAN_MASTER_PASSWORD", master_password)
        .output()
        .unwrap();
    assert!(run_cmd.status.success());
    assert_eq!(
        String::from_utf8_lossy(&run_cmd.stdout).trim(),
        "sk-openai-live-secret"
    );

    // 10. Run with project scope
    let run_proj = Command::new(binary)
        .arg("--vault")
        .arg(&vault_file)
        .arg("run")
        .arg("--project")
        .arg("backend")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("echo $DATABASE_URL")
        .env("APIMAN_MASTER_PASSWORD", master_password)
        .output()
        .unwrap();
    assert!(run_proj.status.success());
    assert_eq!(
        String::from_utf8_lossy(&run_proj.stdout).trim(),
        "postgres://user:pass@db:5432/main"
    );

    // 11. Run non-existent command: must fail with user-friendly error
    let run_bad = Command::new(binary)
        .arg("--vault")
        .arg(&vault_file)
        .arg("run")
        .arg("--")
        .arg("NonExistentProgramXYZ")
        .env("APIMAN_MASTER_PASSWORD", master_password)
        .output()
        .unwrap();
    assert!(!run_bad.status.success());
    let bad_err = String::from_utf8_lossy(&run_bad.stderr);
    assert!(bad_err.contains("Command 'NonExistentProgramXYZ' was not found"));
    assert!(bad_err.contains("apiman get"));

    // 12. Change master password via `passwd`
    let new_password = "brand-new-master-password-999";
    let mut passwd_child = Command::new(binary)
        .arg("--vault")
        .arg(&vault_file)
        .arg("passwd")
        .env("APIMAN_MASTER_PASSWORD", master_password)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

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

    // 13. Verify vault works with new password and fails with old password
    let get_with_new_pw = Command::new(binary)
        .arg("--vault")
        .arg(&vault_file)
        .arg("get")
        .arg("OPENAI_KEY")
        .arg("--allow-view")
        .env("APIMAN_MASTER_PASSWORD", new_password)
        .output()
        .unwrap();
    assert!(get_with_new_pw.status.success());
    assert_eq!(
        String::from_utf8_lossy(&get_with_new_pw.stdout).trim(),
        "sk-openai-live-secret"
    );

    let get_with_old_pw = Command::new(binary)
        .arg("--vault")
        .arg(&vault_file)
        .arg("get")
        .arg("OPENAI_KEY")
        .arg("--allow-view")
        .env("APIMAN_MASTER_PASSWORD", master_password)
        .output()
        .unwrap();
    assert!(!get_with_old_pw.status.success()); // Old password must fail!

    // 14. Delete secret
    let del_res = Command::new(binary)
        .arg("--vault")
        .arg(&vault_file)
        .arg("delete")
        .arg("OPENAI_KEY")
        .env("APIMAN_MASTER_PASSWORD", new_password)
        .output()
        .unwrap();
    assert!(del_res.status.success());

    let get_after_del = Command::new(binary)
        .arg("--vault")
        .arg(&vault_file)
        .arg("get")
        .arg("OPENAI_KEY")
        .arg("--allow-view")
        .env("APIMAN_MASTER_PASSWORD", new_password)
        .output()
        .unwrap();
    assert!(!get_after_del.status.success());

    // 15. Status command check
    let status_res = Command::new(binary)
        .arg("--vault")
        .arg(&vault_file)
        .arg("status")
        .output()
        .unwrap();
    assert!(status_res.status.success());
    let status_str = String::from_utf8_lossy(&status_res.stdout);
    assert!(status_str.contains("Vault Path:"));
    assert!(status_str.contains("Installed:"));
}
