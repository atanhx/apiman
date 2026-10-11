use apiman::security::SecretString;
use apiman::storage::{init_vault, load_vault_with_password};
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_cli_full_flow() {
    let dir = tempdir().unwrap();
    let vault_file = dir.path().join("test_vault.enc");
    let binary = env!("CARGO_BIN_EXE_apiman");

    // Initialize vault programmatically
    let master_password = "test-master-password-123";
    let (mut vault, key, salt) = init_vault(master_password, &vault_file).unwrap();

    vault.set(
        "TEST_API_KEY".to_string(),
        SecretString::new("sk-test-value-42"),
        None,
        vec!["test".to_string()],
        Some("A test key".to_string()),
    );
    vault.set(
        "PROJ_KEY".to_string(),
        SecretString::new("sk-proj-value-99"),
        Some("myapp".to_string()),
        vec!["production".to_string()],
        None,
    );
    apiman::storage::save_vault(&vault, &key, &salt, &vault_file).unwrap();

    // 1. List secrets
    let list_out = Command::new(binary)
        .arg("--vault")
        .arg(&vault_file)
        .arg("list")
        .env("APIMAN_MASTER_PASSWORD", master_password)
        .output()
        .unwrap();

    assert!(list_out.status.success());
    let list_str = String::from_utf8_lossy(&list_out.stdout);
    assert!(list_str.contains("TEST_API_KEY"));
    assert!(list_str.contains("PROJ_KEY"));
    // Values must NEVER appear in list output
    assert!(!list_str.contains("sk-test-value-42"));
    assert!(!list_str.contains("sk-proj-value-99"));

    // 2. Get with allow-view
    let get_view_out = Command::new(binary)
        .arg("--vault")
        .arg(&vault_file)
        .arg("get")
        .arg("TEST_API_KEY")
        .arg("--allow-view")
        .env("APIMAN_MASTER_PASSWORD", master_password)
        .output()
        .unwrap();

    assert!(get_view_out.status.success());
    let get_str = String::from_utf8_lossy(&get_view_out.stdout);
    assert!(get_str.contains("sk-test-value-42"));

    // 3. Run command with env injection
    let run_out = Command::new(binary)
        .arg("--vault")
        .arg(&vault_file)
        .arg("run")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("echo $TEST_API_KEY")
        .env("APIMAN_MASTER_PASSWORD", master_password)
        .output()
        .unwrap();

    assert!(run_out.status.success());
    let run_str = String::from_utf8_lossy(&run_out.stdout);
    assert_eq!(run_str.trim(), "sk-test-value-42");

    // 4. Run command with project-specific env injection
    let run_proj_out = Command::new(binary)
        .arg("--vault")
        .arg(&vault_file)
        .arg("run")
        .arg("--project")
        .arg("myapp")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("echo $PROJ_KEY:$TEST_API_KEY")
        .env("APIMAN_MASTER_PASSWORD", master_password)
        .output()
        .unwrap();

    assert!(run_proj_out.status.success());
    let run_proj_str = String::from_utf8_lossy(&run_proj_out.stdout);
    assert_eq!(run_proj_str.trim(), "sk-proj-value-99:sk-test-value-42");

    // 5. Delete entry
    let del_out = Command::new(binary)
        .arg("--vault")
        .arg(&vault_file)
        .arg("delete")
        .arg("PROJ_KEY")
        .arg("--project")
        .arg("myapp")
        .env("APIMAN_MASTER_PASSWORD", master_password)
        .output()
        .unwrap();

    assert!(del_out.status.success());

    // Verify deletion
    let (reloaded_vault, _, _) = load_vault_with_password(master_password, &vault_file).unwrap();
    assert!(reloaded_vault.get("PROJ_KEY", Some("myapp")).is_none());
}
