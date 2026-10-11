use apiman::cli::SessionContext;
use apiman::config::Config;
use apiman::security::SecretString;
use apiman::storage::init_vault;
use apiman::tui::app::{ActiveModal, App};
use tempfile::tempdir;
use zeroize::Zeroizing;

#[test]
fn test_tui_app_state_and_filtering() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("tui_vault.enc");
    let socket_path = dir.path().join("tui_daemon.sock");

    let (mut vault, key, salt) = init_vault("password123", &vault_path).unwrap();

    vault.set(
        "OPENAI_API_KEY".to_string(),
        SecretString::new("sk-openai-111"),
        None,
        vec!["ai".to_string(), "prod".to_string()],
        Some("OpenAI key".to_string()),
    );
    vault.set(
        "STRIPE_KEY".to_string(),
        SecretString::new("sk-stripe-222"),
        Some("billing".to_string()),
        vec!["payment".to_string()],
        None,
    );

    let ctx = SessionContext {
        config: Config::default(),
        vault_path,
        socket_path,
        master_key: Zeroizing::new(*key),
        salt,
        vault,
    };

    let mut app = App::new(ctx);
    assert_eq!(app.filtered_indices.len(), 2);

    // Test search filter
    app.search_query = "stripe".to_string();
    app.update_filtered_indices();
    assert_eq!(app.filtered_indices.len(), 1);
    assert_eq!(app.selected_entry().unwrap().name, "STRIPE_KEY");

    // Clear search filter
    app.search_query.clear();
    app.update_filtered_indices();
    assert_eq!(app.filtered_indices.len(), 2);

    // Test tag search
    app.search_query = "payment".to_string();
    app.update_filtered_indices();
    assert_eq!(app.filtered_indices.len(), 1);
    assert_eq!(app.selected_entry().unwrap().name, "STRIPE_KEY");

    // Test toggle reveal
    let entry_id = app.selected_entry().unwrap().id.clone();
    assert!(!app.revealed_entries.contains(&entry_id));
    app.toggle_selected_reveal();
    assert!(app.revealed_entries.contains(&entry_id));
    app.toggle_selected_reveal();
    assert!(!app.revealed_entries.contains(&entry_id));

    // Test Add modal save
    app.search_query.clear();
    app.active_modal = ActiveModal::Add;
    app.form_state.name = "GITHUB_TOKEN".to_string();
    app.form_state.value = "ghp_secret".to_string();
    app.form_state.tags = "git, dev".to_string();
    assert!(app.save_form().is_ok());

    assert_eq!(app.ctx.vault.entries.len(), 3);
    assert!(app.ctx.vault.get("GITHUB_TOKEN", None).is_some());
}
