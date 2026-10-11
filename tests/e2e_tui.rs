mod common;

use apiman::config::{Config, KeyList};
use apiman::tui::app::ActiveModal;
use apiman::tui::input::handle_paste;
use common::*;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use std::time::{Duration, Instant};

fn many(n: usize) -> Vec<(String, String)> {
    (0..n)
        .map(|i| (format!("KEY_{i:03}"), format!("value-{i:03}")))
        .collect()
}

#[test]
fn table_scrolls_to_keep_the_selection_visible() {
    let sb = Sandbox::new();
    let data = many(60);
    let entries: Vec<(&str, &str, Option<&str>)> = data
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str(), None))
        .collect();
    let mut app = sb.tui(&entries);

    let screen = render(&app, 100, 24);
    assert!(screen.contains("> KEY_000"));
    assert!(!screen.contains("KEY_059"));

    press(&mut app, key(KeyCode::End));
    let screen = render(&app, 100, 24);
    assert!(screen.contains("> KEY_059"), "{screen}");
    assert!(screen.contains("60/60"));

    // Moving up keeps the viewport steady instead of re-centering every step
    press(&mut app, key(KeyCode::Up));
    let screen = render(&app, 100, 24);
    assert!(screen.contains("> KEY_058") && screen.contains("KEY_059"));

    press(&mut app, key(KeyCode::Home));
    assert!(render(&app, 100, 24).contains("> KEY_000"));
    press(&mut app, key(KeyCode::PageDown));
    assert_eq!(app.selected_index, 10);
    assert!(render(&app, 100, 24).contains("> KEY_010"));
}

#[test]
fn empty_states_tell_the_user_what_to_do() {
    let sb = Sandbox::new();
    let mut app = sb.tui(&[]);
    let screen = render(&app, 100, 24);
    assert!(screen.contains("No secrets yet"));
    assert!(screen.contains("Press a to add one"));

    let sb2 = Sandbox::new();
    app = sb2.tui(&[("ONLY", "v-1", None)]);
    press(&mut app, key(KeyCode::Char('/')));
    type_text(&mut app, "zzz");
    let screen = render(&app, 100, 24);
    assert!(screen.contains("Nothing matches"));
    assert!(screen.contains(" search "));
}

#[test]
fn values_are_masked_until_revealed_and_never_rendered_otherwise() {
    let sb = Sandbox::new();
    let mut app = sb.tui(&[
        ("SHOWME", "visible-after-reveal", None),
        ("MULTI", "line1\nline2", None),
    ]);
    let screen = render(&app, 120, 30);
    assert!(!screen.contains("visible-after-reveal"));
    assert!(screen.contains("**********"));

    press(&mut app, key(KeyCode::Char(' ')));
    assert!(render(&app, 120, 30).contains("visible-after-reveal"));
    press(&mut app, key(KeyCode::Char('V')));
    assert!(render(&app, 120, 30).contains("line1\\nline2"));
}

#[test]
fn feedback_is_visible_even_in_group_mode() {
    let sb = Sandbox::new();
    let mut app = sb.tui(&[("A1", "v-a1", None), ("A2", "v-a2", None)]);
    press(&mut app, shift(KeyCode::Down));
    assert!(app.in_group_mode());
    assert!(render(&app, 120, 30).contains("2 selected"));

    // Submitting an empty bulk edit must show why nothing happened
    press(&mut app, key(KeyCode::Char('e')));
    press(&mut app, ctrl('s'));
    assert_eq!(app.active_modal, ActiveModal::BulkEdit);
    assert!(render(&app, 120, 30).contains("Nothing to change"));
}

#[test]
fn delete_dialog_defaults_to_cancel() {
    let sb = Sandbox::new();
    let mut app = sb.tui(&[("KEEP", "keep-value", None)]);

    press(&mut app, key(KeyCode::Char('d')));
    assert!(render(&app, 100, 30).contains("Delete secret"));
    press(&mut app, key(KeyCode::Enter));
    assert_eq!(app.ctx.vault.entries.len(), 1);

    press(&mut app, key(KeyCode::Char('d')));
    press(&mut app, key(KeyCode::Right));
    press(&mut app, key(KeyCode::Enter));
    assert!(app.ctx.vault.entries.is_empty());
    assert!(render(&app, 100, 24).contains("Deleted 'KEEP'"));
}

#[test]
fn add_and_edit_refuse_duplicates_and_empty_values() {
    let sb = Sandbox::new();
    let mut app = sb.tui(&[
        ("TAKEN", "taken-value", None),
        ("OTHER", "other-value", None),
    ]);

    press(&mut app, key(KeyCode::Char('a')));
    type_text(&mut app, "TAKEN");
    press(&mut app, ctrl('s'));
    assert!(app.status_text().unwrap().contains("cannot be empty"));
    press(&mut app, key(KeyCode::Tab));
    press(&mut app, key(KeyCode::Tab));
    type_text(&mut app, "new-value");
    press(&mut app, ctrl('s'));
    assert!(
        app.status_text().unwrap().contains("already exists"),
        "{:?}",
        app.status_text()
    );
    assert_eq!(app.active_modal, ActiveModal::Add);
    assert_eq!(
        app.ctx
            .vault
            .get("TAKEN", None)
            .unwrap()
            .value
            .expose_secret(),
        "taken-value"
    );

    // Same name in another project is fine and the new row gets the cursor
    press(&mut app, key(KeyCode::Up));
    type_text(&mut app, "teamx");
    press(&mut app, ctrl('s'));
    assert_eq!(app.active_modal, ActiveModal::None);
    assert_eq!(
        app.selected_entry().unwrap().project.as_deref(),
        Some("teamx")
    );
    assert!(
        app.form_state.value.text.is_empty(),
        "form buffer must be wiped"
    );

    // Renaming OTHER to TAKEN in the same scope is refused
    let other_pos = app
        .filtered_indices
        .iter()
        .position(|&i| app.ctx.vault.entries[i].name == "OTHER")
        .unwrap();
    app.jump_to(other_pos);
    press(&mut app, key(KeyCode::Char('e')));
    press(&mut app, ctrl('u'));
    type_text(&mut app, "TAKEN");
    press(&mut app, ctrl('s'));
    assert!(app.status_text().unwrap().contains("already exists"));
    press(&mut app, key(KeyCode::Esc));
    assert!(app.ctx.vault.get("OTHER", None).is_some());
}

#[test]
fn bulk_move_refuses_to_create_duplicates() {
    let sb = Sandbox::new();
    let mut app = sb.tui(&[
        ("SAME", "global-one", None),
        ("SAME", "proj-one", Some("proj")),
        ("FREE", "free", None),
    ]);
    press(&mut app, key(KeyCode::Tab));
    press(&mut app, key(KeyCode::Tab));
    press(&mut app, key(KeyCode::Char('e')));
    type_text(&mut app, "proj");
    press(&mut app, ctrl('s'));
    assert!(
        app.status_text().unwrap().contains("duplicates"),
        "{:?}",
        app.status_text()
    );
    assert!(app.ctx.vault.find_exact("SAME", None).is_some());
}

#[test]
fn paste_keeps_multiline_secrets_and_never_submits() {
    let sb = Sandbox::new();
    let mut app = sb.tui(&[]);
    press(&mut app, key(KeyCode::Char('a')));
    handle_paste(&mut app, "PASTED_KEY\n");
    assert_eq!(app.form_state.name.text, "PASTED_KEY");
    assert_eq!(app.active_modal, ActiveModal::Add);
    press(&mut app, key(KeyCode::Tab));
    press(&mut app, key(KeyCode::Tab));
    handle_paste(&mut app, "-----BEGIN-----\r\nabc\r\n-----END-----\r\n");
    press(&mut app, ctrl('s'));
    assert_eq!(app.active_modal, ActiveModal::None);
    let (vault, _, _) = apiman::storage::load_vault_with_password(&sb.password, &sb.vault).unwrap();
    assert_eq!(
        vault.get("PASTED_KEY", None).unwrap().value.expose_secret(),
        "-----BEGIN-----\nabc\n-----END-----"
    );
}

#[test]
fn long_values_scroll_inside_form_fields() {
    let sb = Sandbox::new();
    let mut app = sb.tui(&[]);
    press(&mut app, key(KeyCode::Char('a')));
    press(&mut app, key(KeyCode::Tab));
    press(&mut app, key(KeyCode::Tab));
    let long: String = (0..200)
        .map(|i| char::from(b'a' + (i % 26) as u8))
        .collect();
    type_text(&mut app, &long);
    press(&mut app, ctrl('v'));
    let screen = render(&app, 100, 30);
    let tail = &long[long.len() - 20..];
    assert!(
        screen.contains(tail),
        "cursor end of a long value must stay visible:\n{screen}"
    );
    assert!(screen.contains('<'));

    // Word and line deletion shortcuts
    press(&mut app, key(KeyCode::Tab));
    type_text(&mut app, "alpha beta");
    press(&mut app, ctrl('w'));
    assert_eq!(app.form_state.tags.text, "alpha ");
    press(&mut app, ctrl('u'));
    assert!(app.form_state.tags.text.is_empty());
}

#[test]
fn inactivity_locks_the_tui() {
    let sb = Sandbox::new();
    let cfg = Config {
        auto_lock_timeout_seconds: 1,
        ..Default::default()
    };
    let mut app = sb.tui_with_config(&[("K", "v-k", None)], cfg);
    app.tick();
    assert!(!app.should_quit);
    app.last_activity = Instant::now() - Duration::from_secs(2);
    app.tick();
    assert!(app.should_quit);
    assert!(app.exit_message.as_deref().unwrap().contains("inactivity"));

    let sb2 = Sandbox::new();
    let cfg = Config {
        auto_lock_timeout_seconds: 0,
        ..Default::default()
    };
    let mut app = sb2.tui_with_config(&[("K", "v-k", None)], cfg);
    app.last_activity = Instant::now() - Duration::from_secs(100_000);
    app.tick();
    assert!(!app.should_quit);
    assert!(render(&app, 100, 24).contains("auto-lock off"));
}

#[test]
fn scope_cycles_both_ways_and_esc_resets_it() {
    let sb = Sandbox::new();
    let mut app = sb.tui(&[
        ("G", "v-g", None),
        ("A", "v-a", Some("alpha")),
        ("B", "v-b", Some("beta")),
    ]);
    let scope =
        |app: &apiman::tui::app::App| app.project_filter.clone().unwrap_or_else(|| "all".into());

    press(&mut app, key(KeyCode::Right));
    assert_eq!(scope(&app), "global");
    press(&mut app, key(KeyCode::Right));
    assert_eq!(scope(&app), "alpha");
    assert_eq!(app.filtered_indices.len(), 1);
    press(&mut app, key(KeyCode::Left));
    assert_eq!(scope(&app), "global");
    press(&mut app, key(KeyCode::Char('h')));
    assert_eq!(scope(&app), "all");
    press(&mut app, key(KeyCode::Char('h')));
    assert_eq!(scope(&app), "beta");
    press(&mut app, key(KeyCode::Esc));
    assert_eq!(scope(&app), "all");

    // New entries default to the scope being viewed
    press(&mut app, key(KeyCode::Char('l')));
    press(&mut app, key(KeyCode::Char('l')));
    press(&mut app, key(KeyCode::Char('a')));
    assert_eq!(app.form_state.project.text, "alpha");
}

#[test]
fn custom_keybindings_drive_the_tui_and_problems_are_shown() {
    let sb = Sandbox::new();
    let mut cfg = Config::default();
    cfg.keybindings
        .insert("add".into(), KeyList::One("n".into()));
    cfg.keybindings.insert(
        "reveal".into(),
        KeyList::Many(vec!["r".into(), "ctrl+o".into()]),
    );
    let mut app = sb.tui_with_config(&[("K", "custom-reveal-value", None)], cfg);

    press(&mut app, key(KeyCode::Char('a')));
    assert_eq!(
        app.active_modal,
        ActiveModal::None,
        "default 'a' must be replaced"
    );
    press(&mut app, key(KeyCode::Char('n')));
    assert_eq!(app.active_modal, ActiveModal::Add);
    press(&mut app, key(KeyCode::Esc));
    press(
        &mut app,
        KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL),
    );
    assert_eq!(app.revealed_entries.len(), 1);
    press(&mut app, key(KeyCode::Char('r')));
    assert!(app.revealed_entries.is_empty());

    // Help and footer are generated from the live keymap
    let screen = render(&app, 120, 40);
    assert!(screen.contains(" n add"), "{screen}");
    press(&mut app, key(KeyCode::Char('?')));
    let screen = render(&app, 120, 60);
    assert!(screen.contains("Keybindings"));
    assert!(screen.contains("r / Ctrl+O"), "{screen}");
    press(&mut app, key(KeyCode::Down));
    assert_eq!(app.help_scroll, 1);
    press(&mut app, key(KeyCode::Char('x')));
    assert_eq!(app.active_modal, ActiveModal::None);

    // Conflicts and typos are reported on start instead of failing silently
    let sb2 = Sandbox::new();
    let mut cfg = Config::default();
    cfg.keybindings
        .insert("reveal".into(), KeyList::One("d".into()));
    cfg.keybindings
        .insert("bogus".into(), KeyList::One("z".into()));
    cfg.theme = "neon".into();
    let app = sb2.tui_with_config(&[("K", "v-k", None)], cfg);
    let msg = app.status_text().unwrap().to_string();
    assert!(msg.contains("bogus") && msg.contains("neon"), "{msg}");
    assert!(render(&app, 160, 24).contains("config.json"));
}

#[test]
fn search_keeps_the_query_and_navigation_works_inside_it() {
    let sb = Sandbox::new();
    let mut app = sb.tui(&[
        ("ALPHA_ONE", "v-1", None),
        ("ALPHA_TWO", "v-2", None),
        ("BETA", "v-3", None),
    ]);
    press(&mut app, key(KeyCode::Char('/')));
    type_text(&mut app, "alpha");
    assert_eq!(app.filtered_indices.len(), 2);
    press(&mut app, key(KeyCode::Down));
    assert_eq!(app.active_modal, ActiveModal::Search);
    assert_eq!(app.selected_index, 1);
    press(&mut app, key(KeyCode::Enter));
    assert_eq!(app.active_modal, ActiveModal::None);
    assert!(render(&app, 100, 24).contains("filter \"alpha\""));

    press(&mut app, key(KeyCode::Char('/')));
    assert_eq!(app.search_query.text, "alpha");
    press(&mut app, key(KeyCode::Esc));
    assert!(app.search_query.text.is_empty());
    assert_eq!(app.filtered_indices.len(), 3);
}

#[test]
fn key_release_events_are_ignored() {
    let sb = Sandbox::new();
    let mut app = sb.tui(&[("K", "v-k", None)]);
    let mut release = key(KeyCode::Char('a'));
    release.kind = KeyEventKind::Release;
    press(&mut app, release);
    assert_eq!(app.active_modal, ActiveModal::None);
}

#[test]
fn tui_never_clobbers_changes_from_other_processes() {
    let sb = Sandbox::new();
    let mut app = sb.tui(&[("EXISTING", "existing-value", None)]);

    // Another process (the CLI) adds a secret while the TUI is open
    sb.ok(&["set", "FROM_CLI", "cli-value"]);

    // Editing in the TUI must keep the CLI's entry
    press(&mut app, key(KeyCode::Char('e')));
    press(&mut app, key(KeyCode::Tab));
    press(&mut app, key(KeyCode::Tab));
    press(&mut app, ctrl('u'));
    type_text(&mut app, "edited-in-tui");
    press(&mut app, ctrl('s'));
    assert_eq!(
        app.active_modal,
        ActiveModal::None,
        "{:?}",
        app.status_text()
    );
    assert_eq!(sb.ok(&["get", "FROM_CLI"]), "cli-value");
    assert_eq!(sb.ok(&["get", "EXISTING"]), "edited-in-tui");
    assert!(app.ctx.vault.get("FROM_CLI", None).is_some());

    // External deletes show up without a restart
    sb.ok(&["delete", "FROM_CLI"]);
    std::thread::sleep(Duration::from_millis(1100));
    app.tick();
    assert!(app.ctx.vault.get("FROM_CLI", None).is_none());

    // After a password change elsewhere, the stale session refuses to write
    let mut passwd = sb.cmd();
    passwd.arg("passwd");
    let out = sb.run_stdin(passwd, "another-strong-pass\nanother-strong-pass\n");
    assert!(out.status.success());
    press(&mut app, key(KeyCode::Char('a')));
    type_text(&mut app, "LATE");
    press(&mut app, key(KeyCode::Tab));
    press(&mut app, key(KeyCode::Tab));
    type_text(&mut app, "late-value");
    press(&mut app, ctrl('s'));
    assert!(
        app.status_text().unwrap().contains("password changed"),
        "{:?}",
        app.status_text()
    );
    let (vault, _, _) =
        apiman::storage::load_vault_with_password("another-strong-pass", &sb.vault).unwrap();
    assert!(vault.get("LATE", None).is_none());
    assert_eq!(
        vault.get("EXISTING", None).unwrap().value.expose_secret(),
        "edited-in-tui"
    );
}

#[test]
fn export_from_tui_expands_home_and_warns_on_duplicate_keys() {
    let sb = Sandbox::new();
    let mut app = sb.tui(&[
        ("DUP", "global-dup", None),
        ("DUP", "proj-dup", Some("p")),
        ("UNIQUE", "u-1", None),
    ]);
    let target = sb.path("tui-export");
    std::fs::create_dir_all(&target).unwrap();
    press(&mut app, key(KeyCode::Char('X')));
    handle_paste(&mut app, &format!("{}/", target.display()));
    press(&mut app, key(KeyCode::Enter));
    press(&mut app, key(KeyCode::Enter));
    let file = target.join("apiman-export.env");
    assert_eq!(file_mode(&file), 0o600);
    assert!(
        std::fs::read_to_string(&file)
            .unwrap()
            .contains("UNIQUE=u-1")
    );
    assert!(
        app.status_text().unwrap().contains("duplicate keys"),
        "{:?}",
        app.status_text()
    );
}
