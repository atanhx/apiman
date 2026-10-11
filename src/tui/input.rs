use crate::tui::app::{
    ActiveModal, App, FORM_VALUE_FIELD, PathFormState, TextField, complete_path,
};
use crate::tui::keymap::{Action, Context};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

const PAGE: isize = 10;

pub fn handle_key(app: &mut App, key: KeyEvent) {
    if key.kind == KeyEventKind::Release {
        return;
    }
    app.note_activity();

    // Ctrl+C quits from anywhere, including inside modals and text fields.
    if key.code == KeyCode::Char('c')
        && key.modifiers.contains(KeyModifiers::CONTROL)
        && !key.modifiers.contains(KeyModifiers::ALT)
    {
        app.should_quit = true;
        return;
    }
    match &app.active_modal {
        ActiveModal::KeybindingsHelp => handle_help_key(app, key),
        ActiveModal::DeleteConfirm(_) => handle_delete_key(app, key),
        ActiveModal::Search => handle_search_key(app, key),
        ActiveModal::Add | ActiveModal::Edit(_) => handle_form_key(app, key),
        ActiveModal::BulkEdit => handle_bulk_key(app, key),
        ActiveModal::Import | ActiveModal::Export => handle_path_form_key(app, key),
        ActiveModal::None => handle_normal_key(app, key),
    }
}

/// Bracketed paste: the whole clipboard arrives at once, so a trailing
/// newline cannot submit a form and multi-line secrets stay intact.
pub fn handle_paste(app: &mut App, text: &str) {
    app.note_activity();
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    let single_line: String = normalized
        .trim_end_matches('\n')
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    match &app.active_modal {
        ActiveModal::Search => {
            app.search_query.insert_str(&single_line);
            app.update_filtered_indices();
        }
        ActiveModal::Add | ActiveModal::Edit(_) => {
            if app.form_state.active_field == FORM_VALUE_FIELD {
                let value: String = normalized
                    .trim_end_matches('\n')
                    .chars()
                    .filter(|c| *c == '\n' || !c.is_control())
                    .collect();
                app.form_state.value.insert_str(&value);
            } else {
                app.form_state.active_field_mut().insert_str(&single_line);
            }
        }
        ActiveModal::BulkEdit => app.bulk_form.active_field_mut().insert_str(&single_line),
        ActiveModal::Import | ActiveModal::Export
            if !(app.active_modal == ActiveModal::Export && app.path_form.active_field == 1) =>
        {
            app.path_form.active_field_mut().insert_str(&single_line);
        }
        _ => {}
    }
}

fn open_search(app: &mut App) {
    app.search_query.move_end();
    app.active_modal = ActiveModal::Search;
}

pub fn run_action(app: &mut App, action: Action) {
    match action {
        Action::Up => app.move_selection(-1),
        Action::Down => app.move_selection(1),
        Action::PageUp => app.move_selection(-PAGE),
        Action::PageDown => app.move_selection(PAGE),
        Action::Top => app.jump_to(0),
        Action::Bottom => app.jump_to(usize::MAX),
        Action::ScopeNext => app.cycle_project_filter_by(1),
        Action::ScopePrev => app.cycle_project_filter_by(-1),
        Action::Search => open_search(app),
        Action::ExtendUp => app.extend_selection(-1),
        Action::ExtendDown => app.extend_selection(1),
        Action::TogglePin => app.toggle_pin(),
        Action::Clear => {
            if app.in_group_mode() {
                app.clear_selection();
            } else if !app.search_query.is_empty() {
                app.search_query = TextField::default();
                app.update_filtered_indices();
            } else if app.project_filter.is_some() {
                app.project_filter = None;
                app.update_filtered_indices();
            }
        }
        Action::Copy => app.copy_selected_secret(),
        Action::Reveal => {
            if app.in_group_mode() {
                app.toggle_reveal_marked();
            } else {
                app.toggle_selected_reveal();
            }
        }
        Action::RevealAll => app.toggle_reveal_all(),
        Action::Add => app.open_add(),
        Action::Edit => app.open_edit(),
        Action::Delete => app.open_delete(),
        Action::Import => {
            app.path_form = PathFormState::default();
            app.active_modal = ActiveModal::Import;
        }
        Action::Export => {
            app.path_form = PathFormState::default();
            app.active_modal = ActiveModal::Export;
        }
        Action::Help => {
            app.help_scroll = 0;
            app.active_modal = ActiveModal::KeybindingsHelp;
        }
        Action::Lock => app.lock_and_quit(),
        Action::Quit => app.should_quit = true,
        Action::FormSave | Action::FormToggleMask => {}
    }
}

fn handle_normal_key(app: &mut App, key: KeyEvent) {
    // Unbound combinations do nothing, so e.g. Ctrl+D never deletes and
    // Ctrl+E never opens the editor.
    if let Some(action) = app.keymap.action(Context::Normal, &key) {
        run_action(app, action);
    }
}

fn handle_help_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => app.help_scroll = app.help_scroll.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => app.help_scroll = app.help_scroll.saturating_add(1),
        KeyCode::PageUp => app.help_scroll = app.help_scroll.saturating_sub(10),
        KeyCode::PageDown | KeyCode::Char(' ') => {
            app.help_scroll = app.help_scroll.saturating_add(10)
        }
        KeyCode::Home | KeyCode::Char('g') => app.help_scroll = 0,
        _ => app.active_modal = ActiveModal::None,
    }
}

fn has_ctrl_or_alt(key: &KeyEvent) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL) || key.modifiers.contains(KeyModifiers::ALT)
}

fn handle_delete_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') if !has_ctrl_or_alt(&key) => {
            app.delete_choice_delete = true;
            if let Err(e) = app.delete_selected_entry() {
                app.set_error(format!("Delete failed: {e}"));
            }
        }
        KeyCode::Esc | KeyCode::Char('q') => app.active_modal = ActiveModal::None,
        KeyCode::Char('n') | KeyCode::Char('N') if !has_ctrl_or_alt(&key) => {
            app.active_modal = ActiveModal::None;
        }
        KeyCode::Left
        | KeyCode::Right
        | KeyCode::Tab
        | KeyCode::BackTab
        | KeyCode::Char('h')
        | KeyCode::Char('l') => {
            app.delete_choice_delete = !app.delete_choice_delete;
        }
        KeyCode::Enter => {
            if let Err(e) = app.confirm_delete_choice() {
                app.set_error(format!("Delete failed: {e}"));
            }
        }
        _ => {}
    }
}

/// Shared single-line editing keys. Returns true when the key was consumed.
fn edit_text(field: &mut TextField, key: &KeyEvent) -> bool {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    match key.code {
        KeyCode::Left => field.move_left(),
        KeyCode::Right => field.move_right(),
        KeyCode::Home => field.move_home(),
        KeyCode::End => field.move_end(),
        KeyCode::Backspace if ctrl || key.modifiers.contains(KeyModifiers::ALT) => {
            field.delete_word_back()
        }
        KeyCode::Backspace => field.backspace(),
        KeyCode::Delete => field.delete_at_cursor(),
        KeyCode::Char('a') if ctrl => field.move_home(),
        KeyCode::Char('e') if ctrl => field.move_end(),
        KeyCode::Char('w') if ctrl => field.delete_word_back(),
        KeyCode::Char('u') if ctrl => field.clear(),
        KeyCode::Char(_) if has_ctrl_or_alt(key) => return false,
        KeyCode::Char(c) => field.insert_char(c),
        _ => return false,
    }
    true
}

fn handle_search_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.search_query = TextField::default();
            app.update_filtered_indices();
            app.active_modal = ActiveModal::None;
        }
        KeyCode::Enter => app.active_modal = ActiveModal::None,
        KeyCode::Up => app.move_selection(-1),
        KeyCode::Down => app.move_selection(1),
        KeyCode::PageUp => app.move_selection(-PAGE),
        KeyCode::PageDown => app.move_selection(PAGE),
        _ => {
            let before = app.search_query.text.clone();
            if edit_text(&mut app.search_query, &key) && app.search_query.text != before {
                app.update_filtered_indices();
            }
        }
    }
}

fn handle_form_key(app: &mut App, key: KeyEvent) {
    match app.keymap.action(Context::Form, &key) {
        Some(Action::FormSave) => {
            if let Err(e) = app.save_form() {
                app.set_error(e);
            }
            return;
        }
        Some(Action::FormToggleMask) => {
            app.form_state.show_secret = !app.form_state.show_secret;
            return;
        }
        _ => {}
    }

    match key.code {
        KeyCode::Esc => app.close_form(),
        KeyCode::Tab | KeyCode::Down => app.form_state.next_field(),
        KeyCode::BackTab | KeyCode::Up => app.form_state.prev_field(),
        KeyCode::Enter => {
            if app.form_state.active_field == crate::tui::app::FORM_FIELDS - 1 {
                if let Err(e) = app.save_form() {
                    app.set_error(e);
                }
            } else {
                app.form_state.next_field();
            }
        }
        _ => {
            edit_text(app.form_state.active_field_mut(), &key);
        }
    }
}

fn handle_bulk_key(app: &mut App, key: KeyEvent) {
    if app.keymap.action(Context::Form, &key) == Some(Action::FormSave) {
        if let Err(e) = app.apply_bulk_edit() {
            app.set_error(e);
        }
        return;
    }

    match key.code {
        KeyCode::Esc => app.active_modal = ActiveModal::None,
        KeyCode::Tab | KeyCode::Down => app.bulk_form.next_field(),
        KeyCode::BackTab | KeyCode::Up => app.bulk_form.prev_field(),
        KeyCode::Enter => {
            if app.bulk_form.active_field == 1 {
                if let Err(e) = app.apply_bulk_edit() {
                    app.set_error(e);
                }
            } else {
                app.bulk_form.next_field();
            }
        }
        _ => {
            edit_text(app.bulk_form.active_field_mut(), &key);
        }
    }
}

fn handle_path_form_key(app: &mut App, key: KeyEvent) {
    let is_export = app.active_modal == ActiveModal::Export;
    let on_format_row = is_export && app.path_form.active_field == 1;
    let max_fields = 2;

    let submit = |app: &mut App| {
        let res = if is_export {
            app.run_export()
        } else {
            app.run_import()
        };
        if let Err(e) = res {
            app.set_error(e);
        }
    };

    if app.keymap.action(Context::Form, &key) == Some(Action::FormSave) {
        submit(app);
        return;
    }

    match key.code {
        KeyCode::Esc => app.active_modal = ActiveModal::None,
        KeyCode::Tab if app.path_form.active_field == 0 => {
            let (completed, msg) = complete_path(&app.path_form.path.text);
            app.path_form.path.set(completed);
            app.set_status(msg);
        }
        KeyCode::Tab | KeyCode::Down => app.path_form.next_field(max_fields),
        KeyCode::BackTab | KeyCode::Up => app.path_form.prev_field(max_fields),
        KeyCode::Left | KeyCode::Right | KeyCode::Char(' ') if on_format_row => {
            app.path_form.export_example = !app.path_form.export_example;
        }
        KeyCode::Enter if app.path_form.active_field == 1 => submit(app),
        KeyCode::Enter => app.path_form.next_field(max_fields),
        _ if on_format_row => {}
        _ => {
            edit_text(app.path_form.active_field_mut(), &key);
        }
    }
}
