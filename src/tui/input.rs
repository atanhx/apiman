use crate::daemon::lock_daemon;
use crate::tui::app::{complete_path, ActiveModal, App, PathFormState, TextField};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

pub fn handle_key(app: &mut App, key: KeyEvent) {
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

fn handle_normal_key(app: &mut App, key: KeyEvent) {
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        match key.code {
            KeyCode::Char('k') => {
                app.active_modal = ActiveModal::KeybindingsHelp;
                return;
            }
            KeyCode::Char('f') => {
                app.search_query = TextField::default();
                app.active_modal = ActiveModal::Search;
                return;
            }
            KeyCode::Char('c') => {
                app.should_quit = true;
                return;
            }
            _ => {}
        }
    }

    match key.code {
        KeyCode::Char('?') => {
            app.active_modal = ActiveModal::KeybindingsHelp;
        }
        KeyCode::Char('/') => {
            app.search_query = TextField::default();
            app.active_modal = ActiveModal::Search;
        }
        KeyCode::Char('q') => {
            app.should_quit = true;
        }
        KeyCode::Char('j') | KeyCode::Down => {
            if key.modifiers.contains(KeyModifiers::SHIFT) {
                app.extend_selection(1);
            } else {
                app.move_selection(1);
            }
        }
        KeyCode::Char('k') | KeyCode::Up => {
            if key.modifiers.contains(KeyModifiers::SHIFT) {
                app.extend_selection(-1);
            } else {
                app.move_selection(-1);
            }
        }
        KeyCode::Left | KeyCode::Right => {
            app.cycle_project_filter();
        }
        KeyCode::PageDown => {
            app.move_selection(10);
        }
        KeyCode::PageUp => {
            app.move_selection(-10);
        }
        KeyCode::Home | KeyCode::Char('g') => {
            app.clear_selection();
            app.selected_index = 0;
        }
        KeyCode::End | KeyCode::Char('G') => {
            app.clear_selection();
            if !app.filtered_indices.is_empty() {
                app.selected_index = app.filtered_indices.len() - 1;
            }
        }
        KeyCode::Char('c') => {
            app.copy_selected_secret();
        }
        KeyCode::Char(' ') => {
            if key.modifiers.contains(KeyModifiers::SHIFT) {
                app.toggle_reveal_all();
            } else {
                app.toggle_selected_reveal();
            }
        }
        KeyCode::Char('v') => {
            app.toggle_selected_reveal();
        }
        KeyCode::Char('*') | KeyCode::Char('V') => {
            app.toggle_reveal_all();
        }
        KeyCode::Char('a') => {
            let default_proj = if app.ctx.config.default_project == "global" {
                String::new()
            } else {
                app.ctx.config.default_project.clone()
            };
            app.form_state = Default::default();
            app.form_state.project = TextField::new(default_proj);
            app.form_state.active_field = 0;
            app.active_modal = ActiveModal::Add;
        }
        KeyCode::Char('e') => {
            if app.in_group_mode() {
                app.bulk_form = crate::tui::app::BulkFormState::default();
                app.active_modal = ActiveModal::BulkEdit;
            } else if !app.filtered_indices.is_empty() {
                let real_idx = app.filtered_indices[app.selected_index];
                if let Some(entry) = app.ctx.vault.entries.get(real_idx) {
                    app.form_state = crate::tui::app::FormState::from_entry(entry);
                    app.active_modal = ActiveModal::Edit(real_idx);
                }
            }
        }
        KeyCode::Char('d') | KeyCode::Delete => {
            if app.in_group_mode() {
                app.delete_choice_delete = true;
                let real_idx = app.filtered_indices[app.selected_index];
                app.active_modal = ActiveModal::DeleteConfirm(real_idx);
            } else if !app.filtered_indices.is_empty() {
                let real_idx = app.filtered_indices[app.selected_index];
                app.delete_choice_delete = true;
                app.active_modal = ActiveModal::DeleteConfirm(real_idx);
            }
        }
        KeyCode::Char('i') => {
            app.path_form = PathFormState::default();
            app.active_modal = ActiveModal::Import;
        }
        KeyCode::Char('X') => {
            app.path_form = PathFormState::default();
            app.active_modal = ActiveModal::Export;
        }
        KeyCode::Char('p') => {
            app.cycle_project_filter();
        }
        KeyCode::Char('l') => {
            let _ = lock_daemon(&app.ctx.socket_path);
            app.set_status("Vault locked");
            app.should_quit = true;
        }
        KeyCode::Esc => {
            if app.in_group_mode() {
                app.clear_selection();
            } else if !app.search_query.text.is_empty() {
                app.search_query = TextField::default();
                app.update_filtered_indices();
            }
        }
        _ => {}
    }
}

fn handle_help_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::Char('?') => {
            app.active_modal = ActiveModal::None;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.move_selection(-1);
        }
        KeyCode::Down | KeyCode::Char('j') | KeyCode::Char(' ') => {
            app.move_selection(1);
        }
        _ => {}
    }
}

fn handle_delete_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            if let Err(e) = app.delete_selected_entry() {
                app.set_status(format!("Error deleting: {e}"));
            }
        }
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
            app.active_modal = ActiveModal::None;
        }
        KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
            app.delete_choice_delete = !app.delete_choice_delete;
        }
        KeyCode::Enter => {
            if let Err(e) = app.confirm_delete_choice() {
                app.set_status(format!("Error deleting: {e}"));
            }
        }
        _ => {}
    }
}

fn handle_search_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.search_query = TextField::default();
            app.update_filtered_indices();
            app.active_modal = ActiveModal::None;
        }
        KeyCode::Enter | KeyCode::Down => {
            app.active_modal = ActiveModal::None;
        }
        KeyCode::Up => {
            app.move_selection(-1);
        }
        KeyCode::Left => {
            app.search_query.move_left();
        }
        KeyCode::Right => {
            app.search_query.move_right();
        }
        KeyCode::Home => {
            app.search_query.move_home();
        }
        KeyCode::End => {
            app.search_query.move_end();
        }
        KeyCode::Backspace => {
            app.search_query.backspace();
            app.update_filtered_indices();
        }
        KeyCode::Delete => {
            app.search_query.delete_at_cursor();
            app.update_filtered_indices();
        }
        KeyCode::Char(c) => {
            app.search_query.insert_char(c);
            app.update_filtered_indices();
        }
        _ => {}
    }
}

fn handle_form_key(app: &mut App, key: KeyEvent) {
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        match key.code {
            KeyCode::Char('s') => {
                if let Err(e) = app.save_form() {
                    app.set_status(format!("Validation error: {e}"));
                }
                return;
            }
            KeyCode::Char('v') => {
                app.form_state.show_secret = !app.form_state.show_secret;
                return;
            }
            _ => {}
        }
    }

    match key.code {
        KeyCode::Esc => {
            app.active_modal = ActiveModal::None;
        }
        KeyCode::Tab => {
            app.form_state.next_field();
        }
        KeyCode::BackTab => {
            app.form_state.prev_field();
        }
        KeyCode::Down => {
            app.form_state.next_field();
        }
        KeyCode::Up => {
            app.form_state.prev_field();
        }
        KeyCode::Left => {
            app.form_state.active_field_mut().move_left();
        }
        KeyCode::Right => {
            app.form_state.active_field_mut().move_right();
        }
        KeyCode::Home => {
            app.form_state.active_field_mut().move_home();
        }
        KeyCode::End => {
            app.form_state.active_field_mut().move_end();
        }
        KeyCode::Enter => {
            if app.form_state.active_field == 4 {
                if let Err(e) = app.save_form() {
                    app.set_status(format!("Validation error: {e}"));
                }
            } else {
                app.form_state.next_field();
            }
        }
        KeyCode::Backspace => {
            app.form_state.active_field_mut().backspace();
        }
        KeyCode::Delete => {
            app.form_state.active_field_mut().delete_at_cursor();
        }
        KeyCode::Char(c) => {
            app.form_state.active_field_mut().insert_char(c);
        }
        _ => {}
    }
}

fn handle_bulk_key(app: &mut App, key: KeyEvent) {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s') {
        if let Err(e) = app.apply_bulk_edit() {
            app.set_status(format!("Validation error: {e}"));
        }
        return;
    }

    match key.code {
        KeyCode::Esc => {
            app.active_modal = ActiveModal::None;
        }
        KeyCode::Tab | KeyCode::Down => {
            app.bulk_form.next_field();
        }
        KeyCode::BackTab | KeyCode::Up => {
            app.bulk_form.prev_field();
        }
        KeyCode::Left => {
            app.bulk_form.active_field_mut().move_left();
        }
        KeyCode::Right => {
            app.bulk_form.active_field_mut().move_right();
        }
        KeyCode::Home => {
            app.bulk_form.active_field_mut().move_home();
        }
        KeyCode::End => {
            app.bulk_form.active_field_mut().move_end();
        }
        KeyCode::Enter => {
            if app.bulk_form.active_field == 1 {
                if let Err(e) = app.apply_bulk_edit() {
                    app.set_status(format!("Validation error: {e}"));
                }
            } else {
                app.bulk_form.next_field();
            }
        }
        KeyCode::Backspace => {
            app.bulk_form.active_field_mut().backspace();
        }
        KeyCode::Delete => {
            app.bulk_form.active_field_mut().delete_at_cursor();
        }
        KeyCode::Char(c) => {
            app.bulk_form.active_field_mut().insert_char(c);
        }
        _ => {}
    }
}

fn handle_path_form_key(app: &mut App, key: KeyEvent) {    let is_export = app.active_modal == ActiveModal::Export;
    let max_fields = 2;

    match key.code {
        KeyCode::Esc => {
            app.active_modal = ActiveModal::None;
        }
        KeyCode::Tab => {
            if app.path_form.active_field == 0 {
                let (completed, msg) = complete_path(&app.path_form.path.text);
                app.path_form.path.text = completed;
                app.path_form.path.move_end();
                app.set_status(msg);
            } else {
                app.path_form.next_field(max_fields);
            }
        }
        KeyCode::BackTab => {
            app.path_form.prev_field(max_fields);
        }
        KeyCode::Down => {
            app.path_form.next_field(max_fields);
        }
        KeyCode::Up => {
            app.path_form.prev_field(max_fields);
        }
        KeyCode::Left => {
            if is_export && app.path_form.active_field == 1 {
                app.path_form.export_example = !app.path_form.export_example;
            } else {
                app.path_form.active_field_mut().move_left();
            }
        }
        KeyCode::Right => {
            if is_export && app.path_form.active_field == 1 {
                app.path_form.export_example = !app.path_form.export_example;
            } else {
                app.path_form.active_field_mut().move_right();
            }
        }
        KeyCode::Home => {
            app.path_form.active_field_mut().move_home();
        }
        KeyCode::End => {
            app.path_form.active_field_mut().move_end();
        }
        KeyCode::Char(' ') if is_export && app.path_form.active_field == 1 => {
            app.path_form.export_example = !app.path_form.export_example;
        }
        KeyCode::Enter => {
            if app.path_form.active_field == 1 {
                let res = if is_export {
                    app.run_export()
                } else {
                    app.run_import()
                };
                if let Err(e) = res {
                    app.set_status(format!("Error: {e}"));
                }
            } else {
                app.path_form.next_field(max_fields);
            }
        }
        KeyCode::Backspace => {
            if !(is_export && app.path_form.active_field == 1) {
                app.path_form.active_field_mut().backspace();
            }
        }
        KeyCode::Delete => {
            if !(is_export && app.path_form.active_field == 1) {
                app.path_form.active_field_mut().delete_at_cursor();
            }
        }
        KeyCode::Char(c) => {
            if is_export && app.path_form.active_field == 1 {
                // Format row is toggled with Left/Right/Space only.
            } else {
                app.path_form.active_field_mut().insert_char(c);
            }
        }
        _ => {}
    }
}
