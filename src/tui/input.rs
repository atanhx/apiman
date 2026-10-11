use crate::daemon::lock_daemon;
use crate::tui::app::{ActiveModal, App, FormState};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

pub fn handle_key(app: &mut App, key: KeyEvent) {
    match &app.active_modal {
        ActiveModal::KeybindingsHelp => handle_help_key(app, key),
        ActiveModal::DeleteConfirm(_) => handle_delete_key(app, key),
        ActiveModal::Search => handle_search_key(app, key),
        ActiveModal::Add | ActiveModal::Edit(_) => handle_form_key(app, key),
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
            app.active_modal = ActiveModal::Search;
        }
        KeyCode::Char('q') => {
            app.should_quit = true;
        }
        KeyCode::Char('j') | KeyCode::Down => {
            if !app.filtered_indices.is_empty() && app.selected_index + 1 < app.filtered_indices.len() {
                app.selected_index += 1;
            }
        }
        KeyCode::Char('k') | KeyCode::Up => {
            if app.selected_index > 0 {
                app.selected_index -= 1;
            }
        }
        KeyCode::Home | KeyCode::Char('g') => {
            app.selected_index = 0;
        }
        KeyCode::End | KeyCode::Char('G') => {
            if !app.filtered_indices.is_empty() {
                app.selected_index = app.filtered_indices.len() - 1;
            }
        }
        KeyCode::Char('c') => {
            app.copy_selected_secret();
        }
        KeyCode::Char(' ') | KeyCode::Char('v') => {
            app.toggle_selected_reveal();
        }
        KeyCode::Char('a') => {
            let default_proj = if app.ctx.config.default_project == "global" {
                String::new()
            } else {
                app.ctx.config.default_project.clone()
            };
            app.form_state = FormState {
                project: default_proj,
                ..Default::default()
            };
            app.active_modal = ActiveModal::Add;
        }
        KeyCode::Char('e') => {
            if !app.filtered_indices.is_empty() {
                let real_idx = app.filtered_indices[app.selected_index];
                if let Some(entry) = app.ctx.vault.entries.get(real_idx) {
                    app.form_state = FormState::from_entry(entry);
                    app.active_modal = ActiveModal::Edit(real_idx);
                }
            }
        }
        KeyCode::Char('d') | KeyCode::Delete => {
            if !app.filtered_indices.is_empty() {
                let real_idx = app.filtered_indices[app.selected_index];
                app.active_modal = ActiveModal::DeleteConfirm(real_idx);
            }
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
            if !app.search_query.is_empty() {
                app.search_query.clear();
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
        _ => {}
    }
}

fn handle_search_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.search_query.clear();
            app.update_filtered_indices();
            app.active_modal = ActiveModal::None;
        }
        KeyCode::Enter => {
            app.active_modal = ActiveModal::None;
        }
        KeyCode::Backspace => {
            app.search_query.pop();
            app.update_filtered_indices();
        }
        KeyCode::Char(c) => {
            app.search_query.push(c);
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
        KeyCode::Tab | KeyCode::Down => {
            app.form_state.active_field = (app.form_state.active_field + 1) % 5;
        }
        KeyCode::BackTab | KeyCode::Up => {
            app.form_state.active_field = if app.form_state.active_field == 0 {
                4
            } else {
                app.form_state.active_field - 1
            };
        }
        KeyCode::Enter => {
            if app.form_state.active_field == 4 {
                if let Err(e) = app.save_form() {
                    app.set_status(format!("Validation error: {e}"));
                }
            } else {
                app.form_state.active_field += 1;
            }
        }
        KeyCode::Backspace => {
            let field = active_field_mut(&mut app.form_state);
            field.pop();
        }
        KeyCode::Char(c) => {
            let field = active_field_mut(&mut app.form_state);
            field.push(c);
        }
        _ => {}
    }
}

fn active_field_mut(form: &mut FormState) -> &mut String {
    match form.active_field {
        0 => &mut form.name,
        1 => &mut form.project,
        2 => &mut form.value,
        3 => &mut form.tags,
        _ => &mut form.description,
    }
}
