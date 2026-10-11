use crate::cli::SessionContext;
use crate::clipboard::copy_to_clipboard;
use crate::dotenv::parse_dotenv;
use crate::security::SecretString;
use crate::vault::SecretEntry;
use std::collections::HashSet;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActiveModal {
    None,
    Add,
    Edit(usize),
    DeleteConfirm(usize),
    KeybindingsHelp,
    Search,
    Import,
    Export,
}

#[derive(Debug, Clone, Default)]
pub struct TextField {
    pub text: String,
    pub cursor: usize, // char index within text
}

impl TextField {
    pub fn new(text: String) -> Self {
        let cursor = text.chars().count();
        Self { text, cursor }
    }

    pub fn insert_char(&mut self, c: char) {
        let byte_idx = char_to_byte_idx(&self.text, self.cursor);
        self.text.insert(byte_idx, c);
        self.cursor += 1;
    }

    pub fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        self.cursor -= 1;
        let byte_idx = char_to_byte_idx(&self.text, self.cursor);
        self.text.remove(byte_idx);
    }

    pub fn delete_at_cursor(&mut self) {
        let total = self.text.chars().count();
        if self.cursor >= total {
            return;
        }
        let byte_idx = char_to_byte_idx(&self.text, self.cursor);
        self.text.remove(byte_idx);
    }

    pub fn move_left(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    pub fn move_right(&mut self) {
        if self.cursor < self.text.chars().count() {
            self.cursor += 1;
        }
    }

    pub fn move_home(&mut self) {
        self.cursor = 0;
    }

    pub fn move_end(&mut self) {
        self.cursor = self.text.chars().count();
    }

    pub fn clamp_cursor(&mut self) {
        let total = self.text.chars().count();
        if self.cursor > total {
            self.cursor = total;
        }
    }

    pub fn with_cursor_marker(&self, mask: bool) -> String {
        let display = if mask {
            "*".repeat(self.text.chars().count())
        } else {
            self.text.clone()
        };
        let mut out = String::with_capacity(display.len() + 1);
        for (i, c) in display.chars().enumerate() {
            if i == self.cursor {
                out.push('█');
            }
            out.push(c);
        }
        if self.cursor >= display.chars().count() {
            out.push('█');
        }
        out
    }
}

fn char_to_byte_idx(s: &str, char_idx: usize) -> usize {
    s.char_indices()
        .nth(char_idx)
        .map(|(i, _)| i)
        .unwrap_or_else(|| s.len())
}

#[derive(Debug, Clone, Default)]
pub struct FormState {
    pub name: TextField,
    pub project: TextField,
    pub value: TextField,
    pub tags: TextField,
    pub description: TextField,
    pub active_field: usize, // 0: Name, 1: Project, 2: Value, 3: Tags, 4: Description
    pub show_secret: bool,
}

impl FormState {
    pub fn from_entry(entry: &SecretEntry) -> Self {
        Self {
            name: TextField::new(entry.name.clone()),
            project: TextField::new(entry.project.clone().unwrap_or_default()),
            value: TextField::new(entry.value.expose_secret().to_string()),
            tags: TextField::new(entry.tags.join(", ")),
            description: TextField::new(entry.description.clone().unwrap_or_default()),
            active_field: 0,
            show_secret: false,
        }
    }

    pub fn active_field_mut(&mut self) -> &mut TextField {
        match self.active_field {
            0 => &mut self.name,
            1 => &mut self.project,
            2 => &mut self.value,
            3 => &mut self.tags,
            _ => &mut self.description,
        }
    }

    pub fn next_field(&mut self) {
        self.active_field = (self.active_field + 1) % 5;
        self.active_field_mut().move_end();
    }

    pub fn prev_field(&mut self) {
        self.active_field = if self.active_field == 0 {
            4
        } else {
            self.active_field - 1
        };
        self.active_field_mut().move_end();
    }
}

#[derive(Debug, Clone, Default)]
pub struct PathFormState {
    pub path: TextField,
    pub project: TextField,
    pub active_field: usize, // 0: Path, 1: Project
    pub export_example: bool,
}

impl PathFormState {
    pub fn active_field_mut(&mut self) -> &mut TextField {
        if self.active_field == 0 {
            &mut self.path
        } else {
            &mut self.project
        }
    }

    pub fn next_field(&mut self, max: usize) {
        self.active_field = (self.active_field + 1) % max;
        self.active_field_mut().move_end();
    }

    pub fn prev_field(&mut self, max: usize) {
        self.active_field = if self.active_field == 0 {
            max - 1
        } else {
            self.active_field - 1
        };
        self.active_field_mut().move_end();
    }
}

pub struct App {
    pub ctx: SessionContext,
    pub filtered_indices: Vec<usize>,
    pub selected_index: usize,
    pub revealed_entries: HashSet<String>,
    pub search_query: TextField,
    pub project_filter: Option<String>,
    pub active_modal: ActiveModal,
    pub form_state: FormState,
    pub path_form: PathFormState,
    pub delete_choice_delete: bool,
    pub status_message: Option<(String, Instant)>,
    pub should_quit: bool,
}

impl App {
    pub fn new(ctx: SessionContext) -> Self {
        let mut app = Self {
            ctx,
            filtered_indices: Vec::new(),
            selected_index: 0,
            revealed_entries: HashSet::new(),
            search_query: TextField::default(),
            project_filter: None,
            active_modal: ActiveModal::None,
            form_state: FormState::default(),
            path_form: PathFormState::default(),
            delete_choice_delete: true,
            status_message: None,
            should_quit: false,
        };
        app.update_filtered_indices();
        app
    }

    pub fn update_filtered_indices(&mut self) {
        let query = self.search_query.text.trim().to_lowercase();
        let proj_filter = self.project_filter.as_deref();

        self.filtered_indices = self
            .ctx
            .vault
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                if let Some(p) = proj_filter {
                    if p != "all" {
                        if p == "global" {
                            if !entry.is_global() {
                                return false;
                            }
                        } else if entry.project.as_deref() != Some(p) {
                            return false;
                        }
                    }
                }

                if !query.is_empty() {
                    let matches_name = entry.name.to_lowercase().contains(&query);
                    let matches_proj = entry.project_display().to_lowercase().contains(&query);
                    let matches_tags = entry
                        .tags
                        .iter()
                        .any(|t| t.to_lowercase().contains(&query));
                    let matches_desc = entry
                        .description
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&query);

                    if !matches_name && !matches_proj && !matches_tags && !matches_desc {
                        return false;
                    }
                }

                true
            })
            .map(|(i, _)| i)
            .collect();

        if self.filtered_indices.is_empty() {
            self.selected_index = 0;
        } else if self.selected_index >= self.filtered_indices.len() {
            self.selected_index = self.filtered_indices.len() - 1;
        }
    }

    pub fn selected_entry(&self) -> Option<&SecretEntry> {
        if self.filtered_indices.is_empty() {
            return None;
        }
        let real_idx = self.filtered_indices[self.selected_index];
        self.ctx.vault.entries.get(real_idx)
    }

    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status_message = Some((msg.into(), Instant::now()));
    }

    pub fn status_text(&self) -> Option<&str> {
        if let Some((msg, time)) = &self.status_message {
            if time.elapsed() < Duration::from_secs(4) {
                return Some(msg.as_str());
            }
        }
        None
    }

    pub fn copy_selected_secret(&mut self) {
        if let Some(entry) = self.selected_entry() {
            let secret_val = entry.value.expose_secret();
            let name = entry.name.clone();
            match copy_to_clipboard(secret_val) {
                Ok(_) => {
                    self.set_status(format!("Copied '{name}' to clipboard"));
                }
                Err(e) => {
                    self.set_status(format!("Copy failed: {e}"));
                }
            }
        }
    }

    pub fn toggle_selected_reveal(&mut self) {
        if let Some(entry) = self.selected_entry() {
            let id = entry.id.clone();
            if self.revealed_entries.contains(&id) {
                self.revealed_entries.remove(&id);
            } else {
                self.revealed_entries.insert(id);
            }
        }
    }

    pub fn move_selection(&mut self, delta: isize) {
        if self.filtered_indices.is_empty() {
            return;
        }
        let len = self.filtered_indices.len() as isize;
        let next = (self.selected_index as isize + delta).clamp(0, len - 1);
        self.selected_index = next as usize;
    }

    pub fn save_form(&mut self) -> Result<(), String> {
        let name = self.form_state.name.text.trim().to_string();
        if name.is_empty() {
            return Err("Secret name cannot be empty".to_string());
        }

        let proj = self.form_state.project.text.trim().to_string();
        let project = if proj.is_empty() || proj.eq_ignore_ascii_case("global") {
            None
        } else {
            Some(proj)
        };

        let tags: Vec<String> = self
            .form_state
            .tags
            .text
            .split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();

        let description = if self.form_state.description.text.trim().is_empty() {
            None
        } else {
            Some(self.form_state.description.text.trim().to_string())
        };

        let value = SecretString::new(self.form_state.value.text.clone());

        match self.active_modal {
            ActiveModal::Add => {
                self.ctx
                    .vault
                    .set(name.clone(), value, project, tags, description);
                self.ctx.save().map_err(|e| e.to_string())?;
                self.set_status(format!("Added secret '{name}'"));
            }
            ActiveModal::Edit(real_idx) => {
                if let Some(existing) = self.ctx.vault.entries.get_mut(real_idx) {
                    existing.name = name.clone();
                    existing.project = project;
                    existing.value = value;
                    existing.tags = tags;
                    existing.description = description;
                    existing.updated_at = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                }
                self.ctx.save().map_err(|e| e.to_string())?;
                self.set_status(format!("Updated secret '{name}'"));
            }
            _ => {}
        }

        self.active_modal = ActiveModal::None;
        self.update_filtered_indices();
        Ok(())
    }

    pub fn confirm_delete_choice(&mut self) -> Result<(), String> {
        if !self.delete_choice_delete {
            self.active_modal = ActiveModal::None;
            return Ok(());
        }
        self.delete_selected_entry()
    }

    pub fn delete_selected_entry(&mut self) -> Result<(), String> {
        if let ActiveModal::DeleteConfirm(real_idx) = self.active_modal {
            if real_idx < self.ctx.vault.entries.len() {
                let name = self.ctx.vault.entries[real_idx].name.clone();
                self.ctx.vault.entries.remove(real_idx);
                self.ctx.save().map_err(|e| e.to_string())?;
                self.set_status(format!("Deleted secret '{name}'"));
            }
        }
        self.active_modal = ActiveModal::None;
        self.update_filtered_indices();
        Ok(())
    }

    pub fn run_import(&mut self) -> Result<(), String> {
        let path_str = self.path_form.path.text.trim().to_string();
        if path_str.is_empty() {
            return Err("File path cannot be empty".to_string());
        }
        let content =
            std::fs::read_to_string(&path_str).map_err(|e| format!("Cannot read file: {e}"))?;
        let (entries, skipped) = parse_dotenv(&content);

        let proj = self.path_form.project.text.trim().to_string();
        let project = if proj.is_empty() || proj.eq_ignore_ascii_case("global") {
            None
        } else {
            Some(proj)
        };

        let mut imported = 0;
        let mut empty_skipped = 0;
        for e in entries {
            if e.value.is_empty() {
                empty_skipped += 1;
                continue;
            }
            self.ctx.vault.set(
                e.key,
                SecretString::new(&e.value),
                project.clone(),
                Vec::new(),
                None,
            );
            imported += 1;
        }
        self.ctx.save().map_err(|e| e.to_string())?;
        self.active_modal = ActiveModal::None;
        self.update_filtered_indices();
        self.set_status(format!(
            "Imported {imported} entries (skipped {skipped} invalid, {empty_skipped} empty)"
        ));
        Ok(())
    }

    pub fn run_export(&mut self) -> Result<(), String> {
        use crate::cli::write_secret_file;
        use crate::dotenv::{format_env, format_example, EnvEntry};

        let path_str = self.path_form.path.text.trim().to_string();
        if path_str.is_empty() {
            return Err("File path cannot be empty".to_string());
        }

        let output = if self.path_form.export_example {
            let mut keys: Vec<String> = self
                .filtered_indices
                .iter()
                .filter_map(|&i| self.ctx.vault.entries.get(i))
                .map(|e| e.name.clone())
                .collect();
            keys.sort();
            keys.dedup();
            format_example(&keys)
        } else {
            let mut entries: Vec<EnvEntry> = self
                .filtered_indices
                .iter()
                .filter_map(|&i| self.ctx.vault.entries.get(i))
                .map(|e| EnvEntry {
                    key: e.name.clone(),
                    value: e.value.expose_secret().to_string(),
                })
                .collect();
            entries.sort_by(|a, b| a.key.cmp(&b.key));
            format_env(&entries)
        };

        write_secret_file(std::path::Path::new(&path_str), output.as_bytes())
            .map_err(|e| format!("Cannot write file: {e}"))?;
        self.active_modal = ActiveModal::None;
        self.set_status(format!("Exported to '{path_str}'"));
        Ok(())
    }

    pub fn cycle_project_filter(&mut self) {
        let mut projects: Vec<String> = self
            .ctx
            .vault
            .entries
            .iter()
            .filter_map(|e| e.project.clone())
            .collect();
        projects.sort();
        projects.dedup();

        let options = {
            let mut opts = vec!["all".to_string(), "global".to_string()];
            opts.extend(projects);
            opts
        };

        let current = self.project_filter.as_deref().unwrap_or("all");
        let next_idx = options
            .iter()
            .position(|p| p == current)
            .map(|i| (i + 1) % options.len())
            .unwrap_or(0);

        let next = &options[next_idx];
        self.project_filter = if next == "all" {
            None
        } else {
            Some(next.clone())
        };
        self.update_filtered_indices();
    }
}
