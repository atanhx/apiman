use crate::cli::SessionContext;
use crate::security::SecretString;
use crate::vault::SecretEntry;
use arboard::Clipboard;
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
}

#[derive(Debug, Clone, Default)]
pub struct FormState {
    pub name: String,
    pub project: String,
    pub value: String,
    pub tags: String,
    pub description: String,
    pub active_field: usize, // 0: Name, 1: Project, 2: Value, 3: Tags, 4: Description
    pub show_secret: bool,
}

impl FormState {
    pub fn from_entry(entry: &SecretEntry) -> Self {
        Self {
            name: entry.name.clone(),
            project: entry.project.clone().unwrap_or_default(),
            value: entry.value.expose_secret().to_string(),
            tags: entry.tags.join(", "),
            description: entry.description.clone().unwrap_or_default(),
            active_field: 0,
            show_secret: false,
        }
    }
}

pub struct App {
    pub ctx: SessionContext,
    pub filtered_indices: Vec<usize>,
    pub selected_index: usize,
    pub revealed_entries: HashSet<String>,
    pub search_query: String,
    pub project_filter: Option<String>,
    pub active_modal: ActiveModal,
    pub form_state: FormState,
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
            search_query: String::new(),
            project_filter: None,
            active_modal: ActiveModal::None,
            form_state: FormState::default(),
            status_message: None,
            should_quit: false,
        };
        app.update_filtered_indices();
        app
    }

    pub fn update_filtered_indices(&mut self) {
        let query = self.search_query.trim().to_lowercase();
        let proj_filter = self.project_filter.as_deref();

        self.filtered_indices = self
            .ctx
            .vault
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                // Project filter check
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

                // Search query check
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
            let secret_val = entry.value.expose_secret().to_string();
            let name = entry.name.clone();
            match Clipboard::new() {
                Ok(mut clipboard) => match clipboard.set_text(secret_val) {
                    Ok(_) => {
                        self.set_status(format!("Copied '{name}' to clipboard"));
                    }
                    Err(e) => {
                        self.set_status(format!("Clipboard copy error: {e}"));
                    }
                },
                Err(e) => {
                    self.set_status(format!("Clipboard unavailable: {e}"));
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

    pub fn save_form(&mut self) -> Result<(), String> {
        let name = self.form_state.name.trim();
        if name.is_empty() {
            return Err("Secret name cannot be empty".to_string());
        }

        let proj = self.form_state.project.trim();
        let project = if proj.is_empty() || proj.eq_ignore_ascii_case("global") {
            None
        } else {
            Some(proj.to_string())
        };

        let tags: Vec<String> = self
            .form_state
            .tags
            .split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();

        let description = if self.form_state.description.trim().is_empty() {
            None
        } else {
            Some(self.form_state.description.trim().to_string())
        };

        let value = SecretString::new(&self.form_state.value);

        match self.active_modal {
            ActiveModal::Add => {
                self.ctx
                    .vault
                    .set(name.to_string(), value, project, tags, description);
                self.ctx.save().map_err(|e| e.to_string())?;
                self.set_status(format!("Added secret '{name}'"));
            }
            ActiveModal::Edit(real_idx) => {
                if let Some(existing) = self.ctx.vault.entries.get_mut(real_idx) {
                    existing.name = name.to_string();
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
