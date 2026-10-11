use crate::cli::SessionContext;
use crate::config::expand_path;
use crate::dotenv::parse_dotenv;
use crate::security::SecretString;
use crate::tui::keymap::Keymap;
use crate::tui::theme::Theme;
use crate::vault::{
    SecretEntry, Vault, normalize_project, normalize_tags, same_project, validate_secret_name,
};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActiveModal {
    None,
    Add,
    /// Entry id being edited.
    Edit(String),
    BulkEdit,
    /// Entry ids to delete, captured when the dialog opened.
    DeleteConfirm(Vec<String>),
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

    pub fn len(&self) -> usize {
        self.text.chars().count()
    }

    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    pub fn insert_char(&mut self, c: char) {
        let byte_idx = char_to_byte_idx(&self.text, self.cursor);
        self.text.insert(byte_idx, c);
        self.cursor += 1;
    }

    pub fn insert_str(&mut self, s: &str) {
        for c in s.chars() {
            self.insert_char(c);
        }
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
        if self.cursor >= self.len() {
            return;
        }
        let byte_idx = char_to_byte_idx(&self.text, self.cursor);
        self.text.remove(byte_idx);
    }

    pub fn delete_word_back(&mut self) {
        while self.cursor > 0 && self.char_before().is_some_and(char::is_whitespace) {
            self.backspace();
        }
        while self.cursor > 0 && self.char_before().is_some_and(|c| !c.is_whitespace()) {
            self.backspace();
        }
    }

    fn char_before(&self) -> Option<char> {
        self.text.chars().nth(self.cursor.checked_sub(1)?)
    }

    pub fn clear(&mut self) {
        self.text.zeroize();
        self.cursor = 0;
    }

    pub fn move_left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn move_right(&mut self) {
        if self.cursor < self.len() {
            self.cursor += 1;
        }
    }

    pub fn move_home(&mut self) {
        self.cursor = 0;
    }

    pub fn move_end(&mut self) {
        self.cursor = self.len();
    }

    pub fn set(&mut self, text: String) {
        self.text.zeroize();
        self.text = text;
        self.move_end();
    }
}

fn char_to_byte_idx(s: &str, char_idx: usize) -> usize {
    s.char_indices()
        .nth(char_idx)
        .map(|(i, _)| i)
        .unwrap_or(s.len())
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

pub const FORM_FIELDS: usize = 5;
pub const FORM_VALUE_FIELD: usize = 2;

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
        self.active_field = (self.active_field + 1) % FORM_FIELDS;
        self.active_field_mut().move_end();
    }

    pub fn prev_field(&mut self) {
        self.active_field = (self.active_field + FORM_FIELDS - 1) % FORM_FIELDS;
        self.active_field_mut().move_end();
    }

    /// Zeroes every field (the secret value above all) when a form closes.
    pub fn wipe(&mut self) {
        for f in [
            &mut self.name,
            &mut self.project,
            &mut self.value,
            &mut self.tags,
            &mut self.description,
        ] {
            f.clear();
        }
        self.active_field = 0;
        self.show_secret = false;
    }
}

#[derive(Debug, Clone, Default)]
pub struct PathFormState {
    pub path: TextField,
    pub project: TextField,
    pub active_field: usize, // 0: Path, 1: Project (import) / Format (export)
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
        self.active_field = (self.active_field + max - 1) % max;
        self.active_field_mut().move_end();
    }
}

#[derive(Debug, Clone, Default)]
pub struct BulkFormState {
    pub project: TextField,
    pub tags: TextField,
    pub active_field: usize, // 0: Project, 1: Tags
}

impl BulkFormState {
    pub fn active_field_mut(&mut self) -> &mut TextField {
        if self.active_field == 0 {
            &mut self.project
        } else {
            &mut self.tags
        }
    }

    pub fn next_field(&mut self) {
        self.active_field = (self.active_field + 1) % 2;
        self.active_field_mut().move_end();
    }

    pub fn prev_field(&mut self) {
        self.next_field();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastKind {
    Info,
    Success,
    Error,
}

const TOAST_TTL: Duration = Duration::from_secs(5);
const KEEPALIVE_EVERY: Duration = Duration::from_secs(30);
const DISK_CHECK_EVERY: Duration = Duration::from_secs(1);

pub struct App {
    pub ctx: SessionContext,
    pub keymap: Keymap,
    pub theme: Theme,
    pub filtered_indices: Vec<usize>,
    pub selected_index: usize,
    /// First visible row of the table, persisted across frames for smooth scrolling.
    pub table_offset: Cell<usize>,
    pub revealed_entries: HashSet<String>,
    /// Entry ids in the group selection (pins + active shift range).
    pub marked: HashSet<String>,
    /// Entry ids pinned individually with Tab or committed from a range.
    pub pinned: HashSet<String>,
    /// Filtered-list position where the active shift-range started.
    pub selection_anchor: Option<usize>,
    pub search_query: TextField,
    pub project_filter: Option<String>,
    pub active_modal: ActiveModal,
    pub form_state: FormState,
    pub path_form: PathFormState,
    pub bulk_form: BulkFormState,
    pub delete_choice_delete: bool,
    pub help_scroll: u16,
    pub status_message: Option<(String, ToastKind, Instant)>,
    pub should_quit: bool,
    /// Printed after the terminal is restored (lock / auto-lock notices).
    pub exit_message: Option<String>,
    pub last_activity: Instant,
    last_keepalive: Instant,
    last_disk_check: Instant,
}

impl App {
    pub fn new(ctx: SessionContext) -> Self {
        let (keymap, mut problems) = Keymap::from_config(&ctx.config.keybindings);
        let (theme, theme_problem) = Theme::from_config(&ctx.config.theme);
        problems.extend(theme_problem);
        let now = Instant::now();
        let mut app = Self {
            ctx,
            keymap,
            theme,
            filtered_indices: Vec::new(),
            selected_index: 0,
            table_offset: Cell::new(0),
            revealed_entries: HashSet::new(),
            marked: HashSet::new(),
            pinned: HashSet::new(),
            selection_anchor: None,
            search_query: TextField::default(),
            project_filter: None,
            active_modal: ActiveModal::None,
            form_state: FormState::default(),
            path_form: PathFormState::default(),
            bulk_form: BulkFormState::default(),
            delete_choice_delete: false,
            help_scroll: 0,
            status_message: None,
            should_quit: false,
            exit_message: None,
            last_activity: now,
            last_keepalive: now,
            last_disk_check: now,
        };
        app.recompute(None);
        if !problems.is_empty() {
            app.set_error(format!(
                "config.json: {} (run 'apiman keys')",
                problems.join("; ")
            ));
        }
        app
    }

    fn entry_matches(&self, entry: &SecretEntry, query: &str) -> bool {
        if let Some(p) = self.project_filter.as_deref() {
            if p == "global" {
                if !entry.is_global() {
                    return false;
                }
            } else if !entry.in_scope(Some(p)) {
                return false;
            }
        }
        if query.is_empty() {
            return true;
        }
        entry.name.to_lowercase().contains(query)
            || entry.project_display().to_lowercase().contains(query)
            || entry.tags.iter().any(|t| t.to_lowercase().contains(query))
            || entry
                .description
                .as_deref()
                .is_some_and(|d| d.to_lowercase().contains(query))
    }

    /// Rebuilds the visible list after the vault or filters changed, keeping
    /// the cursor on `focus` (an entry id) when it is still visible and
    /// dropping selections of entries that no longer exist.
    pub fn recompute(&mut self, focus: Option<String>) {
        let query = self.search_query.text.trim().to_lowercase();
        self.filtered_indices = (0..self.ctx.vault.entries.len())
            .filter(|&i| self.entry_matches(&self.ctx.vault.entries[i], &query))
            .collect();

        let existing: HashSet<&str> = self
            .ctx
            .vault
            .entries
            .iter()
            .map(|e| e.id.as_str())
            .collect();
        self.pinned.retain(|id| existing.contains(id.as_str()));
        self.revealed_entries
            .retain(|id| existing.contains(id.as_str()));

        if let Some(id) = focus
            && let Some(pos) = self
                .filtered_indices
                .iter()
                .position(|&i| self.ctx.vault.entries[i].id == id)
        {
            self.selected_index = pos;
        }
        if self.filtered_indices.is_empty() {
            self.selected_index = 0;
        } else if self.selected_index >= self.filtered_indices.len() {
            self.selected_index = self.filtered_indices.len() - 1;
        }
        if self
            .selection_anchor
            .is_some_and(|a| a >= self.filtered_indices.len())
        {
            self.selection_anchor = None;
        }
        self.refresh_marked();
    }

    /// Filter/search changed: the group selection no longer applies.
    pub fn update_filtered_indices(&mut self) {
        let focus = self.selected_id();
        self.clear_selection();
        self.recompute(focus);
    }

    pub fn selected_entry(&self) -> Option<&SecretEntry> {
        self.filtered_indices
            .get(self.selected_index)
            .and_then(|&i| self.ctx.vault.entries.get(i))
    }

    pub fn selected_id(&self) -> Option<String> {
        self.selected_entry().map(|e| e.id.clone())
    }

    pub fn visible_entries(&self) -> impl Iterator<Item = &SecretEntry> {
        self.filtered_indices
            .iter()
            .filter_map(|&i| self.ctx.vault.entries.get(i))
    }

    pub fn marked_entries(&self) -> Vec<&SecretEntry> {
        self.ctx
            .vault
            .entries
            .iter()
            .filter(|e| self.marked.contains(&e.id))
            .collect()
    }

    fn toast(&mut self, msg: impl Into<String>, kind: ToastKind) {
        self.status_message = Some((msg.into(), kind, Instant::now()));
    }

    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.toast(msg, ToastKind::Info);
    }

    pub fn set_success(&mut self, msg: impl Into<String>) {
        self.toast(msg, ToastKind::Success);
    }

    pub fn set_error(&mut self, msg: impl Into<String>) {
        self.toast(msg, ToastKind::Error);
    }

    pub fn status(&self) -> Option<(&str, ToastKind)> {
        match &self.status_message {
            Some((msg, kind, at))
                if at.elapsed() < TOAST_TTL
                    || *kind == ToastKind::Error && at.elapsed() < TOAST_TTL * 2 =>
            {
                Some((msg.as_str(), *kind))
            }
            _ => None,
        }
    }

    pub fn status_text(&self) -> Option<&str> {
        self.status().map(|(m, _)| m)
    }

    /// Seconds until the TUI locks itself for inactivity, if auto-lock is on.
    pub fn lock_countdown(&self) -> Option<u64> {
        let timeout = self.ctx.config.auto_lock_timeout_seconds;
        (timeout > 0).then(|| timeout.saturating_sub(self.last_activity.elapsed().as_secs()))
    }

    pub fn note_activity(&mut self) {
        self.last_activity = Instant::now();
        if self.last_keepalive.elapsed() >= KEEPALIVE_EVERY {
            self.last_keepalive = Instant::now();
            // Keep the shared session alive while the user is working here.
            let _ = crate::daemon::touch_daemon(&self.ctx.socket_path);
        }
    }

    /// Periodic housekeeping: inactivity auto-lock and picking up vault
    /// changes made by other apiman processes.
    pub fn tick(&mut self) {
        if let Some(0) = self.lock_countdown() {
            let timeout = self.ctx.config.auto_lock_timeout_seconds;
            self.should_quit = true;
            self.exit_message = Some(format!(
                "apiman locked after {} of inactivity.",
                crate::cli::format_duration_short(timeout)
            ));
            return;
        }
        if self.last_disk_check.elapsed() >= DISK_CHECK_EVERY {
            self.last_disk_check = Instant::now();
            self.reload_from_disk();
        }
    }

    pub fn reload_from_disk(&mut self) {
        let focus = self.selected_id();
        match self.ctx.reload_if_changed() {
            Ok(true) => {
                self.recompute(focus);
                self.set_status("Vault changed outside this window; reloaded");
            }
            Ok(false) => {}
            Err(e) => self.set_error(e),
        }
    }

    /// Runs a vault mutation through the locked reload-modify-save cycle and
    /// refreshes the view, keeping the cursor on `focus`.
    fn commit<R>(
        &mut self,
        focus: Option<String>,
        mutate: impl FnOnce(&mut Vault) -> Result<R, String>,
    ) -> Result<R, String> {
        let out = self.ctx.update(mutate)?;
        self.recompute(focus);
        Ok(out)
    }

    pub fn copy_selected_secret(&mut self) {
        let Some(entry) = self.selected_entry() else {
            return;
        };
        let name = entry.name.clone();
        let result = crate::clipboard::copy_secret(
            entry.value.expose_secret(),
            self.ctx.config.clipboard_timeout_seconds,
        );
        match result {
            Ok(note) => self.set_success(format!("Copied '{name}' ({note})")),
            Err(e) => self.set_error(e),
        }
    }

    fn toggle_reveal(&mut self, ids: Vec<String>, label: &str) {
        if ids.is_empty() {
            self.set_status("Nothing to reveal");
            return;
        }
        let n = ids.len();
        if ids.iter().all(|id| self.revealed_entries.contains(id)) {
            for id in &ids {
                self.revealed_entries.remove(id);
            }
            if n > 1 {
                self.set_status(format!("Masked {n} {label}"));
            }
        } else {
            self.revealed_entries.extend(ids);
            if n > 1 {
                self.set_status(format!("Revealed {n} {label}"));
            }
        }
    }

    pub fn toggle_selected_reveal(&mut self) {
        let ids = self.selected_id().into_iter().collect();
        self.toggle_reveal(ids, "secret");
    }

    pub fn toggle_reveal_all(&mut self) {
        let ids = self.visible_entries().map(|e| e.id.clone()).collect();
        self.toggle_reveal(ids, "visible secrets");
    }

    pub fn toggle_reveal_marked(&mut self) {
        let ids = self.marked_entries().iter().map(|e| e.id.clone()).collect();
        self.toggle_reveal(ids, "selected secrets");
    }

    pub fn move_selection(&mut self, delta: isize) {
        if self.filtered_indices.is_empty() {
            return;
        }
        self.commit_range();
        let len = self.filtered_indices.len() as isize;
        self.selected_index = (self.selected_index as isize + delta).clamp(0, len - 1) as usize;
    }

    pub fn jump_to(&mut self, index: usize) {
        self.commit_range();
        if !self.filtered_indices.is_empty() {
            self.selected_index = index.min(self.filtered_indices.len() - 1);
        }
    }

    pub fn clear_selection(&mut self) {
        self.marked.clear();
        self.pinned.clear();
        self.selection_anchor = None;
    }

    /// Fold the active shift-range into persistent pins so plain navigation
    /// never deselects entries out from under the user. Esc still clears all.
    pub fn commit_range(&mut self) {
        self.pinned.extend(self.marked.iter().cloned());
        self.selection_anchor = None;
        self.refresh_marked();
    }

    fn refresh_marked(&mut self) {
        let mut marked = self.pinned.clone();
        if let Some(anchor) = self.selection_anchor
            && !self.filtered_indices.is_empty()
        {
            let last = self.filtered_indices.len() - 1;
            let (a, c) = (anchor.min(last), self.selected_index.min(last));
            let (lo, hi) = if a <= c { (a, c) } else { (c, a) };
            for &i in &self.filtered_indices[lo..=hi] {
                marked.insert(self.ctx.vault.entries[i].id.clone());
            }
        }
        self.marked = marked;
    }

    pub fn extend_selection(&mut self, delta: isize) {
        if self.filtered_indices.is_empty() {
            return;
        }
        if self.selection_anchor.is_none() {
            self.selection_anchor = Some(self.selected_index);
        }
        let len = self.filtered_indices.len() as isize;
        self.selected_index = (self.selected_index as isize + delta).clamp(0, len - 1) as usize;
        self.refresh_marked();
    }

    pub fn toggle_pin(&mut self) {
        let Some(id) = self.selected_id() else {
            return;
        };
        if !self.pinned.remove(&id) {
            self.pinned.insert(id);
        }
        // Advance so Tab-walking pins 1, 4, 6...; shift-range starts fresh from here.
        if self.selected_index + 1 < self.filtered_indices.len() {
            self.selected_index += 1;
        }
        self.selection_anchor = None;
        self.refresh_marked();
    }

    pub fn in_group_mode(&self) -> bool {
        !self.marked.is_empty()
    }

    pub fn open_add(&mut self) {
        self.form_state.wipe();
        self.form_state.project =
            TextField::new(self.ctx.config.default_scope().unwrap_or_default());
        if let Some(p) = self.project_filter.as_deref().filter(|p| *p != "global") {
            self.form_state.project = TextField::new(p.to_string());
        }
        self.active_modal = ActiveModal::Add;
    }

    pub fn open_edit(&mut self) {
        if self.in_group_mode() {
            self.bulk_form = BulkFormState::default();
            self.active_modal = ActiveModal::BulkEdit;
        } else if let Some(entry) = self.selected_entry() {
            let id = entry.id.clone();
            let form = FormState::from_entry(entry);
            self.form_state.wipe();
            self.form_state = form;
            self.active_modal = ActiveModal::Edit(id);
        }
    }

    pub fn close_form(&mut self) {
        self.form_state.wipe();
        self.active_modal = ActiveModal::None;
    }

    pub fn open_delete(&mut self) {
        let ids: Vec<String> = if self.in_group_mode() {
            self.marked_entries().iter().map(|e| e.id.clone()).collect()
        } else {
            self.selected_id().into_iter().collect()
        };
        if ids.is_empty() {
            return;
        }
        // Destructive: the highlighted default is Cancel.
        self.delete_choice_delete = false;
        self.active_modal = ActiveModal::DeleteConfirm(ids);
    }

    pub fn save_form(&mut self) -> Result<(), String> {
        let name = validate_secret_name(&self.form_state.name.text)?;
        if self.form_state.value.text.is_empty() {
            return Err("Secret value cannot be empty".to_string());
        }
        let project = normalize_project(Some(&self.form_state.project.text));
        let tags = normalize_tags(self.form_state.tags.text.split(',').map(str::to_string));
        let description =
            Some(self.form_state.description.text.trim().to_string()).filter(|d| !d.is_empty());
        let value = SecretString::new(self.form_state.value.text.clone());
        let scope_label = project.clone().unwrap_or_else(|| "global".to_string());

        match self.active_modal.clone() {
            ActiveModal::Add => {
                let id = self.commit(None, |v| {
                    if v.find_exact(&name, project.as_deref()).is_some() {
                        return Err(format!(
                            "'{name}' already exists in scope '{scope_label}'; select it and edit instead"
                        ));
                    }
                    let entry = crate::vault::SecretEntry::new(name.clone(), value, project, tags, description);
                    let id = entry.id.clone();
                    v.entries.push(entry);
                    Ok(id)
                })?;
                self.recompute(Some(id));
                self.set_success(format!("Added '{name}' to {scope_label}"));
            }
            ActiveModal::Edit(id) => {
                self.commit(Some(id.clone()), |v| {
                    if v.entries.iter().any(|e| {
                        e.id != id
                            && e.name == name
                            && same_project(e.project.as_deref(), project.as_deref())
                    }) {
                        return Err(format!("'{name}' already exists in scope '{scope_label}'"));
                    }
                    let entry = v
                        .entries
                        .iter_mut()
                        .find(|e| e.id == id)
                        .ok_or("This entry was deleted outside this window")?;
                    entry.name = name.clone();
                    entry.project = project;
                    entry.value = value;
                    entry.tags = tags;
                    entry.description = description;
                    entry.touch();
                    Ok(())
                })?;
                self.set_success(format!("Updated '{name}'"));
            }
            _ => return Ok(()),
        }

        self.close_form();
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
        let ActiveModal::DeleteConfirm(ids) = self.active_modal.clone() else {
            return Ok(());
        };
        self.active_modal = ActiveModal::None;
        let doomed: HashSet<String> = ids.into_iter().collect();
        let focus = self.selected_id().filter(|id| !doomed.contains(id));
        let removed: Vec<String> = self.commit(focus, |v| {
            let names = v
                .entries
                .iter()
                .filter(|e| doomed.contains(&e.id))
                .map(|e| e.name.clone())
                .collect::<Vec<_>>();
            v.entries.retain(|e| !doomed.contains(&e.id));
            Ok(names)
        })?;
        self.clear_selection();
        self.refresh_marked();
        match removed.as_slice() {
            [] => self.set_status("Nothing deleted (already removed elsewhere)"),
            [one] => self.set_success(format!("Deleted '{one}'")),
            many => self.set_success(format!("Deleted {} secrets", many.len())),
        }
        Ok(())
    }

    pub fn apply_bulk_edit(&mut self) -> Result<(), String> {
        if self.marked.is_empty() {
            return Err("No entries selected".to_string());
        }

        let proj_raw = self.bulk_form.project.text.trim().to_string();
        let change_project = !proj_raw.is_empty();
        let new_project = normalize_project(Some(&proj_raw));
        let tags_raw = self.bulk_form.tags.text.trim().to_string();
        let change_tags = !tags_raw.is_empty();
        let new_tags = normalize_tags(tags_raw.split(',').map(str::to_string));

        if !change_project && !change_tags {
            return Err("Nothing to change (blank fields keep current values)".to_string());
        }

        let ids = self.marked.clone();
        let focus = self.selected_id();
        let updated = self.commit(focus, |v| {
            if change_project {
                let mut owners: HashMap<(String, Option<String>), Vec<bool>> = HashMap::new();
                for e in &v.entries {
                    let moving = ids.contains(&e.id);
                    let project = if moving {
                        new_project.clone()
                    } else {
                        e.project.clone()
                    };
                    owners
                        .entry((e.name.clone(), project.map(|p| p.to_lowercase())))
                        .or_default()
                        .push(moving);
                }
                let mut clashes: Vec<String> = owners
                    .into_iter()
                    .filter(|(_, who)| who.len() > 1 && who.iter().any(|m| *m))
                    .map(|((name, _), _)| name)
                    .collect();
                if !clashes.is_empty() {
                    clashes.sort();
                    return Err(format!(
                        "Moving would create duplicates in '{}': {}",
                        new_project.as_deref().unwrap_or("global"),
                        clashes.join(", ")
                    ));
                }
            }
            let mut updated = 0;
            for entry in v.entries.iter_mut().filter(|e| ids.contains(&e.id)) {
                if change_project {
                    entry.project = new_project.clone();
                }
                if change_tags {
                    entry.tags = new_tags.clone();
                }
                entry.touch();
                updated += 1;
            }
            Ok(updated)
        })?;
        self.active_modal = ActiveModal::None;
        self.clear_selection();
        self.refresh_marked();
        self.set_success(format!("Updated {updated} secrets (values untouched)"));
        Ok(())
    }

    pub fn run_import(&mut self) -> Result<(), String> {
        let path_str = self.path_form.path.text.trim().to_string();
        if path_str.is_empty() {
            return Err("File path cannot be empty".to_string());
        }
        let path = expand_path(std::path::Path::new(&path_str));
        if path.is_dir() {
            return Err(format!(
                "'{path_str}' is a directory; pick a .env file inside it"
            ));
        }
        let content = zeroize::Zeroizing::new(
            std::fs::read_to_string(&path).map_err(|e| format!("Cannot read '{path_str}': {e}"))?,
        );
        let (entries, skipped) = parse_dotenv(&content);
        let project = normalize_project(Some(&self.path_form.project.text));
        let focus = self.selected_id();
        let summary = crate::cli::import_entries(&mut self.ctx, entries, project, Vec::new())?;
        self.recompute(focus);
        self.active_modal = ActiveModal::None;
        self.set_success(format!(
            "Imported {} entr{} (skipped {} invalid, {} empty)",
            summary.imported,
            if summary.imported == 1 { "y" } else { "ies" },
            skipped + summary.invalid_names,
            summary.empty
        ));
        Ok(())
    }

    pub fn run_export(&mut self) -> Result<(), String> {
        use crate::cli::{ExportFormat, resolve_export_path, write_secret_file};
        use crate::dotenv::{EnvEntry, format_env, format_example};

        let path_str = self.path_form.path.text.trim().to_string();
        if path_str.is_empty() {
            return Err("File path cannot be empty".to_string());
        }
        let format = if self.path_form.export_example {
            ExportFormat::Example
        } else {
            ExportFormat::Env
        };
        let out_path = resolve_export_path(&expand_path(std::path::Path::new(&path_str)), format);

        let source: Vec<&SecretEntry> = if self.in_group_mode() {
            self.marked_entries()
        } else {
            self.visible_entries().collect()
        };
        let mut entries: Vec<EnvEntry> = source
            .iter()
            .map(|e| EnvEntry {
                key: e.name.clone(),
                value: e.value.expose_secret().to_string(),
            })
            .collect();
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        let mut dupes: Vec<String> = entries
            .windows(2)
            .filter(|w| w[0].key == w[1].key)
            .map(|w| w[0].key.clone())
            .collect();
        dupes.dedup();

        let output = zeroize::Zeroizing::new(if self.path_form.export_example {
            let mut keys: Vec<String> = entries.iter().map(|e| e.key.clone()).collect();
            keys.dedup();
            format_example(&keys)
        } else {
            format_env(&entries)
        });
        for e in &mut entries {
            e.value.zeroize();
        }

        write_secret_file(&out_path, output.as_bytes())
            .map_err(|e| format!("Cannot write file: {e}"))?;
        self.active_modal = ActiveModal::None;
        let msg = format!(
            "Exported {} entries to '{}'",
            entries.len(),
            out_path.display()
        );
        if dupes.is_empty() {
            self.set_success(msg);
        } else {
            self.set_error(format!(
                "{msg}; duplicate keys from different scopes: {} (narrow the scope)",
                dupes.join(", ")
            ));
        }
        Ok(())
    }

    pub fn scope_options(&self) -> Vec<String> {
        let mut opts = vec!["all".to_string(), "global".to_string()];
        opts.extend(self.ctx.vault.projects());
        opts
    }

    pub fn cycle_project_filter_by(&mut self, step: isize) {
        let options = self.scope_options();
        let current = self.project_filter.as_deref().unwrap_or("all");
        let pos = options
            .iter()
            .position(|p| p.eq_ignore_ascii_case(current))
            .unwrap_or(0) as isize;
        let n = options.len() as isize;
        let next = &options[((pos + step) % n + n) as usize % options.len()];
        self.project_filter = (next != "all").then(|| next.clone());
        self.update_filtered_indices();
    }

    pub fn cycle_project_filter(&mut self) {
        self.cycle_project_filter_by(1);
    }

    pub fn lock_and_quit(&mut self) {
        let _ = crate::daemon::lock_daemon(&self.ctx.socket_path);
        self.should_quit = true;
        self.exit_message = Some("Vault locked. Session daemon stopped.".to_string());
    }
}

/// Tab-completes a filesystem path; `~/` is kept in the result.
pub fn complete_path(input: &str) -> (String, String) {
    let home = std::env::var("HOME").unwrap_or_default();
    let uses_tilde = input.starts_with("~/") && !home.is_empty();
    let expanded = if uses_tilde {
        format!("{}{}", home, &input[1..])
    } else {
        input.to_string()
    };

    let (dir_part, prefix) = match expanded.rfind('/') {
        Some(idx) => (
            expanded[..=idx].to_string(),
            expanded[idx + 1..].to_string(),
        ),
        None => (String::new(), expanded.clone()),
    };
    let search_dir = if dir_part.is_empty() {
        ".".to_string()
    } else {
        dir_part.clone()
    };

    let read_dir = match std::fs::read_dir(&search_dir) {
        Ok(rd) => rd,
        Err(_) => {
            return (
                input.to_string(),
                format!("No such directory: {search_dir}"),
            );
        }
    };

    let mut matches: Vec<String> = read_dir
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(&prefix))
        .collect();
    matches.sort();

    if matches.is_empty() {
        return (input.to_string(), "No matches".to_string());
    }

    let mut common = matches[0].clone();
    for m in &matches[1..] {
        let len = common
            .char_indices()
            .zip(m.chars())
            .take_while(|((_, a), b)| a == b)
            .last()
            .map(|((i, a), _)| i + a.len_utf8())
            .unwrap_or(0);
        common.truncate(len);
    }

    let mut completed_expanded = format!("{dir_part}{common}");
    if matches.len() == 1 && std::path::Path::new(&completed_expanded).is_dir() {
        completed_expanded.push('/');
    }

    let completed = if uses_tilde {
        match completed_expanded.strip_prefix(&home) {
            Some(rest) => format!("~{rest}"),
            None => completed_expanded,
        }
    } else {
        completed_expanded
    };

    let status = if matches.len() == 1 {
        format!("Completed: {}", matches[0])
    } else {
        let shown: Vec<&str> = matches.iter().take(8).map(|s| s.as_str()).collect();
        let more = if matches.len() > 8 {
            format!(" (+{} more)", matches.len() - 8)
        } else {
            String::new()
        };
        format!("{} matches: {}{}", matches.len(), shown.join("  "), more)
    };

    (completed, status)
}
