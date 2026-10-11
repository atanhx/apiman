use crate::config::KeyList;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Context {
    Normal,
    Form,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    Up,
    Down,
    PageUp,
    PageDown,
    Top,
    Bottom,
    ScopeNext,
    ScopePrev,
    Search,
    ExtendUp,
    ExtendDown,
    TogglePin,
    Clear,
    Copy,
    Reveal,
    RevealAll,
    Add,
    Edit,
    Delete,
    Import,
    Export,
    Help,
    Lock,
    Quit,
    FormSave,
    FormToggleMask,
}

pub struct ActionInfo {
    pub action: Action,
    pub name: &'static str,
    pub description: &'static str,
    pub group: &'static str,
    pub defaults: &'static [&'static str],
    pub context: Context,
}

const fn info(
    action: Action,
    name: &'static str,
    group: &'static str,
    description: &'static str,
    defaults: &'static [&'static str],
) -> ActionInfo {
    ActionInfo {
        action,
        name,
        description,
        group,
        defaults,
        context: Context::Normal,
    }
}

pub const ACTIONS: &[ActionInfo] = &[
    info(
        Action::Up,
        "up",
        "Navigate",
        "Move selection up",
        &["up", "k"],
    ),
    info(
        Action::Down,
        "down",
        "Navigate",
        "Move selection down",
        &["down", "j"],
    ),
    info(
        Action::PageUp,
        "page_up",
        "Navigate",
        "Move up one page",
        &["pageup"],
    ),
    info(
        Action::PageDown,
        "page_down",
        "Navigate",
        "Move down one page",
        &["pagedown"],
    ),
    info(
        Action::Top,
        "top",
        "Navigate",
        "Jump to first entry",
        &["home", "g"],
    ),
    info(
        Action::Bottom,
        "bottom",
        "Navigate",
        "Jump to last entry",
        &["end", "G"],
    ),
    info(
        Action::ScopeNext,
        "scope_next",
        "Navigate",
        "Next project scope",
        &["right", "l", "p"],
    ),
    info(
        Action::ScopePrev,
        "scope_prev",
        "Navigate",
        "Previous project scope",
        &["left", "h"],
    ),
    info(
        Action::Search,
        "search",
        "Navigate",
        "Search names, projects, tags, notes",
        &["/", "ctrl+f"],
    ),
    info(
        Action::ExtendUp,
        "extend_up",
        "Select",
        "Extend selection up",
        &["shift+up", "K"],
    ),
    info(
        Action::ExtendDown,
        "extend_down",
        "Select",
        "Extend selection down",
        &["shift+down", "J"],
    ),
    info(
        Action::TogglePin,
        "toggle_pin",
        "Select",
        "Pin/unpin entry and advance",
        &["tab", "backtab"],
    ),
    info(
        Action::Clear,
        "clear",
        "Select",
        "Clear selection, then search",
        &["esc"],
    ),
    info(
        Action::Copy,
        "copy",
        "Secrets",
        "Copy value (auto-clears clipboard)",
        &["c", "y"],
    ),
    info(
        Action::Reveal,
        "reveal",
        "Secrets",
        "Reveal/mask entry (or selection)",
        &["space", "v"],
    ),
    info(
        Action::RevealAll,
        "reveal_all",
        "Secrets",
        "Reveal/mask all visible",
        &["V", "*", "shift+space"],
    ),
    info(Action::Add, "add", "Secrets", "Add a secret", &["a"]),
    info(
        Action::Edit,
        "edit",
        "Secrets",
        "Edit entry (bulk edit selection)",
        &["e", "enter"],
    ),
    info(
        Action::Delete,
        "delete",
        "Secrets",
        "Delete entry (or selection)",
        &["d", "delete"],
    ),
    info(
        Action::Import,
        "import",
        "Files",
        "Import a .env file",
        &["i"],
    ),
    info(
        Action::Export,
        "export",
        "Files",
        "Export visible/selected to .env",
        &["X"],
    ),
    info(
        Action::Help,
        "help",
        "Session",
        "Show keybindings",
        &["?", "ctrl+k"],
    ),
    info(
        Action::Lock,
        "lock",
        "Session",
        "Lock vault and quit",
        &["L"],
    ),
    info(
        Action::Quit,
        "quit",
        "Session",
        "Quit (session stays unlocked)",
        &["q"],
    ),
    ActionInfo {
        context: Context::Form,
        ..info(
            Action::FormSave,
            "form_save",
            "Forms",
            "Save the open form",
            &["ctrl+s"],
        )
    },
    ActionInfo {
        context: Context::Form,
        ..info(
            Action::FormToggleMask,
            "form_toggle_mask",
            "Forms",
            "Show/hide the secret being typed",
            &["ctrl+v", "ctrl+r"],
        )
    },
];

impl Action {
    pub const ALL: &'static [Action] = &[
        Action::Up,
        Action::Down,
        Action::PageUp,
        Action::PageDown,
        Action::Top,
        Action::Bottom,
        Action::ScopeNext,
        Action::ScopePrev,
        Action::Search,
        Action::ExtendUp,
        Action::ExtendDown,
        Action::TogglePin,
        Action::Clear,
        Action::Copy,
        Action::Reveal,
        Action::RevealAll,
        Action::Add,
        Action::Edit,
        Action::Delete,
        Action::Import,
        Action::Export,
        Action::Help,
        Action::Lock,
        Action::Quit,
        Action::FormSave,
        Action::FormToggleMask,
    ];

    pub fn info(self) -> &'static ActionInfo {
        ACTIONS
            .iter()
            .find(|i| i.action == self)
            .expect("every action has info")
    }

    pub fn config_name(self) -> &'static str {
        self.info().name
    }

    pub fn description(self) -> &'static str {
        self.info().description
    }

    pub fn from_config_name(name: &str) -> Option<Action> {
        let name = name.trim().to_ascii_lowercase().replace('-', "_");
        ACTIONS.iter().find(|i| i.name == name).map(|i| i.action)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeySpec {
    pub code: KeyCode,
    pub mods: KeyModifiers,
}

impl KeySpec {
    /// Canonical form so that "V", "shift+v" and a terminal's Shift+V event
    /// all compare equal, and Ctrl+letter ignores case.
    fn normalized(code: KeyCode, mods: KeyModifiers) -> Self {
        let mut mods = mods & (KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SHIFT);
        let code = match code {
            KeyCode::Char(c) if c != ' ' => {
                let c = if mods.contains(KeyModifiers::SHIFT) && c.is_ascii_lowercase() {
                    c.to_ascii_uppercase()
                } else {
                    c
                };
                mods.remove(KeyModifiers::SHIFT);
                if mods.contains(KeyModifiers::CONTROL) {
                    KeyCode::Char(c.to_ascii_lowercase())
                } else {
                    KeyCode::Char(c)
                }
            }
            KeyCode::BackTab => {
                mods.remove(KeyModifiers::SHIFT);
                KeyCode::BackTab
            }
            other => other,
        };
        Self { code, mods }
    }

    pub fn from_event(key: &KeyEvent) -> Self {
        Self::normalized(key.code, key.modifiers)
    }

    pub fn parse(spec: &str) -> Result<Self, String> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err("empty key".to_string());
        }
        let (mod_parts, key_part) = if spec == "+" {
            (Vec::new(), "+")
        } else if let Some(stripped) = spec.strip_suffix("++") {
            (stripped.split('+').collect(), "+")
        } else {
            let mut parts: Vec<&str> = spec.split('+').collect();
            let key = parts.pop().unwrap_or_default();
            (parts, key)
        };

        let mut mods = KeyModifiers::empty();
        for m in mod_parts.iter().filter(|m| !m.is_empty()) {
            match m.trim().to_ascii_lowercase().as_str() {
                "ctrl" | "control" => mods |= KeyModifiers::CONTROL,
                "alt" | "meta" | "option" => mods |= KeyModifiers::ALT,
                "shift" => mods |= KeyModifiers::SHIFT,
                other => return Err(format!("unknown modifier '{other}' in '{spec}'")),
            }
        }

        let lower = key_part.to_ascii_lowercase();
        let code = match lower.as_str() {
            "space" | "spc" => KeyCode::Char(' '),
            "enter" | "return" | "ret" => KeyCode::Enter,
            "esc" | "escape" => KeyCode::Esc,
            "tab" => KeyCode::Tab,
            "backtab" => KeyCode::BackTab,
            "backspace" | "bs" => KeyCode::Backspace,
            "delete" | "del" => KeyCode::Delete,
            "insert" | "ins" => KeyCode::Insert,
            "up" => KeyCode::Up,
            "down" => KeyCode::Down,
            "left" => KeyCode::Left,
            "right" => KeyCode::Right,
            "home" => KeyCode::Home,
            "end" => KeyCode::End,
            "pageup" | "pgup" => KeyCode::PageUp,
            "pagedown" | "pgdn" | "pgdown" => KeyCode::PageDown,
            f if f.len() >= 2
                && f.starts_with('f')
                && f[1..].parse::<u8>().is_ok_and(|n| (1..=24).contains(&n)) =>
            {
                KeyCode::F(f[1..].parse().unwrap())
            }
            _ => {
                let mut chars = key_part.chars();
                match (chars.next(), chars.next()) {
                    (Some(c), None) => KeyCode::Char(c),
                    _ => return Err(format!("unknown key '{key_part}' in '{spec}'")),
                }
            }
        };
        if code == KeyCode::Tab && mods.contains(KeyModifiers::SHIFT) {
            return Ok(Self::normalized(KeyCode::BackTab, mods));
        }
        Ok(Self::normalized(code, mods))
    }

    pub fn label(&self) -> String {
        let mut out = String::new();
        if self.mods.contains(KeyModifiers::CONTROL) {
            out.push_str("Ctrl+");
        }
        if self.mods.contains(KeyModifiers::ALT) {
            out.push_str("Alt+");
        }
        if self.mods.contains(KeyModifiers::SHIFT) {
            out.push_str("Shift+");
        }
        let key = match self.code {
            KeyCode::Char(' ') => "Space".to_string(),
            KeyCode::Char(c) if self.mods.contains(KeyModifiers::CONTROL) => {
                c.to_ascii_uppercase().to_string()
            }
            KeyCode::Char(c) => c.to_string(),
            KeyCode::Enter => "Enter".into(),
            KeyCode::Esc => "Esc".into(),
            KeyCode::Tab => "Tab".into(),
            KeyCode::BackTab => "Shift+Tab".into(),
            KeyCode::Backspace => "Backspace".into(),
            KeyCode::Delete => "Del".into(),
            KeyCode::Insert => "Ins".into(),
            KeyCode::Up => "Up".into(),
            KeyCode::Down => "Down".into(),
            KeyCode::Left => "Left".into(),
            KeyCode::Right => "Right".into(),
            KeyCode::Home => "Home".into(),
            KeyCode::End => "End".into(),
            KeyCode::PageUp => "PgUp".into(),
            KeyCode::PageDown => "PgDn".into(),
            KeyCode::F(n) => format!("F{n}"),
            other => format!("{other:?}"),
        };
        out.push_str(&key);
        out
    }
}

#[derive(Debug, Clone)]
pub struct Keymap {
    lookup: HashMap<(Context, KeySpec), Action>,
    keys: HashMap<Action, Vec<KeySpec>>,
}

impl Default for Keymap {
    fn default() -> Self {
        Self::from_config(&BTreeMap::new()).0
    }
}

impl Keymap {
    /// Defaults overridden per action by `keybindings` in config.json. Returns
    /// human-readable problems (unknown actions, bad keys, conflicts) instead
    /// of failing, so a typo never locks the user out of the TUI.
    pub fn from_config(overrides: &BTreeMap<String, KeyList>) -> (Self, Vec<String>) {
        let mut problems = Vec::new();
        let mut custom: HashMap<Action, Vec<KeySpec>> = HashMap::new();

        for (name, list) in overrides {
            let Some(action) = Action::from_config_name(name) else {
                let valid: Vec<&str> = ACTIONS.iter().map(|i| i.name).collect();
                problems.push(format!(
                    "unknown action '{name}' (valid: {})",
                    valid.join(", ")
                ));
                continue;
            };
            let mut specs = Vec::new();
            let mut ok = true;
            for raw in list.specs() {
                match KeySpec::parse(raw) {
                    Ok(spec)
                        if spec
                            == KeySpec::normalized(KeyCode::Char('c'), KeyModifiers::CONTROL) =>
                    {
                        problems.push(format!("{name}: Ctrl+C is reserved for quitting"));
                    }
                    Ok(spec) => specs.push(spec),
                    Err(e) => {
                        problems.push(format!("{name}: {e}"));
                        ok = false;
                    }
                }
            }
            if ok {
                custom.insert(action, specs);
            }
        }

        let mut lookup: HashMap<(Context, KeySpec), Action> = HashMap::new();
        let mut keys: HashMap<Action, Vec<KeySpec>> = HashMap::new();
        // Custom bindings claim their keys first, then defaults fill the gaps.
        let mut bind =
            |action: Action, spec: KeySpec, is_custom: bool, problems: &mut Vec<String>| {
                let ctx = action.info().context;
                match lookup.get(&(ctx, spec)) {
                    Some(&owner) if owner != action => {
                        if is_custom {
                            problems.push(format!(
                                "key '{}' is bound to both '{}' and '{}'; keeping '{}'",
                                spec.label(),
                                owner.config_name(),
                                action.config_name(),
                                owner.config_name()
                            ));
                        }
                    }
                    Some(_) => {}
                    None => {
                        lookup.insert((ctx, spec), action);
                        keys.entry(action).or_default().push(spec);
                    }
                }
            };

        for info in ACTIONS {
            if let Some(specs) = custom.get(&info.action) {
                for &spec in specs {
                    bind(info.action, spec, true, &mut problems);
                }
            }
        }
        for info in ACTIONS {
            if custom.contains_key(&info.action) {
                continue;
            }
            for raw in info.defaults {
                let spec = KeySpec::parse(raw).expect("default keys parse");
                bind(info.action, spec, false, &mut problems);
            }
        }

        for info in ACTIONS {
            if matches!(info.action, Action::Quit | Action::Help)
                && keys.get(&info.action).is_none_or(Vec::is_empty)
            {
                problems.push(format!(
                    "'{}' has no key left (Ctrl+C still quits)",
                    info.name
                ));
            }
        }

        (Self { lookup, keys }, problems)
    }

    pub fn action(&self, context: Context, key: &KeyEvent) -> Option<Action> {
        self.lookup
            .get(&(context, KeySpec::from_event(key)))
            .copied()
    }

    pub fn keys(&self, action: Action) -> &[KeySpec] {
        self.keys.get(&action).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn keys_label(&self, action: Action) -> String {
        let labels: Vec<String> = self.keys(action).iter().map(KeySpec::label).collect();
        if labels.is_empty() {
            "(unbound)".to_string()
        } else {
            labels.join(" / ")
        }
    }

    pub fn first_label(&self, action: Action) -> String {
        self.keys(action)
            .first()
            .map(KeySpec::label)
            .unwrap_or_else(|| "-".to_string())
    }
}
