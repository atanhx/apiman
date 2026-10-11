use ratatui::style::{Color, Modifier, Style};

#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub accent: Color,
    pub accent_soft: Color,
    pub danger: Color,
    pub success: Color,
    pub text: Color,
    pub muted: Color,
    pub border: Color,
    pub selected_bg: Color,
    pub marked_bg: Color,
    pub on_accent: Color,
}

pub const THEMES: &[&str] = &["ember", "ocean", "forest", "mono"];

impl Theme {
    pub fn ember() -> Self {
        Self {
            accent: Color::Rgb(255, 135, 50),
            accent_soft: Color::Rgb(255, 196, 92),
            danger: Color::Rgb(240, 82, 72),
            success: Color::Rgb(122, 204, 120),
            text: Color::Rgb(236, 230, 224),
            muted: Color::Rgb(150, 136, 128),
            border: Color::Rgb(112, 74, 60),
            selected_bg: Color::Rgb(66, 34, 24),
            marked_bg: Color::Rgb(48, 34, 22),
            on_accent: Color::Rgb(20, 14, 10),
        }
    }

    pub fn ocean() -> Self {
        Self {
            accent: Color::Rgb(86, 182, 255),
            accent_soft: Color::Rgb(128, 222, 234),
            danger: Color::Rgb(255, 107, 107),
            success: Color::Rgb(126, 214, 160),
            text: Color::Rgb(226, 232, 240),
            muted: Color::Rgb(128, 144, 166),
            border: Color::Rgb(58, 82, 112),
            selected_bg: Color::Rgb(22, 44, 72),
            marked_bg: Color::Rgb(18, 34, 52),
            on_accent: Color::Rgb(8, 16, 28),
        }
    }

    pub fn forest() -> Self {
        Self {
            accent: Color::Rgb(134, 210, 116),
            accent_soft: Color::Rgb(214, 220, 128),
            danger: Color::Rgb(236, 96, 86),
            success: Color::Rgb(134, 210, 116),
            text: Color::Rgb(228, 234, 222),
            muted: Color::Rgb(136, 150, 128),
            border: Color::Rgb(70, 96, 64),
            selected_bg: Color::Rgb(30, 54, 30),
            marked_bg: Color::Rgb(26, 40, 24),
            on_accent: Color::Rgb(12, 20, 10),
        }
    }

    /// Terminal default colors only; used for NO_COLOR as well.
    pub fn mono() -> Self {
        Self {
            accent: Color::Reset,
            accent_soft: Color::Reset,
            danger: Color::Reset,
            success: Color::Reset,
            text: Color::Reset,
            muted: Color::DarkGray,
            border: Color::DarkGray,
            selected_bg: Color::Reset,
            marked_bg: Color::Reset,
            on_accent: Color::Reset,
        }
    }

    pub fn is_mono(&self) -> bool {
        self.accent == Color::Reset
    }

    /// Theme named in config; unknown names fall back to ember with a note.
    pub fn from_config(name: &str) -> (Self, Option<String>) {
        if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
            return (Self::mono(), None);
        }
        match name.trim().to_ascii_lowercase().as_str() {
            "" | "ember" => (Self::ember(), None),
            "ocean" => (Self::ocean(), None),
            "forest" => (Self::forest(), None),
            "mono" => (Self::mono(), None),
            other => (
                Self::ember(),
                Some(format!(
                    "unknown theme '{other}' (available: {})",
                    THEMES.join(", ")
                )),
            ),
        }
    }

    pub fn text(&self) -> Style {
        Style::default().fg(self.text)
    }

    pub fn muted(&self) -> Style {
        Style::default().fg(self.muted)
    }

    pub fn accent(&self) -> Style {
        Style::default()
            .fg(self.accent)
            .add_modifier(Modifier::BOLD)
    }

    pub fn key(&self) -> Style {
        Style::default()
            .fg(self.accent_soft)
            .add_modifier(Modifier::BOLD)
    }

    pub fn badge(&self, bg: Color) -> Style {
        if self.is_mono() {
            Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
        } else {
            Style::default()
                .fg(self.on_accent)
                .bg(bg)
                .add_modifier(Modifier::BOLD)
        }
    }

    pub fn selected_row(&self) -> Style {
        if self.is_mono() {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default()
                .bg(self.selected_bg)
                .fg(self.text)
                .add_modifier(Modifier::BOLD)
        }
    }

    pub fn marked_row(&self) -> Style {
        if self.is_mono() {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            Style::default().bg(self.marked_bg).fg(self.text)
        }
    }
}
