use crate::tui::app::{ActiveModal, App};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Row, Table},
    Frame,
};

const ACCENT_ORANGE: Color = Color::Rgb(255, 130, 40);
const ACCENT_RED: Color = Color::Rgb(235, 60, 50);
const ACCENT_AMBER: Color = Color::Rgb(255, 190, 70);
const BORDER_WARM: Color = Color::Rgb(140, 80, 65);
const ROW_HIGHLIGHT_BG: Color = Color::Rgb(55, 25, 20);

pub fn render(frame: &mut Frame, app: &App) {
    let size = frame.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(5),    // Table
            Constraint::Length(3), // Footer / Status Bar
        ])
        .split(size);

    render_header(frame, app, chunks[0]);
    render_table(frame, app, chunks[1]);
    render_footer(frame, app, chunks[2]);

    match &app.active_modal {
        ActiveModal::KeybindingsHelp => render_help_modal(frame),
        ActiveModal::Add | ActiveModal::Edit(_) => render_form_modal(frame, app),
        ActiveModal::DeleteConfirm(_) => render_delete_modal(frame, app),
        _ => {}
    }
}

fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let proj_label = app.project_filter.as_deref().unwrap_or("all");
    let total_count = app.ctx.vault.entries.len();
    let filtered_count = app.filtered_indices.len();

    let header_text = vec![Line::from(vec![
        Span::styled(
            " APIMAN ",
            Style::default()
                .fg(Color::Black)
                .bg(ACCENT_ORANGE)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("  Vault: ", Style::default().fg(Color::White)),
        Span::styled(
            app.ctx.vault_path.display().to_string(),
            Style::default()
                .fg(ACCENT_AMBER)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" | Scope: ", Style::default().fg(Color::White)),
        Span::styled(
            format!("[{proj_label}]"),
            Style::default()
                .fg(ACCENT_ORANGE)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" | Entries: ", Style::default().fg(Color::White)),
        Span::styled(
            format!("{filtered_count}/{total_count}"),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" | State: ", Style::default().fg(Color::White)),
        Span::styled(
            if app.ctx.config.auto_lock_timeout_seconds == 0 {
                "Unlocked (Always)"
            } else {
                "Unlocked"
            },
            Style::default()
                .fg(ACCENT_AMBER)
                .add_modifier(Modifier::BOLD),
        ),
    ])];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER_WARM));

    let paragraph = Paragraph::new(header_text).block(block);
    frame.render_widget(paragraph, area);
}

fn render_table(frame: &mut Frame, app: &App, area: Rect) {
    let header_cells = ["NAME", "PROJECT", "SECRET VALUE", "TAGS", "DESCRIPTION"]
        .iter()
        .map(|h| {
            Span::styled(
                *h,
                Style::default()
                    .fg(ACCENT_ORANGE)
                    .add_modifier(Modifier::BOLD),
            )
        });
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    let rows: Vec<Row> = app
        .filtered_indices
        .iter()
        .enumerate()
        .map(|(display_idx, &real_idx)| {
            let entry = &app.ctx.vault.entries[real_idx];
            let is_selected = display_idx == app.selected_index;
            let is_revealed = app.revealed_entries.contains(&entry.id);

            let val_str = if is_revealed {
                entry.value.expose_secret()
            } else {
                "••••••••••••"
            };

            let proj_str = entry.project_display();
            let tags_str = if entry.tags.is_empty() {
                "-".to_string()
            } else {
                entry.tags.join(", ")
            };
            let desc_str = entry.description.as_deref().unwrap_or("-");

            let style = if is_selected {
                Style::default()
                    .bg(ROW_HIGHLIGHT_BG)
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            let name_cell = if is_selected {
                format!(">> {}", entry.name)
            } else {
                format!("   {}", entry.name)
            };

            let cells = vec![
                Span::styled(
                    name_cell,
                    if is_selected {
                        Style::default()
                            .fg(ACCENT_ORANGE)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    },
                ),
                Span::styled(
                    proj_str,
                    if entry.is_global() {
                        Style::default().fg(Color::White)
                    } else {
                        Style::default()
                            .fg(ACCENT_RED)
                            .add_modifier(Modifier::BOLD)
                    },
                ),
                Span::styled(
                    val_str,
                    if is_revealed {
                        Style::default()
                            .fg(ACCENT_AMBER)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    },
                ),
                Span::styled(tags_str, Style::default().fg(ACCENT_ORANGE)),
                Span::styled(desc_str, Style::default().fg(Color::White)),
            ];

            Row::new(cells).style(style)
        })
        .collect();

    let widths = [
        Constraint::Percentage(25),
        Constraint::Percentage(15),
        Constraint::Percentage(25),
        Constraint::Percentage(15),
        Constraint::Percentage(20),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER_WARM))
        .title(Span::styled(
            " Secrets Catalog ",
            Style::default()
                .fg(ACCENT_ORANGE)
                .add_modifier(Modifier::BOLD),
        ));

    let table = Table::new(rows, widths).header(header).block(block);
    frame.render_widget(table, area);
}

fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    let content = if app.active_modal == ActiveModal::Search {
        Line::from(vec![
            Span::styled(
                " SEARCH: ",
                Style::default()
                    .fg(Color::Black)
                    .bg(ACCENT_ORANGE)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(
                &app.search_query,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("█", Style::default().fg(ACCENT_ORANGE)),
            Span::styled(
                "  [Enter] Confirm | [Esc] Clear",
                Style::default().fg(Color::White),
            ),
        ])
    } else if let Some(toast) = app.status_text() {
        Line::from(vec![
            Span::styled(
                " INFO: ",
                Style::default()
                    .fg(Color::Black)
                    .bg(ACCENT_ORANGE)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(
                toast,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ])
    } else if !app.search_query.is_empty() {
        Line::from(vec![
            Span::styled(
                format!(" Filter: '{}' (Esc to clear) ", app.search_query),
                Style::default()
                    .fg(ACCENT_ORANGE)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" | "),
            Span::styled(
                "[Ctrl+K] Help | [c] Copy | [Space] Reveal | [a] Add | [e] Edit | [d] Delete | [q] Quit",
                Style::default().fg(Color::White),
            ),
        ])
    } else {
        Line::from(vec![
            Span::styled(
                "[Ctrl+K]",
                Style::default()
                    .fg(ACCENT_ORANGE)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Help ", Style::default().fg(Color::White)),
            Span::styled(
                "[Ctrl+F]",
                Style::default()
                    .fg(ACCENT_ORANGE)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Search ", Style::default().fg(Color::White)),
            Span::styled(
                "[c]",
                Style::default()
                    .fg(ACCENT_ORANGE)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Copy ", Style::default().fg(Color::White)),
            Span::styled(
                "[Space]",
                Style::default()
                    .fg(ACCENT_ORANGE)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Reveal ", Style::default().fg(Color::White)),
            Span::styled(
                "[a]",
                Style::default()
                    .fg(ACCENT_ORANGE)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Add ", Style::default().fg(Color::White)),
            Span::styled(
                "[e]",
                Style::default()
                    .fg(ACCENT_ORANGE)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Edit ", Style::default().fg(Color::White)),
            Span::styled(
                "[d]",
                Style::default()
                    .fg(ACCENT_ORANGE)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Del ", Style::default().fg(Color::White)),
            Span::styled(
                "[p]",
                Style::default()
                    .fg(ACCENT_ORANGE)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Scope ", Style::default().fg(Color::White)),
            Span::styled(
                "[l]",
                Style::default()
                    .fg(ACCENT_ORANGE)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Lock ", Style::default().fg(Color::White)),
            Span::styled(
                "[q]",
                Style::default()
                    .fg(ACCENT_ORANGE)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Quit", Style::default().fg(Color::White)),
        ])
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER_WARM));

    let paragraph = Paragraph::new(content).block(block);
    frame.render_widget(paragraph, area);
}

fn render_help_modal(frame: &mut Frame) {
    let area = centered_rect(62, 70, frame.area());
    frame.render_widget(Clear, area);

    let shortcuts = vec![
        Line::from(vec![Span::styled(
            "Navigation & Search",
            Style::default()
                .fg(ACCENT_ORANGE)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(Span::styled("  j / Down       Move selection down", Style::default().fg(Color::White))),
        Line::from(Span::styled("  k / Up         Move selection up", Style::default().fg(Color::White))),
        Line::from(Span::styled("  Ctrl+F or /    Filter/Search entries across names, tags, projects", Style::default().fg(Color::White))),
        Line::from(Span::styled("  p              Cycle project scope filter (All -> Global -> Projects)", Style::default().fg(Color::White))),
        Line::from(Span::styled("  Esc            Clear active search filter", Style::default().fg(Color::White))),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Secret Actions",
            Style::default()
                .fg(ACCENT_ORANGE)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(Span::styled("  c              Copy selected secret value to clipboard", Style::default().fg(Color::White))),
        Line::from(Span::styled("  Space / v      Toggle masked (••••) vs plaintext reveal", Style::default().fg(Color::White))),
        Line::from(Span::styled("  a              Open Add Secret form modal", Style::default().fg(Color::White))),
        Line::from(Span::styled("  e              Edit selected secret details", Style::default().fg(Color::White))),
        Line::from(Span::styled("  d              Delete selected secret (with confirmation)", Style::default().fg(Color::White))),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Session & Password Management",
            Style::default()
                .fg(ACCENT_ORANGE)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(Span::styled("  l              Lock vault and terminate background daemon", Style::default().fg(Color::White))),
        Line::from(Span::styled("  apiman passwd  Change master password (run from shell)", Style::default().fg(ACCENT_AMBER))),
        Line::from(Span::styled("  Ctrl+K or ?    Show this help modal", Style::default().fg(Color::White))),
        Line::from(Span::styled("  q / Ctrl+C     Exit TUI (session remains unlocked until auto-lock)", Style::default().fg(Color::White))),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Press [Esc] or [Enter] to close help",
            Style::default()
                .fg(ACCENT_ORANGE)
                .add_modifier(Modifier::BOLD),
        )]),
    ];

    let block = Block::default()
        .title(" Keybindings Reference ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT_ORANGE).add_modifier(Modifier::BOLD));

    let paragraph = Paragraph::new(shortcuts).block(block);
    frame.render_widget(paragraph, area);
}

fn render_form_modal(frame: &mut Frame, app: &App) {
    let area = centered_rect(68, 80, frame.area());
    frame.render_widget(Clear, area);

    let is_edit = matches!(app.active_modal, ActiveModal::Edit(_));
    let title = if is_edit {
        " Edit Secret Entry "
    } else {
        " Add New Secret Entry "
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Name
            Constraint::Length(3), // Project
            Constraint::Length(3), // Value
            Constraint::Length(3), // Tags
            Constraint::Length(3), // Description
            Constraint::Length(2), // Help hint
        ])
        .split(area);

    let active = app.form_state.active_field;

    // Field 0: Name
    let name_block = field_block(" Name (required) ", active == 0);
    let name_text = if active == 0 {
        format!("{}█", app.form_state.name)
    } else {
        app.form_state.name.clone()
    };
    let name_widget = Paragraph::new(name_text)
        .style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .block(name_block);
    frame.render_widget(name_widget, chunks[0]);

    // Field 1: Project
    let proj_block = field_block(" Project (blank for global) ", active == 1);
    let proj_text = if active == 1 {
        format!("{}█", app.form_state.project)
    } else {
        app.form_state.project.clone()
    };
    let proj_widget = Paragraph::new(proj_text)
        .style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .block(proj_block);
    frame.render_widget(proj_widget, chunks[1]);

    // Field 2: Value
    let val_label = if app.form_state.show_secret {
        " Secret Value [Plaintext visible - Ctrl+V to mask] "
    } else {
        " Secret Value [Masked - Ctrl+V to reveal] "
    };
    let val_block = field_block(val_label, active == 2);
    let display_val = if app.form_state.show_secret {
        if active == 2 {
            format!("{}█", app.form_state.value)
        } else {
            app.form_state.value.clone()
        }
    } else {
        let stars = "*".repeat(app.form_state.value.len());
        if active == 2 {
            format!("{stars}█")
        } else {
            stars
        }
    };
    let val_widget = Paragraph::new(display_val)
        .style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .block(val_block);
    frame.render_widget(val_widget, chunks[2]);

    // Field 3: Tags
    let tags_block = field_block(" Tags (comma separated) ", active == 3);
    let tags_text = if active == 3 {
        format!("{}█", app.form_state.tags)
    } else {
        app.form_state.tags.clone()
    };
    let tags_widget = Paragraph::new(tags_text)
        .style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .block(tags_block);
    frame.render_widget(tags_widget, chunks[3]);

    // Field 4: Description
    let desc_block = field_block(" Description / Notes ", active == 4);
    let desc_text = if active == 4 {
        format!("{}█", app.form_state.description)
    } else {
        app.form_state.description.clone()
    };
    let desc_widget = Paragraph::new(desc_text)
        .style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .block(desc_block);
    frame.render_widget(desc_widget, chunks[4]);

    // Hints
    let hints = Line::from(vec![
        Span::styled(
            "[Tab/Down]",
            Style::default()
                .fg(ACCENT_ORANGE)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Next | ", Style::default().fg(Color::White)),
        Span::styled(
            "[Shift+Tab/Up]",
            Style::default()
                .fg(ACCENT_ORANGE)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Prev | ", Style::default().fg(Color::White)),
        Span::styled(
            "[Ctrl+V]",
            Style::default()
                .fg(ACCENT_AMBER)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Mask/Reveal | ", Style::default().fg(Color::White)),
        Span::styled(
            "[Ctrl+S/Enter]",
            Style::default()
                .fg(ACCENT_ORANGE)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Save | ", Style::default().fg(Color::White)),
        Span::styled(
            "[Esc]",
            Style::default()
                .fg(ACCENT_RED)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Cancel", Style::default().fg(Color::White)),
    ]);
    frame.render_widget(
        Paragraph::new(hints).alignment(Alignment::Center),
        chunks[5],
    );

    let outer_block = Block::default()
        .title(Span::styled(
            title,
            Style::default()
                .fg(ACCENT_ORANGE)
                .add_modifier(Modifier::BOLD),
        ))
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT_ORANGE).add_modifier(Modifier::BOLD));
    frame.render_widget(outer_block, area);
}

fn field_block(title: &'static str, is_active: bool) -> Block<'static> {
    if is_active {
        Block::default()
            .title(Span::styled(
                title,
                Style::default()
                    .fg(ACCENT_ORANGE)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(
                Style::default()
                    .fg(ACCENT_ORANGE)
                    .add_modifier(Modifier::BOLD),
            )
    } else {
        Block::default()
            .title(Span::styled(
                title,
                Style::default().fg(Color::White),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER_WARM))
    }
}

fn render_delete_modal(frame: &mut Frame, app: &App) {
    let area = centered_rect(50, 25, frame.area());
    frame.render_widget(Clear, area);

    let name = if let ActiveModal::DeleteConfirm(real_idx) = app.active_modal {
        app.ctx
            .vault
            .entries
            .get(real_idx)
            .map(|e| e.name.as_str())
            .unwrap_or("")
    } else {
        ""
    };

    let text = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("Permanently delete secret '", Style::default().fg(Color::White)),
            Span::styled(
                name,
                Style::default()
                    .fg(ACCENT_ORANGE)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("' ?", Style::default().fg(Color::White)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                " [y] Confirm Delete ",
                Style::default()
                    .fg(Color::White)
                    .bg(ACCENT_RED)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("   "),
            Span::styled(
                " [n / Esc] Cancel ",
                Style::default().fg(Color::Black).bg(Color::White),
            ),
        ]),
    ];

    let block = Block::default()
        .title(Span::styled(
            " Confirm Deletion ",
            Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD),
        ))
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD));

    let paragraph = Paragraph::new(text).alignment(Alignment::Center).block(block);
    frame.render_widget(paragraph, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
