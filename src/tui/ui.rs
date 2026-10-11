use crate::tui::app::{ActiveModal, App, FORM_VALUE_FIELD, TextField, ToastKind};
use crate::tui::keymap::{ACTIONS, Action};
use crate::tui::theme::Theme;
use crate::vault::{SecretEntry, SecretRef};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Margin, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Cell, Clear, Padding, Paragraph, Row, Scrollbar,
        ScrollbarOrientation, ScrollbarState, Table, TableState, Wrap,
    },
};

const MASK: &str = "**********";

pub fn render(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let t = &app.theme;
    frame.render_widget(Block::default().style(t.text()), area);

    let show_details = area.height >= 22;
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(5),
            Constraint::Length(if show_details { 5 } else { 0 }),
            Constraint::Length(1),
        ])
        .split(area);

    render_header(frame, app, chunks[0]);
    render_scope_bar(frame, app, chunks[1]);
    render_table(frame, app, chunks[2]);
    if show_details {
        render_details(frame, app, chunks[3]);
    }
    render_footer(frame, app, chunks[4]);

    match &app.active_modal {
        ActiveModal::KeybindingsHelp => render_help_modal(frame, app),
        ActiveModal::Add | ActiveModal::Edit(_) => render_form_modal(frame, app),
        ActiveModal::BulkEdit => render_bulk_modal(frame, app),
        ActiveModal::DeleteConfirm(ids) => render_delete_modal(frame, app, ids),
        ActiveModal::Import | ActiveModal::Export => render_path_modal(frame, app),
        ActiveModal::None | ActiveModal::Search => {}
    }
}

fn shorten_home(path: &std::path::Path) -> String {
    let s = path.display().to_string();
    match std::env::var("HOME") {
        Ok(home) if !home.is_empty() && s.starts_with(&home) => format!("~{}", &s[home.len()..]),
        _ => s,
    }
}

fn relative_time(ts: u64) -> String {
    let now = crate::vault::current_timestamp();
    let d = now.saturating_sub(ts);
    match d {
        0..60 => "just now".to_string(),
        60..3600 => format!("{}m ago", d / 60),
        3600..86400 => format!("{}h ago", d / 3600),
        86400..2_592_000 => format!("{}d ago", d / 86400),
        _ => format!("{}mo ago", d / 2_592_000),
    }
}

/// Single-line view of `value` for table cells: newlines are shown as `\n`.
fn one_line(value: &str) -> String {
    value.replace('\n', "\\n").replace('\r', "")
}

fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let left = Line::from(vec![
        Span::styled(" apiman ", t.badge(t.accent)),
        Span::raw("  "),
        Span::styled(shorten_home(&app.ctx.vault_path), t.muted()),
    ]);
    frame.render_widget(Paragraph::new(left), area);

    let state = match app.lock_countdown() {
        None => Span::styled("unlocked, auto-lock off ", Style::default().fg(t.success)),
        Some(s) if s < 60 => Span::styled(
            format!("locking in {s}s "),
            Style::default().fg(t.danger).add_modifier(Modifier::BOLD),
        ),
        Some(s) => Span::styled(
            format!(
                "unlocked, auto-lock in {} ",
                crate::cli::format_duration_short(s.div_ceil(60) * 60)
            ),
            Style::default().fg(t.success),
        ),
    };
    frame.render_widget(
        Paragraph::new(Line::from(state)).alignment(Alignment::Right),
        area,
    );
}

fn render_scope_bar(frame: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let current = app.project_filter.as_deref().unwrap_or("all");
    let mut spans = vec![Span::styled(" scope ", t.muted())];
    for opt in app.scope_options() {
        let style = if opt.eq_ignore_ascii_case(current) {
            t.badge(t.accent_soft)
        } else {
            t.muted()
        };
        spans.push(Span::styled(format!(" {opt} "), style));
        spans.push(Span::raw(" "));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);

    let mut right = vec![];
    if !app.search_query.is_empty() && app.active_modal != ActiveModal::Search {
        right.push(Span::styled(
            format!("filter \"{}\"  ", app.search_query.text),
            t.key(),
        ));
    }
    right.push(Span::styled(
        format!(
            "{} / {} shown",
            app.filtered_indices.len(),
            app.ctx.vault.entries.len()
        ),
        t.muted(),
    ));
    if app.in_group_mode() {
        right.push(Span::raw("  "));
        right.push(Span::styled(
            format!(" {} selected ", app.marked.len()),
            t.badge(t.accent),
        ));
    }
    right.push(Span::raw(" "));
    frame.render_widget(
        Paragraph::new(Line::from(right)).alignment(Alignment::Right),
        area,
    );
}

fn panel<'a>(t: &Theme, title: impl Into<Line<'a>>) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(t.border))
        .title(title)
}

fn render_table(frame: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let position = if app.filtered_indices.is_empty() {
        String::new()
    } else {
        format!(
            " {}/{} ",
            app.selected_index + 1,
            app.filtered_indices.len()
        )
    };
    let block = panel(t, Line::from(Span::styled(" Secrets ", t.accent())))
        .title_bottom(Line::from(Span::styled(position, t.muted())).right_aligned());

    if app.filtered_indices.is_empty() {
        let (title, hint) = if app.ctx.vault.entries.is_empty() {
            (
                "No secrets yet",
                format!(
                    "Press {} to add one, or {} to import a .env file",
                    app.keymap.first_label(Action::Add),
                    app.keymap.first_label(Action::Import)
                ),
            )
        } else {
            (
                "Nothing matches",
                format!(
                    "{} clears the search or scope, {} changes scope",
                    app.keymap.first_label(Action::Clear),
                    app.keymap.first_label(Action::ScopeNext)
                ),
            )
        };
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let y = inner.y + inner.height.saturating_sub(2) / 2;
        let text = vec![
            Line::from(Span::styled(title, t.accent())),
            Line::from(Span::styled(hint, t.muted())),
        ];
        frame.render_widget(
            Paragraph::new(text).alignment(Alignment::Center),
            Rect::new(inner.x, y, inner.width, 2.min(inner.height)),
        );
        return;
    }

    let wide = area.width >= 90;
    let header_cells: Vec<&str> = if wide {
        vec!["  NAME", "SCOPE", "VALUE", "TAGS", "UPDATED"]
    } else {
        vec!["  NAME", "SCOPE", "VALUE"]
    };
    let header = Row::new(
        header_cells
            .into_iter()
            .map(|h| Cell::from(Span::styled(h, t.accent()))),
    )
    .height(1)
    .bottom_margin(0);

    let rows: Vec<Row> = app
        .filtered_indices
        .iter()
        .enumerate()
        .map(|(pos, &real_idx)| {
            let entry = &app.ctx.vault.entries[real_idx];
            let selected = pos == app.selected_index;
            let marked = app.marked.contains(&entry.id);
            let revealed = app.revealed_entries.contains(&entry.id);

            let marker = match (selected, marked) {
                (true, true) => Span::styled(">+", t.accent()),
                (true, false) => Span::styled("> ", t.accent()),
                (false, true) => Span::styled(" +", t.accent()),
                _ => Span::raw("  "),
            };
            let name = Line::from(vec![
                marker,
                Span::styled(
                    entry.name.clone(),
                    if selected || marked {
                        t.accent()
                    } else {
                        t.text()
                    },
                ),
            ]);
            let scope = Span::styled(
                entry.project_display().to_string(),
                if entry.is_global() {
                    t.muted()
                } else {
                    Style::default().fg(t.accent_soft)
                },
            );
            let value = if revealed {
                Span::styled(
                    one_line(entry.value.expose_secret()),
                    Style::default()
                        .fg(t.accent_soft)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled(MASK, t.muted())
            };
            let mut cells = vec![Cell::from(name), Cell::from(scope), Cell::from(value)];
            if wide {
                let tags = if entry.tags.is_empty() {
                    "-".to_string()
                } else {
                    entry.tags.join(", ")
                };
                cells.push(Cell::from(Span::styled(tags, t.muted())));
                cells.push(Cell::from(Span::styled(
                    relative_time(entry.updated_at),
                    t.muted(),
                )));
            }
            let style = if selected {
                t.selected_row()
            } else if marked {
                t.marked_row()
            } else {
                Style::default()
            };
            Row::new(cells).style(style)
        })
        .collect();

    let widths: Vec<Constraint> = if wide {
        vec![
            Constraint::Percentage(30),
            Constraint::Percentage(14),
            Constraint::Percentage(30),
            Constraint::Percentage(16),
            Constraint::Length(10),
        ]
    } else {
        vec![
            Constraint::Percentage(45),
            Constraint::Percentage(20),
            Constraint::Percentage(35),
        ]
    };

    let mut state = TableState::default()
        .with_offset(app.table_offset.get())
        .with_selected(Some(app.selected_index));
    let table = Table::new(rows, widths)
        .header(header)
        .block(block)
        .column_spacing(1);
    frame.render_stateful_widget(table, area, &mut state);
    app.table_offset.set(state.offset());

    let visible_rows = area.height.saturating_sub(3) as usize;
    if app.filtered_indices.len() > visible_rows {
        let mut sb = ScrollbarState::new(app.filtered_indices.len().saturating_sub(visible_rows))
            .position(state.offset());
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None)
                .thumb_style(Style::default().fg(t.accent))
                .track_style(Style::default().fg(t.border)),
            area.inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut sb,
        );
    }
}

fn render_details(frame: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let block =
        panel(t, Line::from(Span::styled(" Details ", t.muted()))).padding(Padding::horizontal(1));
    let Some(e) = app.selected_entry() else {
        frame.render_widget(block, area);
        return;
    };
    let reference = SecretRef {
        project: e.project.clone(),
        name: e.name.clone(),
    }
    .to_string();
    let label = |s: &'static str| Span::styled(s, t.muted());
    let lines = vec![
        Line::from(vec![
            label("ref "),
            Span::styled(reference, t.key()),
            label("   tags "),
            Span::styled(
                if e.tags.is_empty() {
                    "-".to_string()
                } else {
                    e.tags.join(", ")
                },
                t.text(),
            ),
            label("   length "),
            Span::styled(
                format!("{}", e.value.expose_secret().chars().count()),
                t.text(),
            ),
        ]),
        Line::from(vec![
            label("note "),
            Span::styled(
                e.description.clone().unwrap_or_else(|| "-".to_string()),
                t.text(),
            ),
        ]),
        Line::from(vec![
            label("updated "),
            Span::styled(relative_time(e.updated_at), t.text()),
            label("   created "),
            Span::styled(relative_time(e.created_at), t.text()),
        ]),
    ];
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn hint_spans<'a>(t: &Theme, items: &[(String, &'a str)]) -> Vec<Span<'a>> {
    let mut spans = Vec::new();
    for (key, label) in items {
        spans.push(Span::styled(format!(" {key} "), t.key()));
        spans.push(Span::styled(format!("{label} "), t.muted()));
    }
    spans
}

fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let k = |a: Action| app.keymap.first_label(a);

    if app.active_modal == ActiveModal::Search {
        const PREFIX: &str = " search ";
        let width = area.width.saturating_sub(40) as usize;
        let (text, col) = field_view(&app.search_query, false, true, width.max(10));
        let text_len = text.chars().count();
        let mut spans = vec![
            Span::styled(PREFIX, t.badge(t.accent)),
            Span::raw(" "),
            Span::styled(text, t.text().add_modifier(Modifier::BOLD)),
            Span::raw(" ".repeat(width.max(10).saturating_sub(text_len) + 1)),
        ];
        spans.extend(hint_spans(
            t,
            &[
                ("Enter".into(), "done"),
                ("Up/Down".into(), "move"),
                ("Esc".into(), "clear"),
            ],
        ));
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
        frame.set_cursor_position((area.x + PREFIX.len() as u16 + 1 + col as u16, area.y));
        return;
    }

    if let Some((msg, kind)) = app.status() {
        let (icon, color) = match kind {
            ToastKind::Success => ("OK", t.success),
            ToastKind::Error => ("ERROR", t.danger),
            ToastKind::Info => ("INFO", t.accent_soft),
        };
        let line = Line::from(vec![
            Span::styled(format!(" {icon} "), t.badge(color)),
            Span::raw(" "),
            Span::styled(
                msg.to_string(),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
        ]);
        frame.render_widget(Paragraph::new(line), area);
        return;
    }

    let items: Vec<(String, &str)> = if app.in_group_mode() {
        vec![
            (k(Action::Edit), "bulk edit"),
            (k(Action::Delete), "delete"),
            (k(Action::Reveal), "reveal"),
            (k(Action::Export), "export"),
            (k(Action::TogglePin), "pin"),
            (k(Action::Clear), "clear"),
        ]
    } else {
        vec![
            (k(Action::Search), "search"),
            (k(Action::Copy), "copy"),
            (k(Action::Reveal), "reveal"),
            (k(Action::Add), "add"),
            (k(Action::Edit), "edit"),
            (k(Action::Delete), "delete"),
            (k(Action::ScopeNext), "scope"),
            (k(Action::Help), "help"),
            (k(Action::Quit), "quit"),
        ]
    };
    frame.render_widget(Paragraph::new(Line::from(hint_spans(t, &items))), area);
}

fn centered(width: u16, height: u16, area: Rect) -> Rect {
    let w = width.min(area.width.saturating_sub(2)).max(1);
    let h = height.min(area.height.saturating_sub(2)).max(1);
    Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    )
}

fn modal<'a>(
    frame: &mut Frame,
    t: &Theme,
    area: Rect,
    title: String,
    color: ratatui::style::Color,
) -> Block<'a> {
    frame.render_widget(Clear, area);
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(color).add_modifier(Modifier::BOLD))
        .title(
            Line::from(Span::styled(
                format!(" {title} "),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ))
            .centered(),
        )
        .style(t.text())
}

/// Visible window of a text field plus the cursor column inside it. Long
/// values (API keys, JWTs) scroll horizontally; `<` and `>` mark clipped text.
pub fn field_view(field: &TextField, mask: bool, active: bool, width: usize) -> (String, usize) {
    let chars: Vec<char> = if mask {
        vec!['*'; field.len()]
    } else {
        field
            .text
            .chars()
            .map(|c| if c == '\n' { ' ' } else { c })
            .collect()
    };
    let width = width.max(4);
    if !active {
        if chars.len() <= width {
            return (chars.iter().collect(), 0);
        }
        let mut s: String = chars[..width - 1].iter().collect();
        s.push('>');
        return (s, 0);
    }
    // Keep one cell free after the text for the cursor.
    let cursor = field.cursor.min(chars.len());
    let room = width - 1;
    let start = cursor.saturating_sub(room);
    let end = (start + room).min(chars.len());
    let mut view = chars[start..end].to_vec();
    if start > 0 {
        view[0] = '<';
    }
    if end < chars.len()
        && let Some(last) = view.last_mut()
    {
        *last = '>';
    }
    (view.into_iter().collect(), cursor - start)
}

#[allow(clippy::too_many_arguments)]
fn text_input(
    frame: &mut Frame,
    t: &Theme,
    area: Rect,
    label: &str,
    field: &TextField,
    active: bool,
    mask: bool,
    placeholder: Option<&str>,
) {
    let border = if active { t.accent } else { t.border };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(border))
        .title(Span::styled(
            format!(" {label} "),
            if active { t.accent() } else { t.muted() },
        ))
        .padding(Padding::horizontal(1));
    let inner_width = area.width.saturating_sub(4) as usize;
    let (content, col) = match placeholder {
        Some(ph) if field.is_empty() => (
            Line::from(Span::styled(
                ph.to_string(),
                t.muted().add_modifier(Modifier::ITALIC),
            )),
            0,
        ),
        _ => {
            let (text, col) = field_view(field, mask, active, inner_width);
            (
                Line::from(Span::styled(text, t.text().add_modifier(Modifier::BOLD))),
                col,
            )
        }
    };
    frame.render_widget(Paragraph::new(content).block(block), area);
    if active && area.width > 4 && area.height > 2 {
        frame.set_cursor_position((area.x + 2 + col as u16, area.y + 1));
    }
}

fn render_hints(frame: &mut Frame, t: &Theme, area: Rect, items: &[(String, &str)]) {
    frame.render_widget(
        Paragraph::new(Line::from(hint_spans(t, items))).alignment(Alignment::Center),
        area,
    );
}

fn render_form_modal(frame: &mut Frame, app: &App) {
    let t = &app.theme;
    let area = centered(76, 19, frame.area());
    let title = if matches!(app.active_modal, ActiveModal::Edit(_)) {
        "Edit secret"
    } else {
        "New secret"
    };
    let block = modal(frame, t, area, title.to_string(), t.accent);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .split(inner.inner(Margin {
            vertical: 0,
            horizontal: 1,
        }));

    let f = &app.form_state;
    let active = f.active_field;
    let mask_key = app.keymap.first_label(Action::FormToggleMask);
    let value_label = if f.show_secret {
        format!("Value, visible ({mask_key} to hide)")
    } else {
        format!("Value, hidden ({mask_key} to show)")
    };
    text_input(
        frame,
        t,
        rows[0],
        "Name",
        &f.name,
        active == 0,
        false,
        Some("e.g. OPENAI_API_KEY"),
    );
    text_input(
        frame,
        t,
        rows[1],
        "Project",
        &f.project,
        active == 1,
        false,
        Some("blank = global"),
    );
    text_input(
        frame,
        t,
        rows[2],
        &value_label,
        &f.value,
        active == FORM_VALUE_FIELD,
        !f.show_secret,
        Some("paste or type the secret"),
    );
    text_input(
        frame,
        t,
        rows[3],
        "Tags",
        &f.tags,
        active == 3,
        false,
        Some("comma separated, e.g. prod, ai"),
    );
    text_input(
        frame,
        t,
        rows[4],
        "Note",
        &f.description,
        active == 4,
        false,
        Some("optional description"),
    );

    render_hints(
        frame,
        t,
        rows[5],
        &[
            ("Tab".into(), "next field"),
            (app.keymap.first_label(Action::FormSave), "save"),
            ("Esc".into(), "cancel"),
        ],
    );
}

fn render_bulk_modal(frame: &mut Frame, app: &App) {
    let t = &app.theme;
    let area = centered(70, 10, frame.area());
    let block = modal(
        frame,
        t,
        area,
        format!("Bulk edit {} secrets (values untouched)", app.marked.len()),
        t.accent,
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .split(inner.inner(Margin {
            vertical: 0,
            horizontal: 1,
        }));
    let b = &app.bulk_form;
    text_input(
        frame,
        t,
        rows[0],
        "Move to project",
        &b.project,
        b.active_field == 0,
        false,
        Some("blank keeps current, 'global' moves to global"),
    );
    text_input(
        frame,
        t,
        rows[1],
        "Replace tags",
        &b.tags,
        b.active_field == 1,
        false,
        Some("blank keeps current, comma separated"),
    );
    render_hints(
        frame,
        t,
        rows[2],
        &[
            ("Tab".into(), "field"),
            (app.keymap.first_label(Action::FormSave), "apply"),
            ("Esc".into(), "cancel"),
        ],
    );
}

fn render_delete_modal(frame: &mut Frame, app: &App, ids: &[String]) {
    let t = &app.theme;
    let entries: Vec<&SecretEntry> = ids
        .iter()
        .filter_map(|id| app.ctx.vault.find_by_id(id))
        .collect();
    let shown = entries.len().min(6);
    let area = centered(60, 8 + shown as u16, frame.area());
    let title = if entries.len() == 1 {
        "Delete secret".to_string()
    } else {
        format!("Delete {} secrets", entries.len())
    };
    let block = modal(frame, t, area, title, t.danger);

    let mut lines = vec![
        Line::from(Span::styled("This cannot be undone:", t.text())),
        Line::from(""),
    ];
    for e in entries.iter().take(shown) {
        lines.push(Line::from(vec![
            Span::styled(e.name.clone(), t.accent()),
            Span::styled(format!("  ({})", e.project_display()), t.muted()),
        ]));
    }
    if entries.len() > shown {
        lines.push(Line::from(Span::styled(
            format!("and {} more", entries.len() - shown),
            t.muted(),
        )));
    }
    lines.push(Line::from(""));
    let (del, cancel) = if app.delete_choice_delete {
        (t.badge(t.danger), t.muted())
    } else {
        (t.muted(), t.badge(t.accent_soft))
    };
    lines.push(Line::from(vec![
        Span::styled(" y  Delete ", del),
        Span::raw("    "),
        Span::styled(" n  Cancel ", cancel),
    ]));
    lines.push(Line::from(Span::styled(
        "Left/Right choose, Enter confirm, Esc cancel",
        t.muted(),
    )));
    frame.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .block(block),
        area,
    );
}

fn render_path_modal(frame: &mut Frame, app: &App) {
    let t = &app.theme;
    let is_export = app.active_modal == ActiveModal::Export;
    let area = centered(76, 11, frame.area());
    let title = if !is_export {
        "Import .env file".to_string()
    } else if app.in_group_mode() {
        format!("Export {} selected secrets", app.marked.len())
    } else {
        format!("Export {} visible secrets", app.filtered_indices.len())
    };
    let block = modal(frame, t, area, title, t.accent);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .split(inner.inner(Margin {
            vertical: 0,
            horizontal: 1,
        }));

    let pf = &app.path_form;
    let placeholder = if is_export {
        "e.g. ~/Downloads/  (a folder gets apiman-export.env)"
    } else {
        "e.g. ./backend/.env  (Tab completes)"
    };
    text_input(
        frame,
        t,
        rows[0],
        if is_export { "Write to" } else { "Read from" },
        &pf.path,
        pf.active_field == 0,
        false,
        Some(placeholder),
    );

    if is_export {
        let active = pf.active_field == 1;
        let opt = |on: bool, label: &'static str| {
            if on {
                Span::styled(format!(" {label} "), t.badge(t.accent_soft))
            } else {
                Span::styled(format!(" {label} "), t.muted())
            }
        };
        let line = Line::from(vec![
            opt(!pf.export_example, ".env  keys + values"),
            Span::raw("   "),
            opt(pf.export_example, ".env.example  keys only"),
        ]);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(if active { t.accent } else { t.border }))
            .title(Span::styled(
                " Format (Left/Right or Space) ",
                if active { t.accent() } else { t.muted() },
            ));
        frame.render_widget(
            Paragraph::new(line)
                .alignment(Alignment::Center)
                .block(block),
            rows[1],
        );
    } else {
        text_input(
            frame,
            t,
            rows[1],
            "Into project",
            &pf.project,
            pf.active_field == 1,
            false,
            Some("blank = global"),
        );
    }

    render_hints(
        frame,
        t,
        rows[2],
        &[
            ("Tab".into(), "complete path"),
            ("Up/Down".into(), "field"),
            ("Enter".into(), if is_export { "export" } else { "import" }),
            ("Esc".into(), "cancel"),
        ],
    );
}

pub fn help_lines(app: &App) -> Vec<Line<'static>> {
    let t = &app.theme;
    let mut lines = Vec::new();
    let mut group = "";
    for info in ACTIONS {
        if info.group != group {
            if !group.is_empty() {
                lines.push(Line::from(""));
            }
            group = info.group;
            lines.push(Line::from(Span::styled(group.to_string(), t.accent())));
        }
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {:<24}", app.keymap.keys_label(info.action)),
                t.key(),
            ),
            Span::styled(info.description.to_string(), t.text()),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("Text fields", t.accent())));
    for (keys, what) in [
        ("Tab, Up, Down", "Switch field"),
        (
            "Left, Right, Home, End",
            "Move cursor (Ctrl+A and Ctrl+E too)",
        ),
        ("Ctrl+W / Ctrl+U", "Delete word / clear field"),
        ("Esc", "Cancel"),
    ] {
        lines.push(Line::from(vec![
            Span::styled(format!("  {keys:<24}"), t.key()),
            Span::styled(what.to_string(), t.text()),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Ctrl+C always quits. Remap keys under \"keybindings\" in config.json; `apiman keys` checks them.",
        t.muted(),
    )));
    lines
}

fn render_help_modal(frame: &mut Frame, app: &App) {
    let t = &app.theme;
    let lines = help_lines(app);
    let area = centered(84, lines.len() as u16 + 2, frame.area());
    let block = modal(
        frame,
        t,
        area,
        "Keybindings (Up/Down scroll, any other key closes)".to_string(),
        t.accent,
    );
    let max_scroll = (lines.len() as u16).saturating_sub(area.height.saturating_sub(2));
    let scroll = app.help_scroll.min(max_scroll);
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        area,
    );
}
