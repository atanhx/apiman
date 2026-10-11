pub mod app;
pub mod input;
pub mod ui;

use crate::cli::SessionContext;
use app::App;
use crossterm::{
    event::{
        self, Event, KeyboardEnhancementFlags, PopKeyboardEnhancementFlags,
        PushKeyboardEnhancementFlags,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io::stdout;
use std::panic;
use std::time::Duration;

pub fn run_tui(ctx: SessionContext) -> Result<(), Box<dyn std::error::Error>> {
    let original_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let _ = execute!(
            stdout(),
            PopKeyboardEnhancementFlags,
            LeaveAlternateScreen
        );
        original_hook(panic_info);
    }));

    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    // Ask supporting terminals (kitty, foot, wezterm, alacritty, ...) to
    // disambiguate modified keys so Shift+Space / Shift+Arrows arrive with
    // their modifiers. Terminals without support ignore this harmlessly.
    let _ = execute!(
        stdout,
        PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
    );
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(ctx);

    while !app.should_quit {
        terminal.draw(|f| ui::render(f, &app))?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                input::handle_key(&mut app, key);
            }
        }
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        PopKeyboardEnhancementFlags,
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;

    Ok(())
}
