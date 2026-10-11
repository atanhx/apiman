pub mod app;
pub mod input;
pub mod keymap;
pub mod theme;
pub mod ui;

use crate::cli::SessionContext;
use app::App;
use crossterm::{
    event::{
        self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyboardEnhancementFlags,
        PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::io::{self, stdout};
use std::panic;
use std::time::{Duration, Instant};

fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(
        stdout(),
        PopKeyboardEnhancementFlags,
        DisableBracketedPaste,
        LeaveAlternateScreen,
        crossterm::cursor::Show
    );
}

pub fn run_tui(ctx: SessionContext) -> Result<(), Box<dyn std::error::Error>> {
    let original_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        restore_terminal();
        original_hook(panic_info);
    }));

    enable_raw_mode()?;
    let mut out = stdout();
    if let Err(e) = execute!(out, EnterAlternateScreen, EnableBracketedPaste) {
        restore_terminal();
        return Err(e.into());
    }
    // Ask supporting terminals (kitty, foot, wezterm, ...) to report modified
    // keys such as Shift+Space; others ignore this harmlessly.
    let _ = execute!(
        out,
        PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
    );

    let mut app = App::new(ctx);
    let result = Terminal::new(CrosstermBackend::new(out))
        .and_then(|mut terminal| event_loop(&mut terminal, &mut app));
    restore_terminal();
    let _ = panic::take_hook();

    result?;
    if let Some(msg) = app.exit_message.take() {
        eprintln!("{msg}");
    }
    Ok(())
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> io::Result<()> {
    // Redraw only after input or once per second (clock, toasts, auto-lock
    // countdown), so an idle TUI stays near zero CPU.
    const FRAME: Duration = Duration::from_secs(1);
    let mut dirty = true;
    let mut last_draw = Instant::now();
    while !app.should_quit {
        if dirty || last_draw.elapsed() >= FRAME {
            terminal.draw(|f| ui::render(f, app))?;
            dirty = false;
            last_draw = Instant::now();
        }
        if event::poll(FRAME.saturating_sub(last_draw.elapsed()))? {
            match event::read()? {
                Event::Key(key) => input::handle_key(app, key),
                Event::Paste(text) => input::handle_paste(app, &text),
                Event::Resize(..) => {}
                _ => continue,
            }
            dirty = true;
        }
        app.tick();
    }
    Ok(())
}
