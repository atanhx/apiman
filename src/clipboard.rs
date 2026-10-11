use crate::daemon::{detached_command, reap_in_background};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::Duration;
use zeroize::Zeroizing;

struct Backend {
    name: &'static str,
    copy: (&'static str, &'static [&'static str]),
    paste: (&'static str, &'static [&'static str]),
    /// Dedicated clear invocation; otherwise an empty copy clears.
    clear: Option<(&'static str, &'static [&'static str])>,
}

const BACKENDS: &[Backend] = &[
    Backend {
        name: "wl-copy",
        copy: ("wl-copy", &[]),
        paste: ("wl-paste", &["--no-newline"]),
        clear: Some(("wl-copy", &["--clear"])),
    },
    Backend {
        name: "xclip",
        copy: ("xclip", &["-selection", "clipboard"]),
        paste: ("xclip", &["-selection", "clipboard", "-o"]),
        clear: None,
    },
    Backend {
        name: "xsel",
        copy: ("xsel", &["--clipboard", "--input"]),
        paste: ("xsel", &["--clipboard", "--output"]),
        clear: Some(("xsel", &["--clipboard", "--clear"])),
    },
    Backend {
        name: "pbcopy",
        copy: ("pbcopy", &[]),
        paste: ("pbpaste", &[]),
        clear: None,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyMethod {
    Command(&'static str),
    Arboard,
    Osc52,
}

fn pipe_into(program: &str, args: &[&str], input: &[u8]) -> bool {
    let Ok(mut child) = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input);
    }
    child.wait().map(|s| s.success()).unwrap_or(false)
}

fn read_from(program: &str, args: &[&str]) -> Option<Zeroizing<Vec<u8>>> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut out = Zeroizing::new(Vec::new());
    child.stdout.take()?.read_to_end(&mut out).ok()?;
    child.wait().ok()?.success().then_some(out)
}

pub fn copy_to_clipboard(text: &str) -> Result<CopyMethod, String> {
    for b in BACKENDS {
        if pipe_into(b.copy.0, b.copy.1, text.as_bytes()) {
            return Ok(CopyMethod::Command(b.name));
        }
    }

    if let Ok(mut cb) = arboard::Clipboard::new()
        && cb.set_text(text.to_string()).is_ok()
    {
        return Ok(CopyMethod::Arboard);
    }

    // OSC 52 asks the terminal itself to set the clipboard (works over SSH).
    let b64 = Zeroizing::new(base64_encode(text.as_bytes()));
    let osc52 = Zeroizing::new(format!("\x1b]52;c;{}\x07", b64.as_str()));
    if let Ok(mut tty) = std::fs::OpenOptions::new().write(true).open("/dev/tty") {
        if tty.write_all(osc52.as_bytes()).is_ok() && tty.flush().is_ok() {
            return Ok(CopyMethod::Osc52);
        }
        return Err("Could not copy: terminal rejected the clipboard write".to_string());
    }

    Err("Could not copy: no clipboard backend available (wl-copy, xclip, xsel, pbcopy)".to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearOutcome {
    Cleared,
    Changed,
    Unavailable,
}

/// Clears the clipboard only if it still holds `expected`, so whatever the
/// user copied afterwards is left alone.
pub fn clear_if_unchanged(expected: &[u8]) -> ClearOutcome {
    for b in BACKENDS {
        let Some(current) = read_from(b.paste.0, b.paste.1) else {
            continue;
        };
        if current.as_slice() != expected {
            return ClearOutcome::Changed;
        }
        let cleared = match b.clear {
            Some((program, args)) => pipe_into(program, args, b""),
            None => pipe_into(b.copy.0, b.copy.1, b""),
        };
        return if cleared {
            ClearOutcome::Cleared
        } else {
            ClearOutcome::Unavailable
        };
    }

    if let Ok(mut cb) = arboard::Clipboard::new()
        && let Ok(current) = cb.get_text()
    {
        let current = Zeroizing::new(current);
        if current.as_bytes() != expected {
            return ClearOutcome::Changed;
        }
        return if cb.clear().is_ok() {
            ClearOutcome::Cleared
        } else {
            ClearOutcome::Unavailable
        };
    }
    ClearOutcome::Unavailable
}

/// Hands the secret to a detached `apiman clipboard-clear` helper over a pipe
/// (never argv/env) which wipes the clipboard after `after_secs`.
pub fn schedule_clear(text: &str, after_secs: u64) -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let Ok(mut child) = detached_command(&exe)
        .arg("clipboard-clear")
        .arg("--after")
        .arg(after_secs.to_string())
        .spawn()
    else {
        return false;
    };
    let ok = child
        .stdin
        .take()
        .map(|mut s| s.write_all(text.as_bytes()).is_ok())
        .unwrap_or(false);
    reap_in_background(child);
    ok
}

pub fn run_clear_helper(after_secs: u64) -> std::io::Result<()> {
    crate::security::harden_process();
    let mut secret = Zeroizing::new(Vec::new());
    std::io::stdin().read_to_end(&mut secret)?;
    std::thread::sleep(Duration::from_secs(after_secs));
    if !secret.is_empty() {
        clear_if_unchanged(&secret);
    }
    Ok(())
}

/// Copy and arrange auto-clear. Returns a short human note for status lines.
pub fn copy_secret(text: &str, clear_after_secs: u64) -> Result<String, String> {
    let method = copy_to_clipboard(text)?;
    let note = match method {
        CopyMethod::Osc52 => "via terminal (OSC 52); clear it manually".to_string(),
        _ if clear_after_secs == 0 => "auto-clear disabled".to_string(),
        _ if schedule_clear(text, clear_after_secs) => format!(
            "clears in {}",
            crate::cli::format_duration_short(clear_after_secs)
        ),
        _ => "auto-clear unavailable".to_string(),
    };
    Ok(note)
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(b2 & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}
