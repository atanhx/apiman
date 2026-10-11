#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvEntry {
    pub key: String,
    pub value: String,
}

pub fn is_valid_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
}

/// Parses `.env` text. Supports `export` prefixes, `#` comments (full-line and
/// inline after whitespace), single/double quotes, double-quote escapes and
/// quoted values spanning several lines. Returns entries plus the number of
/// lines that could not be parsed.
pub fn parse_dotenv(text: &str) -> (Vec<EnvEntry>, usize) {
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
    let lines: Vec<&str> = text.lines().collect();
    let mut entries = Vec::new();
    let mut skipped = 0;
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i].trim();
        i += 1;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let line = match line.strip_prefix("export") {
            Some(rest) if rest.starts_with(char::is_whitespace) => rest.trim_start(),
            _ => line,
        };

        let Some(eq_pos) = line.find('=') else {
            skipped += 1;
            continue;
        };

        let key = line[..eq_pos].trim();
        if !is_valid_key(key) {
            skipped += 1;
            continue;
        }

        let mut raw_value = line[eq_pos + 1..].to_string();
        let opening = raw_value.trim_start().chars().next();
        if let Some(q @ ('"' | '\'')) = opening {
            let after_open = &raw_value.trim_start()[1..];
            if find_closing_quote(after_open, q).is_none() {
                // Multi-line value: only accept it when a closing quote exists,
                // so one stray quote cannot swallow the rest of the file.
                if let Some(end) =
                    (i..lines.len()).find(|&j| find_closing_quote(lines[j], q).is_some())
                {
                    for next in &lines[i..=end] {
                        raw_value.push('\n');
                        raw_value.push_str(next);
                    }
                    i = end + 1;
                }
            }
        }

        let value = unquote(strip_inline_comment(&raw_value).trim());
        entries.push(EnvEntry {
            key: key.to_string(),
            value,
        });
    }

    (entries, skipped)
}

fn find_closing_quote(s: &str, quote: char) -> Option<usize> {
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        if quote == '"' && escaped {
            escaped = false;
            continue;
        }
        if quote == '"' && c == '\\' {
            escaped = true;
            continue;
        }
        if c == quote {
            return Some(i);
        }
    }
    None
}

/// Drops a `#` comment that is preceded by whitespace and not inside quotes.
/// `KEY=abc#def` keeps the hash; `KEY=abc # note` and `KEY= # note` do not.
fn strip_inline_comment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut quote: Option<char> = None;
    let mut escaped = false;

    for c in value.chars() {
        if let Some(q) = quote {
            out.push(c);
            if escaped {
                escaped = false;
            } else if q == '"' && c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        if c == '#' && out.ends_with(char::is_whitespace) {
            break;
        }
        // Only a quote that opens the value quotes it; `it's` stays literal.
        if (c == '"' || c == '\'') && out.trim().is_empty() {
            quote = Some(c);
        }
        out.push(c);
    }

    out
}

fn unquote(value: &str) -> String {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            let inner = &value[1..value.len() - 1];
            if first == b'"' {
                return unescape_double(inner);
            }
            return inner.to_string();
        }
    }
    value.to_string()
}

fn unescape_double(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn escape_double(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

fn needs_quotes(value: &str) -> bool {
    if value.is_empty() || value != value.trim() {
        return true;
    }
    value.chars().any(|c| {
        c.is_whitespace()
            || matches!(
                c,
                '#' | '"'
                    | '\''
                    | '`'
                    | '$'
                    | '\\'
                    | '!'
                    | '*'
                    | ';'
                    | '&'
                    | '|'
                    | '<'
                    | '>'
                    | '('
                    | ')'
            )
    })
}

/// Quote a value for `.env` files. Single quotes are literal in shells and in
/// every common dotenv loader, so `$`, backticks and `!` cannot expand; double
/// quotes are only used when the value itself needs escapes.
pub fn quote_env_value(value: &str) -> String {
    if !needs_quotes(value) {
        value.to_string()
    } else if !value.contains(['\'', '\n', '\r']) {
        format!("'{value}'")
    } else {
        format!("\"{}\"", escape_double(value))
    }
}

/// POSIX shell single-quoting, safe for `eval`.
pub fn quote_shell(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub fn format_env(entries: &[EnvEntry]) -> String {
    let mut out = String::from("# Exported by apiman\n");
    for e in entries {
        out.push_str(&format!("{}={}\n", e.key, quote_env_value(&e.value)));
    }
    out
}

pub fn format_shell(entries: &[EnvEntry]) -> String {
    let mut out = String::new();
    for e in entries {
        out.push_str(&format!("export {}={}\n", e.key, quote_shell(&e.value)));
    }
    out
}

pub fn format_example(keys: &[String]) -> String {
    let mut out = String::from(
        "# Generated by apiman export --format example (fill in values, no secrets included)\n",
    );
    for k in keys {
        out.push_str(&format!("{k}=\n"));
    }
    out
}

/// `.env` file whose values are `apiman://` references: safe to commit and
/// resolved by `apiman run --env-file`.
pub fn format_refs(entries: &[(String, String)]) -> String {
    let mut out = String::from(
        "# apiman references: safe to commit, resolved by `apiman run --env-file <this file>`\n",
    );
    for (key, reference) in entries {
        out.push_str(&format!("{key}={reference}\n"));
    }
    out
}
