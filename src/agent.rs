use crate::config::{AgentMode, Config};

/// Markers coding agents set for the shell commands they run. Exact names
/// only: substring matching misfires on unrelated paths and repo names.
const AGENT_MARKERS: &[(&str, &str)] = &[
    ("CLAUDECODE", "Claude Code"),
    ("GEMINI_CLI", "Gemini CLI"),
    ("CURSOR_AGENT", "Cursor"),
    ("CODEX_THREAD_ID", "Codex"),
    ("CODEX_SANDBOX", "Codex"),
    ("CODEX_CI", "Codex"),
    ("AI_AGENT", "an AI agent"),
    ("AGENT", "an AI agent"),
];

fn is_set(var: &str) -> bool {
    std::env::var(var).is_ok_and(|v| {
        let v = v.trim().to_ascii_lowercase();
        !v.is_empty() && v != "0" && v != "false" && v != "no" && v != "off"
    })
}

/// Why values must be masked for this caller, or `None`.
pub fn agent_mode_reason(config: &Config) -> Option<String> {
    match config.agent_mode {
        AgentMode::Off => None,
        AgentMode::On => Some("agent_mode is \"on\" in config".to_string()),
        AgentMode::Auto => {
            if is_set("APIMAN_AGENT") {
                return Some("APIMAN_AGENT is set".to_string());
            }
            AGENT_MARKERS
                .iter()
                .find(|(var, _)| is_set(var))
                .map(|(var, tool)| format!("running under {tool} (${var})"))
        }
    }
}

pub fn masked(name: &str) -> String {
    format!("[REDACTED:{name}]")
}

pub fn refuse_in_agent_mode(config: &Config, action: &str) -> Result<(), String> {
    match agent_mode_reason(config) {
        Some(reason) => Err(format!(
            "Refusing to {action}: agent mode is active ({reason}). Agents only see masked values.\n\
             Use the secret without seeing it:\n  \
             apiman run --only NAME -- <command>      # injected, output masked\n  \
             apiman proxy env                         # call APIs through the local auth proxy"
        )),
        None => Ok(()),
    }
}
