# apiman

Minimal, secure API credential and secret manager for Linux, macOS, and Windows.

Features an interactive TUI (Ratatui) with a warm amber/orange accent theme, CLI subcommands, subprocess environment variable injection, terminal leak prevention, and an in-memory session daemon with auto-lock.

## Features

- **Security & Cryptography:** Argon2id key derivation + XChaCha20-Poly1305 authenticated encryption.
- **In-Memory Hardening:** Sensitive strings wrapped with `zeroize` on drop, redacted debug output, memory page locking via `mlock`, and disabled core dumps via Linux `prctl`.
- **Zero-Leak Subprocess Runner:** `apiman run -- <command>` injects secrets directly into child process memory without writing to disk or shell history.
- **Console Leak Prevention:** `apiman get <key>` prevents accidental printing to interactive terminals unless `--allow-view` is passed. Piping (`|`) works automatically without warnings.
- **In-Memory Session Daemon:** Caches master key in RAM via an ephemeral local Unix socket with a configurable auto-lock inactivity timer.
- **Interactive TUI:** Built with Ratatui; opens by default when running `apiman`. Features live search, masked secret viewing, and modal forms.
- **Single Command Installation:** Install to `~/.local/bin/apiman` with `apiman install` and remove with `apiman uninstall`.
- **Master Password Modification:** Change master password with `apiman passwd` without losing any stored credentials.

## Compilation & Installation

### Quick Build & Install

```bash
cargo build --release
./target/release/apiman install
```

`apiman install` copies the binary to `~/.local/bin/apiman` (and creates the directory if needed).

To check installation status:
```bash
apiman status
```

To remove the installed binary:
```bash
apiman uninstall
```

## Running Tests

Runs the comprehensive end-to-end integration test suite:

```bash
cargo test
```

## Quick Start

### 1. Launch TUI (Default Mode)

Running `apiman` with no arguments launches the TUI. If no vault exists, it prompts to initialize one:

```bash
apiman
```

#### TUI Keybindings

- `Ctrl+K` or `?`: Show keybindings help modal
- `Ctrl+F` or `/`: Search and filter entries across names, tags, and projects
- `c`: Copy selected secret value to clipboard (supports Wayland `wl-copy`, X11, macOS, and OSC 52)
- `Space` or `v`: Toggle masked (`••••••••`) vs revealed secret value
- `a`: Add new secret entry (interactive form modal)
- `e`: Edit selected entry
- `d` or `Delete`: Delete selected entry (with confirmation)
- `p`: Cycle project filter (`all` -> `global` -> project names)
- `j` / `k` or `Down` / `Up`: Navigate list
- `l`: Lock vault and exit
- `q`: Quit TUI

### 2. CLI Usage

#### Initialize Vault
```bash
apiman init
```

#### Store Secrets
```bash
# Global secret (prompted securely for value without echo)
apiman set OPENAI_API_KEY

# Project-scoped secret with tags and description
apiman set STRIPE_SECRET_KEY "sk_live_123" --project billing --tags payment,prod --description "Stripe production key"
```

#### Retrieve Secrets
```bash
# Direct terminal display (requires explicit --allow-view to prevent shoulder surfing)
apiman get OPENAI_API_KEY --allow-view

# Retrieve project secret directly (searched across all projects automatically)
apiman get STRIPE_SECRET_KEY --allow-view

# Pipe to clipboard or another command (raw value, no warning)
apiman get OPENAI_API_KEY | wl-copy
apiman get GITHUB_TOKEN | gh auth login --with-token
```

#### List Secrets
```bash
# Table format (secret values are never displayed)
apiman list

# Filter by project or tag
apiman list --project billing --tag prod

# JSON output
apiman list --format json
```

#### Run Applications Securely (Subprocess Injection)
`apiman run` executes an external program with matching secrets injected into its environment variables in RAM:

```bash
# Injects global secrets into child process environment
apiman run -- node server.js

# Injects project-specific secrets (overriding globals on conflict)
apiman run --project billing -- python main.py

# Filter by tag
apiman run --project billing --tag prod -- npm start

# Execute a shell pipeline or curl command
apiman run -- sh -c 'curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models'
```

#### Change Master Password
```bash
apiman passwd
```
Prompts for a new master password, derives a new Argon2id key with fresh salt, re-encrypts the vault, and updates the active session daemon.

#### Delete a Secret
```bash
apiman delete STRIPE_SECRET_KEY --project billing
```

#### Session Management & Auto-Lock Timeout
```bash
apiman status   # Check daemon lock status, remaining timeout, and installation
apiman unlock   # Start background session daemon
apiman lock     # Lock vault and wipe master key from memory immediately
```

Configure how long the session stays unlocked (supports `s`/`m`/`h`/`d` suffixes, or `none` to disable auto-lock):

```bash
apiman timeout          # Show current configured + active session timeout
apiman timeout 30m      # Auto-lock after 30 minutes of inactivity
apiman timeout 2h       # Auto-lock after 2 hours
apiman timeout 900      # Auto-lock after 900 seconds
apiman timeout none     # Always unlocked, never auto-lock
```

Setting `none` (stored as `0`) keeps the master key in the daemon indefinitely until `apiman lock`.
You can also edit `auto_lock_timeout_seconds` directly in `config.json` (`0` = always unlocked).

## Configuration

Configuration is stored in `~/.config/apiman/config.json`:

```json
{
  "vault_path": "~/.config/apiman/vault.enc",
  "auto_lock_timeout_seconds": 900,
  "default_project": "global",
  "clipboard_timeout_seconds": 30
}
```
