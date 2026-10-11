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

`apiman install` force-copies the current binary to `~/.local/bin/apiman` (overwriting any previous install, creating the directory if needed, mode `0755`).

Install to a custom directory instead:

```bash
apiman install ~/bin
apiman install /usr/local/bin
```

If the target directory is not in your `PATH` (including `~/.local/bin` for the default install), `apiman` warns you and prints the `export PATH=...` line to add to `~/.bashrc` or `~/.zshrc`.

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
  (inside search: `Left`/`Right` move the cursor, `Up`/`Down` move selection)
- `Up` / `Down` or `j` / `k`: Move selection (`PgUp`/`PgDn` jump 10, `Home`/`End` jump to ends)
- `Left` / `Right`: Cycle project scope filter (`all` -> `global` -> projects)
- `c`: Copy selected secret value to clipboard (supports Wayland `wl-copy`, X11, macOS, and OSC 52)
- `Space` or `v`: Toggle masked (`••••••••`) vs revealed secret value (single entry)
- `Shift+Space` or `*`: Reveal / mask ALL currently visible secrets at once
- `Shift+Up` / `Shift+Down`: Select multiple entries (group mode, marked with `+`)
  - In group mode: `e` bulk-edits project/tags for all selected (values are never touched — blank fields keep current values, `global` moves entries to global scope), `d` deletes all selected, `Esc` clears the selection
- `a`: Add new secret entry (interactive form modal)
- `e`: Edit selected entry
- `d` or `Delete`: Delete selected entry (`Left`/`Right` + `Enter` to confirm)
- `i`: Import secrets from a `.env` file
- `X` (Shift+X): Export visible secrets to a `.env` file (or safe `.env.example` template)
- `p`: Cycle project filter
- `j` / `k`: Navigate list (vim-style)
- `l`: Lock vault and exit
- `q`: Quit TUI

Inside any form modal: `Tab` / `Up` / `Down` switch fields, `Left` / `Right` / `Home` / `End` move the text cursor, `Delete` removes the character under the cursor, `Ctrl+S` saves, `Esc` cancels.

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

#### Import Secrets From .env Files
```bash
# Import every KEY=VALUE pair as a global secret
apiman import ./.env

# Import into a project scope with tags
apiman import ./backend/.env --project backend --tags prod

# .env.example files work too (empty placeholders are skipped)
apiman import ./.env.example --project myapp
```
Supports `export KEY=...` prefixes, single/double quotes, `\n` escapes, `#` comments, and reports skipped lines. Existing entries are updated in place.

#### Export Secrets To .env Files
```bash
# Write project secrets (with global fallback) to a file (0600 permissions)
apiman export --project backend --output ./backend/.env

# Point at a folder to auto-save apiman-export.env inside it
apiman export --project backend --output /home/um/Downloads/

# Generate a safe .env.example template (keys only, no secret values)
apiman export --format example --output ./.env.example

# Pipe to another tool (raw KEY=VALUE lines)
apiman export --project billing | wl-copy
```
In the TUI, press `i` to import or `X` to export whatever is currently visible (respects search + scope filter). Path fields show grey placeholder examples and support `Tab` filesystem autocompletion.

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
