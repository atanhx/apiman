# apiman

A small, local secret manager for API keys and credentials. Secrets are kept in
an encrypted vault and used through a terminal UI, a CLI, a process runner that
injects them into one command, and a local auth proxy that lets apps and AI
agents call APIs without ever holding the key.

Built and tested on Linux. macOS is supported when building from source.

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Using secrets in programs](#using-secrets-in-programs)
- [AI agents](#ai-agents)
- [Terminal UI](#terminal-ui)
- [CLI reference](#cli-reference)
- [Configuration](#configuration)
- [Security](#security)
- [Development](#development)
- [License](#license)

## Install

### Option 1: release binary (Linux x86_64)

A static binary that runs on any x86_64 Linux distribution:

```bash
curl -LO https://github.com/atanhx/apiman/releases/latest/download/apiman-x86_64-unknown-linux-musl.tar.gz
curl -LO https://github.com/atanhx/apiman/releases/latest/download/apiman-x86_64-unknown-linux-musl.tar.gz.sha256
sha256sum -c apiman-x86_64-unknown-linux-musl.tar.gz.sha256
tar -xzf apiman-x86_64-unknown-linux-musl.tar.gz
./apiman install
```

### Option 2: build from source

Requires Rust 1.88 or newer.

```bash
git clone https://github.com/atanhx/apiman.git
cd apiman
cargo build --release
./target/release/apiman install
```

Or install with Cargo directly:

```bash
cargo install --path .
```

### Install location

`apiman install` copies the binary to `~/.local/bin/apiman` (or a directory you
pass, for example `apiman install ~/bin`). It warns if that directory is not on
your `PATH`. Remove it with `apiman uninstall`.

Shell completions:

```bash
apiman completions bash > ~/.local/share/bash-completion/completions/apiman
apiman completions zsh  > ~/.zfunc/_apiman
apiman completions fish > ~/.config/fish/completions/apiman.fish
```

## Quick start

```bash
apiman init                          # create the vault and choose a master password
apiman set OPENAI_API_KEY            # prompts for the value without echo
apiman set STRIPE_KEY --project billing --tags payment,prod
apiman list                          # names, projects, tags; never values
apiman                               # open the terminal UI
```

The vault unlocks once per session. A background daemon keeps the key in memory
and locks after 15 minutes of inactivity (`apiman timeout 30m`, or `none`).
`apiman lock` locks immediately.

## Using secrets in programs

### Run a command with secrets

```bash
apiman run -- node server.js                       # all global secrets
apiman run --project billing -- python app.py      # globals plus the billing project
apiman run --only OPENAI_API_KEY -- pytest         # only the secrets the command needs
apiman run --mask -- ./ci.sh                       # hide values in the command's output
```

The program receives the values in its environment. Nothing is written to disk
or shell history.

### Reference secrets instead of storing them in files

An `apiman://` reference points to a secret without containing it, so it is safe
to commit:

```bash
apiman export --project backend --format refs --output .env.apiman
apiman run --env-file .env.apiman -- npm start
```

`.env.apiman` looks like this:

```
DATABASE_URL=apiman://backend/DATABASE_URL
OPENAI_API_KEY=apiman://OPENAI_API_KEY
PORT=3000
```

References also work in environment variables (`export TOKEN=apiman://TOKEN`)
and are resolved by `apiman run`.

### Read, copy, import and export

```bash
apiman get OPENAI_API_KEY | gh auth login --with-token   # piped output is the raw value
apiman get OPENAI_API_KEY --allow-view                   # print to a terminal on purpose
apiman copy OPENAI_API_KEY                               # clipboard, cleared after 30s
apiman import ./.env --project backend
apiman export --project backend --output ./backend/.env
apiman export --format example --output .env.example    # keys only
eval "$(apiman export --format shell --allow-view)"      # load into the current shell
```

Exported files are written with mode `0600`.

## AI agents

apiman lets coding agents (Claude Code, Codex, Gemini CLI, Cursor and others)
use your keys without the key entering their context.

### Auth proxy

The proxy adds the real key to outgoing requests and forwards them only to the
host configured for that key. The agent or app only sees a local base URL.

```bash
apiman proxy add --preset openai          # route /openai to https://api.openai.com
apiman proxy add stripe --secret STRIPE_KEY --upstream https://api.stripe.com
apiman proxy start                        # listens on 127.0.0.1:8787
apiman proxy env                          # base URLs to give to apps and agents
```

```bash
curl http://127.0.0.1:8787/openai/v1/models
OPENAI_BASE_URL=http://127.0.0.1:8787/openai/v1 OPENAI_API_KEY=apiman-proxy python app.py
```

Presets: `openai`, `anthropic`, `gemini`, `openrouter`, `groq`, `mistral`,
`github`. Custom routes take `--header 'Name: Bearer {secret}'` and
`--query 'key={secret}'`. Routes are stored inside the encrypted vault.

The proxy only listens on loopback, rejects browser requests and unexpected
`Host` headers, does not follow redirects, masks the key if an upstream echoes
it, and stops authenticating as soon as the vault is locked.

### Agent mode

By default agents see values like any other caller. To hide values from agents,
set `agent_mode` in the config:

| Value | Behaviour |
| --- | --- |
| `off` (default) | No special handling |
| `auto` | Applies when an agent is detected (`CLAUDECODE`, `CODEX_*`, `GEMINI_CLI`, `CURSOR_AGENT`, `AI_AGENT`, `AGENT`) or `APIMAN_AGENT=1` |
| `on` | Applies to every CLI call |

In agent mode `get` and `export` print `[REDACTED:NAME]` instead of values,
`copy` and route changes are refused, and `apiman run` still gives the program
the real values but masks them in its output. This prevents accidental exposure
in agent transcripts and logs. It is not a sandbox: a process running as your
user can reach the session. For strict isolation, run the agent in a sandbox
without access to `~/.config/apiman` and give it only the proxy URL.

### Agent skill

`docs/skills/SKILL.md` teaches agents how to use apiman safely. Install it into
the shared skills folder used by most agents:

```bash
apiman skill --install ~/.agents/skills        # writes ~/.agents/skills/apiman/SKILL.md
```

Other locations:

```bash
apiman skill --install ~/.claude/skills        # Claude Code
apiman skill --install ~/.codex/skills         # Codex
apiman skill --install ~/.gemini/skills        # Gemini CLI
apiman skill --install .agents/skills          # one project only
```

## Terminal UI

Run `apiman` with no arguments. Values are masked until revealed.

| Keys | Action |
| --- | --- |
| `Up` `Down` / `k` `j` | Move |
| `PgUp` `PgDn` `Home` `End` (`g` `G`) | Jump |
| `Left` `Right` / `h` `l` / `p` | Change project scope |
| `/` or `Ctrl+F` | Search names, projects, tags and notes |
| `Space` or `v` | Reveal or mask the entry (or the selection) |
| `V`, `*` or `Shift+Space` | Reveal or mask everything visible |
| `c` or `y` | Copy the value (clipboard is cleared after the timeout) |
| `a` | Add |
| `e` or `Enter` | Edit (bulk edit when entries are selected) |
| `d` or `Delete` | Delete (the confirmation defaults to Cancel) |
| `Shift+Up` `Shift+Down` / `K` `J` | Select a range |
| `Tab` | Select or unselect one entry and move down |
| `Esc` | Clear the selection, then the search, then the scope |
| `i` / `X` | Import a `.env` file / export visible or selected entries |
| `?` or `Ctrl+K` | Show all keybindings |
| `L` | Lock the vault and quit |
| `q` or `Ctrl+C` | Quit |

In forms: `Tab` or `Up`/`Down` switch fields, `Ctrl+S` saves, `Ctrl+V` or
`Ctrl+R` shows or hides the value, `Ctrl+W` deletes a word, `Ctrl+U` clears the
field, `Esc` cancels. Pasting a secret never submits the form.

The TUI picks up changes made by other apiman processes, locks itself after the
auto-lock timeout, and uses no CPU while idle.

### Custom keybindings and themes

Any action can be remapped in `config.json`. Each action takes one key or a
list. Run `apiman keys` to see all actions and check your configuration for
typos and conflicts.

```json
{
  "theme": "ocean",
  "keybindings": {
    "copy": "y",
    "lock": ["L", "ctrl+l"],
    "add": "n"
  }
}
```

Key syntax: a character (`a`, `V`, `?`), a named key (`enter`, `esc`, `tab`,
`space`, `up`, `pageup`, `home`, `delete`, `f1`), optionally with `ctrl+`,
`alt+` or `shift+`. `Ctrl+C` always quits.

Themes: `ember` (default), `ocean`, `forest`, `mono`. `NO_COLOR` forces `mono`.

## CLI reference

| Command | Purpose |
| --- | --- |
| `init` | Create a vault |
| `set NAME [VALUE]` | Add or update a secret (prompts, or reads all of stdin when piped) |
| `get NAME` | Print a value (pipes only, unless `--allow-view`) |
| `copy NAME` | Copy to the clipboard with auto-clear |
| `list` | List entries without values (`--format json`) |
| `delete NAME` | Delete an entry |
| `run -- CMD` | Run a command with secrets injected |
| `import FILE` | Import a `.env` file |
| `export` | Export as `env`, `shell`, `example` or `refs` |
| `proxy add/list/remove/env/start` | Manage the local auth proxy |
| `passwd` | Change the master password |
| `unlock`, `lock` | Start or stop the session |
| `timeout [DURATION]` | Show or set auto-lock (`15m`, `2h`, `none`) |
| `status` | Vault, session and agent mode status (`--format json`) |
| `keys` | Show and validate TUI keybindings |
| `skill` | Print or install the agent skill |
| `completions SHELL` | Shell completion script |
| `install`, `uninstall` | Manage the installed binary |

Every command has examples in `apiman <command> --help`.

Name lookup: with `--project P`, apiman looks in `P` and then in global.
Without it, apiman uses the global entry or the single project that has the
name, and asks for `--project` when several projects do. `delete --project P`
only ever deletes from `P`.

Scripts and CI can unlock with `APIMAN_MASTER_PASSWORD`. It is never passed on
to programs started by `apiman run`.

## Configuration

`~/.config/apiman/config.json` is created on first use. Missing keys use their
defaults; an invalid file is reported and never overwritten.

| Key | Default | Meaning |
| --- | --- | --- |
| `vault_path` | `~/.config/apiman/apiman_vault.enc` | Encrypted vault file |
| `auto_lock_timeout_seconds` | `900` | Idle time before the session locks (`0` = never) |
| `default_project` | `global` | Scope for `set` and `import` without `--project` |
| `clipboard_timeout_seconds` | `30` | Clipboard auto-clear delay (`0` = off) |
| `agent_mode` | `off` | `off`, `auto` or `on` (see AI agents) |
| `proxy_port` | `8787` | Port used by `apiman proxy` |
| `theme` | `ember` | TUI theme |
| `keybindings` | `{}` | TUI key overrides |

Use `--config FILE` and `--vault FILE` to work with other files. Vaults created
by older versions as `vault.enc` are renamed to `apiman_vault.enc` on first use.

## Security

- Key derivation: Argon2id (64 MiB, 3 passes, 4 lanes) with a random 32 byte
  salt. Parameters are stored in the vault header.
- Encryption: XChaCha20-Poly1305 with a random nonce on every save. The header
  is authenticated, so any modified byte is detected.
- Files: the vault and exports are written atomically with mode `0600`; the
  config directory is created `0700`. Concurrent writers are serialized with a
  lock, so the TUI and CLI never overwrite each other.
- Memory: secrets are zeroed when dropped, core dumps are disabled, and the
  daemon key is locked in RAM.
- Session daemon: a Unix socket with mode `0600` that only answers the same
  user. It runs detached from the terminal and uses no CPU while idle.
- Master password: at least 8 characters.

## Development

```bash
cargo build
cargo clippy --all-targets
cargo test
```

All tests are end to end: they run the real binary, or drive the TUI with key
events, against real encrypted vaults in isolated temporary directories. See
`AGENTS.md` for the code layout and conventions.

## License

MIT. See [LICENSE](LICENSE).
