# AGENTS.md

Technical guide for working on apiman. Read this before changing code.

apiman is a local secret manager written in Rust. It stores API keys in an
encrypted vault and exposes them through a CLI, a TUI, a process runner and a
local credential-injecting HTTP proxy. A small background daemon holds the
unlocked key for the session.

Users of the tool (including AI agents using it on a user's behalf) should read
the agent skill instead: [docs/skills/SKILL.md](docs/skills/SKILL.md).

## Build, lint, test

```bash
cargo build
cargo clippy --all-targets      # must report zero warnings
cargo fmt
cargo test                      # end-to-end suites in tests/
```

Static Linux release binary:

```bash
rustup target add x86_64-unknown-linux-musl
CC_x86_64_unknown_linux_musl=gcc cargo build --release --target x86_64-unknown-linux-musl
```

Minimum Rust version is 1.88 (edition 2024, let-chains).

## Layout

| Path | Responsibility |
| --- | --- |
| `src/main.rs` | Entry point. No command or `tui` opens the TUI; everything else goes to `cli::handle_cli` |
| `src/cli.rs` | clap definitions, help text, every command handler, `SessionContext` |
| `src/config.rs` | `config.json` model, loading, defaults, legacy vault migration, socket path |
| `src/crypto.rs` | Argon2id key derivation, XChaCha20-Poly1305 envelope (v1 read, v2 read/write) |
| `src/storage.rs` | Vault file IO: atomic 0600 writes, directory lock, change signature |
| `src/vault.rs` | Data model (`Vault`, `SecretEntry`), name resolution, `apiman://` references |
| `src/daemon.rs` | Session daemon (Unix socket protocol), detached process spawning |
| `src/runner.rs` | Streaming output masker and the masked child runner for `apiman run` |
| `src/proxy.rs` | Local auth proxy: routes, presets, request forwarding, response masking |
| `src/agent.rs` | Agent detection and the agent-mode policy helpers |
| `src/clipboard.rs` | Clipboard backends and the delayed auto-clear helper |
| `src/dotenv.rs` | `.env` parsing and the env, shell, example and refs formats |
| `src/install.rs` | `install` and `uninstall` |
| `src/security.rs` | `SecretString`, password and secret input, process hardening |
| `src/tui/mod.rs` | Terminal setup and restore, event loop |
| `src/tui/app.rs` | TUI state and every vault operation the TUI performs |
| `src/tui/input.rs` | Key and paste handling per modal |
| `src/tui/keymap.rs` | Actions, default keys, key parsing, config overrides and validation |
| `src/tui/theme.rs` | Color themes |
| `src/tui/ui.rs` | Rendering only (reads `App`, never mutates vault state) |
| `docs/skills/SKILL.md` | Agent skill, embedded into the binary by `apiman skill` |
| `tests/common/mod.rs` | Shared `Sandbox` test harness |

## Core flows

### Session and unlocking

`cli::load_session` loads the config, asks the daemon for the cached key
(`GetMasterKey`) and decrypts the vault with it. If there is no daemon or its
key does not fit this vault, it derives the key from `APIMAN_MASTER_PASSWORD`
or an interactive prompt (3 attempts on a TTY), replaces a stale daemon and
spawns a new one. The result is a `SessionContext`.

### Writing to the vault

All writes go through `SessionContext::update(|vault| ...)`. It takes the vault
directory lock, reloads the latest vault from disk with the session key,
applies the closure and saves atomically. Never mutate `ctx.vault` and save it
directly: another apiman process (a TUI left open, a script) may have written
in the meantime. `reload_if_changed` lets long-lived views (the TUI) pick up
external changes.

### Vault file format

```
v2: "APIMAN02" | m_cost u32 LE | t_cost u32 LE | p_cost u32 LE | salt[32] | nonce[24] | ciphertext
v1: "APIMAN01" | salt[32] | nonce[24] | ciphertext        (read only, fixed KDF params)
```

In v2 the entire header is AEAD associated data. Every save writes v2 with the
vault's existing salt and KDF params (`KeyParams`), so the session key stays
valid. KDF params read from a file are bounds-checked before use. The plaintext
is the JSON of `Vault`; `proxy_routes` lives there so routes are encrypted and
tamper-evident.

### Name resolution

`Vault::resolve(name, project)`:
- explicit project: that project, then global; never another project
- explicit `global`: global only
- no project: global, then the single project holding the name; several
  projects is `LookupError::Ambiguous`, never a guess

`Vault::find_in_scope` is the strict single-scope lookup used by `delete
--project`. Exact-case names win over case-insensitive matches. Project names
compare case-insensitively everywhere (`same_project`).

### Daemon

Requests are one JSON line each: `GetMasterKey`, `UpdateMasterKey`,
`UpdateTimeout`, `Touch`, `Status`, `Ping`, `Lock`. Only key access, key or
timeout updates and `Touch` reset the idle timer; `Status` and `Ping` do not.
The daemon is started with `setsid` from `/` (`daemon::detached_command`), so
terminal signals never reach it. It blocks in `accept` and its watcher sleeps
until the idle deadline: no polling. Connections from other UIDs are dropped.

### `apiman run`

The environment is built from: `apiman://` references found in the inherited
environment, then the scope (`resolve_env_map`) unless `--only` or
`--env-file` is used, then `--only` names, then `--env-file` entries. Without
masking the process `exec`s the program (signals, TTY and exit code belong to
the program and the decrypted vault leaves memory). With masking
(`--mask` or agent mode) `runner::run_masked` pipes stdout and stderr through
`Masker`, forwards termination signals and returns the child's exit code.

### Auth proxy

`apiman proxy start` serves `http://127.0.0.1:PORT/<alias>/<path>`. Per request
it fetches the key from the daemon (423 when locked), loads routes from the
vault, resolves the route's secret, replaces client copies of the injected
headers, forwards over HTTPS with redirects disabled and masks the secret in
the response body. It accepts only loopback binds, rejects requests with
`Origin` or `Sec-Fetch-Site`, and requires a loopback `Host`. Upstreams must be
`https://` (plain `http://` only for loopback).

### Agent mode

`agent::agent_mode_reason(config)` returns why values must be hidden. The
default is off. When active: `get` prints `[REDACTED:NAME]`, `export` masks
values and refuses `--output`, `copy` and `proxy add/remove` are refused, and
`run` always masks. Detection uses exact environment variable names listed in
`AGENT_MARKERS`; extend that list instead of adding substring matching.

### TUI

`App` stores selections by entry id (`marked`, `pinned`, `revealed_entries`,
`ActiveModal::Edit(id)`, `ActiveModal::DeleteConfirm(ids)`), never by vault
index, because the vault can be reloaded underneath it. `filtered_indices` are
indices into the current `ctx.vault.entries` and are rebuilt by `recompute`.
The event loop redraws only after input or once per second, and `App::tick`
handles the inactivity lock and external reloads.

## Making changes

### Adding or changing a CLI command

1. Add the variant to `Commands` in `src/cli.rs` with `about` and an
   `after_help = ex(&[...])` examples block (`# comment` lines are dimmed).
2. Dispatch it in `handle_cli` and write a `handle_*` function that returns
   `Result<ExitCode, Box<dyn Error>>`. Use `fail(msg)` for user errors.
3. Route every vault write through `ctx.update`.
4. Call `refuse_in_agent_mode` (or mask with `agent::masked`) for anything that
   would reveal a value or change where a value can be sent.
5. Add an end-to-end test, then update `README.md` (CLI reference and the
   relevant section) and `docs/skills/SKILL.md` if agents can use it.

### Adding a TUI action

1. Add a variant to `keymap::Action`, an entry to `Action::ALL` and an
   `ActionInfo` row in `ACTIONS` (config name, group, description, defaults).
2. Handle it in `input::run_action`.
3. Help, the footer hints and `apiman keys` are generated from the keymap; only
   the TUI key table in `README.md` needs a manual update.

### Adding a config field

Add it to `Config` with a default in `impl Default`. The struct uses
`#[serde(default)]`, so older config files keep working. Document it in the
README configuration table.

### Adding a proxy preset

Add a `Preset` to `PRESETS` in `src/proxy.rs` (upstream, header template,
conventional secret name, SDK base path, and SDK env var names only when they
are documented by the SDK). List it in `README.md` and `docs/skills/SKILL.md`.

### Changing the vault format

Bump the magic, keep reading every older format, and make saves write only the
newest one. Add a test that opens a vault written in the old format.

## Invariants

- Secret values never go to stdout or stderr unless the user explicitly asked
  (`get` piped or `--allow-view`, `export`), and never in agent mode.
- Secret buffers use `SecretString` or `Zeroizing`. Do not log values, put them
  in error messages, or pass them on argv or in env to helpers; the clipboard
  helper receives its secret over a pipe.
- Files that can contain secrets are written with `storage::save_vault` or
  `cli::write_secret_file` (temp file in the same directory, 0600, rename).
- A missing config is created with defaults; a malformed one is an error and is
  never overwritten.
- Long-running processes (daemon, TUI, proxy) must not poll. Block on IO or
  sleep until a known deadline.
- Help text, UI strings, comments and docs use plain ASCII: no decorative
  Unicode, emoji or typographic dashes.

## Tests

Tests are end-to-end only; there are no unit tests. Each suite builds a
`common::Sandbox`, which gives a private `HOME`, `XDG_CONFIG_HOME`, vault and
daemon socket, scrubs agent markers and `APIMAN_*` variables from the
environment, and stops its daemon on drop.

| Suite | Covers |
| --- | --- |
| `tests/e2e_tests.rs` | Core lifecycle, install, stale daemon, TUI selection flows |
| `tests/e2e_cli.rs` | Crypto format and tampering, migration, resolution, dotenv, run, daemon, clipboard, agent mode, proxy, keys, skill |
| `tests/e2e_tui.rs` | TUI behaviour and rendering through `ratatui::backend::TestBackend` |

Patterns:
- CLI: `sb.ok(&[...])` (asserts success, returns stdout), `sb.fails(&[...])`
  (asserts failure, returns stderr), `sb.run_stdin(cmd, input)` for prompts.
- TUI: `sb.tui(&[(name, value, project)])` builds a real vault and an `App`;
  drive it with `press`, `type_text`, `handle_paste`; check the screen with
  `render(&app, width, height)`.
- Never touch the real user environment: no real clipboard, no real config,
  no fixed ports (bind port 0 and read it back).

## Keeping documentation in sync

| When this changes | Update |
| --- | --- |
| CLI commands, flags or output | `README.md`, the command's `after_help`, `docs/skills/SKILL.md` |
| Default keybindings | `README.md` TUI table |
| Config fields | `README.md` configuration table |
| Agent behaviour, proxy, references | `docs/skills/SKILL.md`, `README.md` AI agents section |
| Architecture or invariants | This file |

`docs/skills/SKILL.md` follows the Agent Skills format (YAML front matter with
`name` and `description`, Markdown body). It is compiled into the binary, so
`apiman skill` always prints the version that matches the code; a test checks
that the output equals the file.
