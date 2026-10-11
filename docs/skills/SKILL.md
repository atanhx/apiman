---
name: apiman
description: Use API keys and other secrets stored in the user's apiman vault without reading or printing them. Use when a task needs credentials (OpenAI, Anthropic, Stripe, GitHub, database URLs, any API token), when a command fails for a missing or invalid key, when the user mentions apiman, .env files, or secret references like apiman://NAME, or when wiring a project's environment variables.
license: MIT
compatibility: Requires the apiman CLI on PATH (Linux or macOS). The vault must be unlocked by the user.
metadata:
  author: atanhx
  version: "0.4.0"
---

# apiman

apiman is the user's local, encrypted secret manager. Secrets live in an
encrypted vault and an unlocked session daemon. Your job is to use secrets for
the user's task while keeping their values out of your context, your output,
files, commits and logs.

## Rules

1. Never ask the user to paste a secret into the chat. Ask them to store it:
   `apiman set NAME` in their own terminal (it prompts without echo).
2. Never print, echo, log or write secret values. Do not run `apiman get`,
   `apiman export` (env or shell format) or `apiman copy` to look at values.
3. Never put real values in files you create or edit. Write `apiman://`
   references instead (see below).
4. If output contains `[REDACTED:NAME]`, that is apiman hiding a value on
   purpose. Do not try to recover it (no base64, hex, reversing, etc).
5. If the vault is locked, stop and ask the user to run `apiman unlock` in
   their terminal. Never ask for the master password.

## Discover what exists

```sh
apiman status --format json      # unlocked, agent_mode, proxy_port
apiman list --format json        # names, projects, tags, references; never values
apiman proxy list                # configured auth proxy routes
```

`list` returns a `reference` per entry, for example `apiman://billing/STRIPE_KEY`.

## Use a secret: preferred order

### 1. Auth proxy (the value never reaches your process)

If a route exists for the API, call it through the local proxy. apiman adds
the real key to the request and forwards it only to that route's host.

```sh
apiman proxy env                 # prints base URLs, e.g. OPENAI_BASE_URL=http://127.0.0.1:8787/openai/v1
curl http://127.0.0.1:8787/openai/v1/models
OPENAI_BASE_URL=http://127.0.0.1:8787/openai/v1 OPENAI_API_KEY=apiman-proxy python app.py
```

Any placeholder works as the client-side key. If the proxy is not running,
ask the user to start it with `apiman proxy start` (or start it yourself in
the background if allowed). Adding or changing routes is for the user:
`apiman proxy add --preset openai`.

### 2. Inject into one command

```sh
apiman run --only OPENAI_API_KEY -- python script.py
apiman run --only DATABASE_URL,REDIS_URL --project backend -- npm test
apiman run --mask --only STRIPE_KEY -- ./scripts/smoke.sh
```

Use `--only` to inject just what the command needs. `--mask` replaces the
values with `[REDACTED:NAME]` in the command's output; in agent mode masking
is always on, and the program still receives the real values.

### 3. References in project files

Keep committed config free of secrets by using references:

```sh
apiman export --project backend --format refs --output .env.apiman
apiman run --env-file .env.apiman -- npm start
```

`.env.apiman` contains lines like `DATABASE_URL=apiman://backend/DATABASE_URL`
and plain values such as `PORT=3000`. Environment variables whose value is an
`apiman://` reference are resolved by `apiman run` too.

Reference forms: `apiman://NAME` (global, or the single project holding it)
and `apiman://PROJECT/NAME`.

## Common situations

| Situation | Do this |
| --- | --- |
| A key is missing | Ask the user to run `apiman set NAME` (add `--project P` if needed) |
| Name exists in several projects | Pass `--project P` or use `apiman://P/NAME` |
| `Vault is locked` or proxy returns 423 | Ask the user to run `apiman unlock` |
| Proxy returns 404 for a route | Ask the user to add it: `apiman proxy add ...` |
| Need a `.env.example` | `apiman export --format example --output .env.example` |
| Project needs env wiring | Create `.env.apiman` with references, run via `apiman run --env-file` |
| Output shows `[REDACTED:NAME]` | Expected; continue without the value |

## Agent mode

When the user enables it (`"agent_mode": "auto"` or `"on"` in
`~/.config/apiman/config.json`), apiman detects agents such as Claude Code,
Codex, Gemini CLI and Cursor (or `APIMAN_AGENT=1`). Then `get` and `export`
print `[REDACTED:NAME]`, `copy` is refused, and `run` masks its output. This
is the expected behaviour, not an error.
