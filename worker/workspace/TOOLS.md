# TOOLS.md - Local Notes

Skills define _how_ tools work. This file is for _your_ specifics — the stuff that's unique to your setup.

## Environment

This container includes: python3/pip, node/npm/pnpm/bun, git, brew, curl, wget, jq, and standard Unix tools.

## Tool Selection Guide

- `web_fetch`: Preferred for simple HTTP requests — fetching web pages, public APIs, articles. Handles timeouts and redirects automatically.
- `exec` + `curl`: For requests needing custom headers, auth tokens, POST bodies, or piping to `jq`. Always use `--connect-timeout 5 --max-time 10` to fail fast.
- `edit` over `write`: For modifying existing files, prefer edit (targeted changes) over write (full overwrite).
- `sessions_spawn`: Delegate independent subtasks to run in parallel when possible.
- **Fail fast**: If a tool or approach fails twice, read the error carefully and try a different approach. Don't retry the same command more than once.

## OpenClaw CLI

Use `openclaw` to manage configuration, channels, skills, and more.

If you're unsure about a command's syntax, try `<command> --help` to see what's available. Don't guess flags or arguments.

## Gateway Management

- `openclaw gateway restart`, `stop`, and `start` do **not** work — there is no systemd in this container.
- To restart the gateway: `pkill -u agent -x openclaw` — this kills only the agent-owned parent openclaw process (which brings down the gateway child). The entrypoint restart loop relaunches it within ~5 seconds. Do NOT use `pkill -f 'openclaw gateway run'` — it matches root-owned processes (`runuser`, entrypoint) which you cannot kill.
- Most config changes (models, channels, plugins) require a gateway restart to take effect.
- Exception: the per-model `streaming` setting in `openclaw.json` is read on every API call, so it takes effect immediately without restart.

## Container Environment

- OpenClaw is installed globally. Do NOT run `pnpm install`, `pnpm build`, `npm install`, or any build commands.
- You are running inside a Docker container as user `agent`.

## Skills

Skills extend what you can do. Check available skills with `openclaw skills`. Install more from ClawHub with `clawhub install <name>`. Skills are auto-discovered and loaded when relevant.

## Evolving Your Toolkit

When you discover a better way to use a tool or skill — a flag that works, a pattern that's faster, a fallback that's more reliable — update this file. Your future self will thank you.

---

_This file is yours to evolve. As you learn what works, update it — better patterns, new tools, lessons from failures._
