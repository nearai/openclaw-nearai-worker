# TOOLS.md - Local Notes

Skills define _how_ tools work. This file is for _your_ specifics — the stuff that's unique to your setup.

## Environment

This container includes: python3/pip, node/npm/pnpm/bun, git, brew, curl, wget, jq, and standard Unix tools.

## Tool Selection Guide

- `web_fetch`: Preferred for simple HTTP requests — fetching web pages, public APIs, articles. Handles timeouts and redirects automatically.
- `exec` + `curl`: For requests needing custom headers, auth tokens, POST bodies, or piping to `jq`. Always use `--connect-timeout 5 --max-time 10` to fail fast.
- `edit` over `write`: For modifying existing files, prefer edit (targeted changes) over write (full overwrite).
- `sessions_spawn`: Delegate independent subtasks to run in parallel when possible.
- **Fail fast**: If a tool or approach fails twice, switch to an alternative immediately. Don't retry the same command with minor variations.

## OpenClaw CLI

Use `openclaw` to manage configuration, channels, skills, and more. Run `openclaw --help` to explore.

## Skills

Skills extend what you can do. Check available skills with `openclaw skills`. Install more from ClawHub with `clawhub install <name>`. Skills are auto-discovered and loaded when relevant.

## Evolving Your Toolkit

When you discover a better way to use a tool or skill — a flag that works, a pattern that's faster, a fallback that's more reliable — update this file. Your future self will thank you.

---

_This file is yours to evolve. As you learn what works, update it — better patterns, new tools, lessons from failures._
