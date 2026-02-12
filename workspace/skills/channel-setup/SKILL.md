---
name: channel-setup
description: Help the user connect a messaging channel (Telegram, Discord, WhatsApp, etc.) to OpenClaw
---

# Channel Setup

OpenClaw supports 23+ chat platforms. Full docs: https://docs.openclaw.ai/channels/index

CLI reference: https://docs.openclaw.ai/cli/channels

## Example: Telegram

1. Message **@BotFather** on Telegram, send `/newbot`, follow prompts, save the token
2. Add to your OpenClaw config (`~/.openclaw/openclaw.json`):
   ```json
   {
     "channels": {
       "telegram": {
         "enabled": true,
         "botToken": "YOUR_TOKEN_HERE",
         "dmPolicy": "pairing",
         "groups": { "*": { "requireMention": true } }
       }
     }
   }
   ```
   Or set env var: `TELEGRAM_BOT_TOKEN=...`
3. Restart the gateway, then message your bot on Telegram
4. Approve pairing: `openclaw pairing list telegram` → `openclaw pairing approve telegram <CODE>`
5. Verify: `openclaw channels list`

## Other Channels

- `openclaw channels add --channel <provider> --token <token>`
- `openclaw channels list` — show all configured channels
- `openclaw channels status` — check runtime status
- `openclaw channels remove --channel <provider>` — remove a channel
