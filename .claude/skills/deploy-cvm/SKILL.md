---
name: deploy-cvm
description: Deploy local changes to the dev TDX CVM
disable-model-invocation: true
allowed-tools: Bash, Read, Glob, Grep
---

# Deploy to Dev CVM

Deploy all local changes to the TDX CVM dev environment.

## Target
- SSH host: `tdx` (ProxyJump through gpu26, port 10022)
- Code path on CVM: `/home/root/openclaw/`
- Guest OS: Alpine/BusyBox (no rsync)

## Steps

1. **Check connectivity**:
   ```
   ssh tdx "echo ok"
   ```

2. **Detect changed files** using `git diff --name-only HEAD` and `git status --short` to find all modified/untracked files.

3. **Sync all changed files** to the CVM, preserving directory structure. Use `scp` for each file/directory since the CVM lacks rsync. Sync to `/home/root/openclaw/`.

4. **Rebuild compose-api** if any `compose-api/` files changed:
   ```
   ssh tdx "cd /home/root/openclaw/compose-api && docker build --build-arg CACHEBUST=$(date +%s) -t openclaw-compose-api:local ."
   ```

5. **Rebuild worker** if any `worker/` files changed:
   ```
   ssh tdx "cd /home/root/openclaw/worker && docker build --build-arg CACHEBUST=$(date +%s) -t openclaw-nearai-worker:local ."
   ```

6. **Redeploy** containers:
   ```
   ssh tdx "cd /home/root/openclaw && docker compose -f deploy/docker-compose.dstack.yml --env-file deploy/.env.dstack up -d"
   ```

7. **Verify** deployment:
   ```
   ssh tdx "curl -s http://localhost:8080/version"
   ```

## Important notes
- Always run from the project root directory
- The CVM is Alpine/BusyBox - no rsync, limited GNU flags
- Build output can be long - watch for errors at the end
- After deploy, verify with the version endpoint
