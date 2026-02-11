# safe-agent-sandbox

Runs untrusted code from AI agents in locked-down containers. Python, Node.js, Bash -- and now Claude Code itself.

Works on macOS (Docker Desktop) and Linux (containerd or Docker). Picks the best backend automatically.

## Running it locally

You need Go 1.22+ and Docker. On macOS that means Docker Desktop. On Linux you can use Docker Engine or containerd directly.

```bash
# pull the runtime images first (only need to do this once)
docker pull python:3.12-slim
docker pull node:20-slim
docker pull alpine:3.19

# build and run
make build
make run
```

The server starts on `:8080`. No database or config file required -- it'll use sane defaults and skip audit logging if Postgres isn't around.

Try it out:

```bash
# python
curl -s -X POST http://localhost:8080/execute \
  -H "Content-Type: application/json" \
  -d '{"code": "print(sum(range(100)))", "language": "python"}'

# node
curl -s -X POST http://localhost:8080/execute \
  -H "Content-Type: application/json" \
  -d '{"code": "console.log(Array.from({length:10},(_,i)=>i*i))", "language": "node"}'

# bash
curl -s -X POST http://localhost:8080/execute \
  -H "Content-Type: application/json" \
  -d '{"code": "echo hello from sandbox && uname -a", "language": "bash"}'
```

Response looks like:

```json
{
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "output": "4950\n",
  "exit_code": 0,
  "duration": "45.2ms"
}
```

### Performance

The first execution for a given language is slow (~1-2s) because Docker has to create the container from scratch -- pull layers into cache, set up the filesystem overlay, start the process. After that first run, subsequent executions of the same language are much faster (~100-250ms) because Docker caches the image layers and the overlay setup is quicker.

On Linux with containerd, cold starts are faster (~500ms) and warm starts can get under 50ms. The codebase has a container pool stub (`internal/sandbox/pool.go`) meant to pre-warm containers for near-instant startup, but that's not wired up yet.

If you're running this in production and latency matters, keep a steady trickle of requests going so the Docker image cache stays warm. Or run on Linux with containerd.

For streaming output (useful for long-running code), use the SSE endpoint:

```bash
curl -N -X POST http://localhost:8080/execute/stream \
  -H "Content-Type: application/json" \
  -d '{"code": "import time\nfor i in range(5):\n    print(i)\n    time.sleep(0.5)", "language": "python"}'
```

You'll see events arrive in real time as the code prints.

## Running Claude Code in the sandbox

This is the interesting part. You can run Claude Code itself inside a sandbox container -- it can do real dev work on your project while being jailed so it can't read your SSH keys, exfiltrate data, or mess with anything outside the project directory.

### Setup

First, build the Claude image:

```bash
make claude-image
```

This installs `@anthropic-ai/claude-code` into a `node:20-slim` container. Takes a minute or two.

You'll also need Claude auth. The sandbox passes auth to the container via environment variables -- nothing from `~/.claude/` is mounted. Set `CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY` in the server's environment and it'll forward them into the container automatically.

If you're on Claude Max, you can extract your OAuth token with `claude setup-token`, or grab it from the macOS keychain. If you have an API key, just export `ANTHROPIC_API_KEY`.

### Using it

With the CLI:

```bash
# point it at your project and give it a prompt
./bin/sandbox-cli claude "list the files and summarize the project structure" --dir ./my-project

# defaults to current directory if you don't pass --dir
./bin/sandbox-cli claude "add error handling to the main function"
```

Or via the API:

```bash
curl -s -X POST http://localhost:8080/execute \
  -H "Content-Type: application/json" \
  -d '{
    "code": "find all TODO comments in the codebase and list them",
    "language": "claude",
    "work_dir": "/absolute/path/to/project"
  }'
```

The `code` field is the prompt. `work_dir` is the project directory that gets mounted into the container at `/workspace`.

### What's different about the Claude runtime

Unlike python/node/bash which run in a completely locked-down box, Claude needs a few things:

- **Network access** -- it has to reach `api.anthropic.com`. The container gets `--network bridge` instead of `--network none`. This does mean it can reach the broader internet, which is a known tradeoff. If that bothers you, set up a firewall rule or network policy to restrict egress.
- **Higher resource limits** -- 1GB RAM, 200 PIDs, 500MB disk, 2 CPUs (vs 256MB/50 PIDs/100MB for code runtimes). Claude spawns subprocesses to do its work.
- **Longer timeout** -- 5 minutes instead of 10 seconds. Real dev tasks take time.
- **Writable workspace** -- the project dir is mounted read-write so Claude can actually edit files.
- **Runs as UID 1000** instead of nobody, since it needs to write to `~/.claude/` inside the container.

Everything else stays the same: read-only rootfs, all caps dropped, no-new-privileges, seccomp. The sandbox is the security boundary -- Claude runs with `--dangerously-skip-permissions` inside because the container itself is the jail.

### Security notes

The Claude runtime is Docker-only (not containerd) because of the network requirements. If you try to run it on the containerd backend, you'll get an error.

Auth is passed via environment variables (`CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY`), not by mounting host config directories. Nothing from your home directory is exposed to the container.

The e2e tests include adversarial cases that verify the container blocks things like reading `/etc/shadow`, accessing SSH keys, writing to the rootfs, using `mount()`, `chroot()`, `setuid(0)`, and so on. These are deterministic container security tests, not "ask Claude to be bad" tests.

### With Postgres (optional)

If you want the audit log and execution history endpoints, spin up a Postgres instance and point the config at it:

```bash
# quick and dirty with docker
docker run -d --name sandbox-pg -e POSTGRES_USER=sandbox -e POSTGRES_PASSWORD=sandbox -e POSTGRES_DB=sandbox -p 5432:5432 postgres:15

# run the migration
psql "postgres://sandbox:sandbox@localhost:5432/sandbox?sslmode=disable" -f internal/storage/migrations/001_initial.sql

# start the server (it'll pick up the DSN from configs/config.yaml)
make run
```

### With Docker Compose

If you want the full stack (server + postgres + prometheus):

```bash
docker-compose -f deployments/docker-compose.yml up
```

## How it works

Code never lives inside the container image. The server writes submitted code to a host temp file, bind-mounts it read-only into a fresh container, runs it, captures output, and tears the container down. The whole lifecycle is managed per-request.

On Linux it tries containerd first (fastest, native cgroup/namespace control). Everywhere else it shells out to `docker run` with equivalent security flags. Both backends enforce the same restrictions.

### Request flow

1. Request goes through middleware (rate limiting, auth, body size limit, request ID)
2. Handler validates the request and runs a basic escape-attempt detector (advisory only, doesn't block)
3. Backend grabs a concurrency slot, writes code to a temp dir
4. Container starts with the security profile applied, code mounted read-only at `/workspace`
5. stdout/stderr captured (or streamed over SSE)
6. Container killed + cleaned up on completion or timeout
7. Result optionally logged to Postgres, response sent back

### Container security

Every container runs with:
- Read-only root filesystem
- No network (unless you explicitly enable it, or use the claude runtime)
- All capabilities dropped
- Seccomp filtering (deny-by-default on containerd, Docker's default profile elsewhere)
- PID limit of 50, memory limit of 256MB, no swap
- Non-root user (nobody/65534)
- `no-new-privileges` flag
- Timeout (default 10s, hard max 60s)

The Claude runtime gets higher limits (1GB RAM, 200 PIDs, 5min timeout) and network access, but keeps all the other restrictions.

The idea is defense in depth. Even if one layer fails, the others should hold.

### Threat model

The attacker is an AI agent with full control over the code string. The goal is to keep them from escaping to the host.

What we defend against:
- **Kernel exploits** (dirty cow, etc) -- seccomp blocks dangerous syscalls, caps dropped, user namespaces, NoNewPrivileges
- **Resource exhaustion** (fork bombs, OOM) -- PID limit, memory cap, disk quota, timeout
- **Network escape** -- network namespace isolated, `--network none`, seccomp blocks socket calls
- **Filesystem access** -- read-only rootfs, code injected via RO bind mount, no host paths exposed
- **Process introspection** (ptrace) -- PID namespace, seccomp blocks ptrace
- **API abuse** -- rate limiting per IP, 1MB body limit, concurrency cap

Invariants: no container touches the host filesystem, no container reaches the network (unless opted in), no container affects other containers, no container exhausts host resources, all containers get cleaned up even on panic.

## API

All endpoints return JSON. Errors look like `{"error": "...", "code": "SOME_CODE", "request_id": "uuid"}`.

If you configure API keys in the config, pass them as `X-API-Key` or `Authorization: Bearer <key>`.

### POST /execute

Run code and get the result back.

```json
{
  "code": "print('hello')",
  "language": "python",
  "timeout": "10s",
  "limits": {
    "memory_mb": 256,
    "pids_limit": 50,
    "disk_mb": 100
  },
  "permissions": {
    "network": { "enabled": false }
  }
}
```

`language` is required (`python`, `node`, `bash`, `claude`). `code` is required (max 1MB). Everything else has defaults.

For Claude, `code` is the prompt and you probably want to pass `work_dir` too:

```json
{
  "code": "refactor the auth module to use JWT",
  "language": "claude",
  "work_dir": "/path/to/project"
}
```

Response:

```json
{
  "id": "uuid",
  "output": "hello\n",
  "stderr": "",
  "exit_code": 0,
  "duration": "45.2ms",
  "resource_usage": { "cpu_time_ms": 12, "memory_peak_mb": 24, "pids_used": 1 },
  "security_events": []
}
```

`exit_code` is -1 on timeout. `output` is capped at 1MB, `stderr` at 256KB.

### POST /execute/stream

Same request body. Returns an SSE stream instead:

```
event: stdout
data: hello

event: stderr
data: some warning

event: done
data: {"id":"...","exit_code":0,"duration":"45.2ms"}
```

### GET /executions

List recent executions (needs Postgres). Filter with `?language=python` or `?status=timeout`.

### GET /executions/{id}

Full details for one execution.

### DELETE /executions/{id}

Kill a running execution.

### GET /health

Returns `{"status": "ok", ...}` with backend and database info.

### GET /metrics

Prometheus metrics. `sandbox_executions_total`, `sandbox_execution_duration_seconds`, `sandbox_active_executions`, `sandbox_security_events_total`, etc.

## Configuration

Edit `configs/config.yaml` or just run with the defaults. The main things you might want to change:

```yaml
sandbox:
  backend: "auto"        # auto, containerd, or docker
  max_concurrent: 1000
  default_timeout: 10s
  max_timeout: 60s
  default_limits:
    memory_mb: 256
    pids_limit: 50
    disk_mb: 100

security:
  rate_limit_rps: 100
  allowed_keys: []       # empty = no auth

tls:
  enabled: false
  cert_file: ""
  key_file: ""
```

Postgres is optional. Without it you just don't get the audit log / execution history endpoints.

You can also set `CONFIG_PATH` env var to point to a different config file, or `PORT` to override the listen port.

## Runtimes

| Language | Image | Command |
|----------|-------|---------|
| python | python:3.12-slim | `python3 -u -B <file>` |
| node | node:20-slim | `node --max-old-space-size=256 <file>` |
| bash | alpine:3.19 | `/bin/sh -e -u <file>` |
| claude | sandbox-claude:latest | `claude -p --dangerously-skip-permissions` |

Adding a new runtime means adding a file in `internal/runtime/` that implements the `Runtime` interface and registering it in the registry.

## Development

```bash
make build          # build server + cli
make test           # all tests
make test-unit      # unit tests only (no docker needed)
make test-e2e       # e2e security tests (needs docker)
make claude-image   # build the claude sandbox image
make lint           # golangci-lint
make security-scan  # gosec
make vulncheck      # govulncheck (dependency CVEs)
make ci             # run everything CI runs (build, vet, tests, security, lint)
make setup          # install dev tools (gosec, govulncheck, golangci-lint, gofumpt)
```

`make ci` mirrors the GitHub Actions pipeline exactly, so if it passes locally it'll pass in CI. The e2e tests spin up real containers and try escape attempts (fork bombs, filesystem writes, network access, mount syscalls, chroot, setuid) to make sure the sandbox holds.

## Project layout

```
cmd/server/          entrypoint
cmd/cli/             cli client
internal/api/        http handlers, middleware, sse streaming
internal/sandbox/    container execution (containerd + docker backends)
internal/runtime/    language runtime configs
internal/monitor/    prometheus metrics, escape detection heuristics
internal/storage/    postgres audit log
internal/config/     config loading
pkg/seccomp/         seccomp profile builder
```

## License

MIT
