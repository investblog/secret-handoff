# secret-handoff

Move an API key, token or password between AI-agent sessions and projects without any agent, chat
or log ever seeing the value.

Two pieces:

- **`handoff.py`** — a locked box outside every repository (`~/.agents-secrets`). The sender `put`s
  a value from a file (or the owner from the clipboard); the receiver `take`s it into its own
  secret file. The value is never printed, never on a command line, never in the box's log.
  Sessions tell each other only the parcel's name.
- **`guard/secrets-guard.sh`** — a `PreToolUse` hook for Claude Code and Codex that blocks any tool
  call naming a secret file (`.env*`, `.dev.vars`, anything under `.secrets/`, `*.pem`, `id_rsa`,
  the box itself) and lets exactly one thing through: a single-line call of this skill's launcher.

## Why

An agent that needs a token has three bad ways to get it: you paste it into the chat (it stays in
the transcript), it reads `.env` (the value enters its context), or another session messages it
over (a message is a transcript too). The rule that fixes this is simple — *an agent may use a
value, never see it* — but it needs a way for a value to cross from one place to another that is
neither a chat nor a file the agent can read. That is the box.

## Install

The guard trusts the launcher only at one place, in your home folder, so clone there:

```sh
git clone https://github.com/investblog/secret-handoff ~/.agents/skills/secret-handoff
```

Requires Python 3 (`python3`, `python` or `py -3`; set `AGENTS_PYTHON` to pick one) and, on
Windows, Git Bash.

**As a Claude Code skill** (so the agent knows the protocol): link the folder into
`~/.claude/skills/secret-handoff` — `ln -s ~/.agents/skills/secret-handoff ~/.claude/skills/secret-handoff`,
or on Windows `New-Item -ItemType Junction -Path $HOME\.claude\skills\secret-handoff -Target $HOME\.agents\skills\secret-handoff`.

**The guard in Claude Code** — `~/.claude/settings.json` (or a project's `.claude/settings.json`).
The matcher must name every tool that reads files or runs commands — `Grep` too, which reads
contents, and `PowerShell` on Windows: a tool it leaves out runs unguarded.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read|Edit|Write|Grep|Bash|PowerShell",
        "hooks": [
          {
            "type": "command",
            "command": "git -c \"alias.agent-hook=!bash ~/.agents/skills/secret-handoff/guard/secrets-guard.sh\" agent-hook --claude; exit $LASTEXITCODE"
          }
        ]
      }
    ]
  }
}
```

The `git -c alias…` launcher looks odd on purpose: the same string has to run under PowerShell and
`sh`, a bare `bash` from PowerShell is WSL's launcher, and git's `!` alias always runs Git Bash.
`; exit $LASTEXITCODE` keeps the guard's exit code 2 (a block) instead of PowerShell's 1. It works
outside a repository too. On macOS and Linux `bash ~/.agents/skills/secret-handoff/guard/secrets-guard.sh --claude`
is enough.

**The guard in Codex** — `~/.codex/config.toml`:

```toml
[[hooks.PreToolUse]]
matcher = "Bash|apply_patch"

[[hooks.PreToolUse.hooks]]
type = "command"
command = 'git -c "alias.agent-hook=!bash ~/.agents/skills/secret-handoff/guard/secrets-guard.sh" agent-hook --codex; exit $LASTEXITCODE'
statusMessage = "secrets-guard"
```

Codex runs a hook it did not ship only after you review and trust it: open `/hooks` in Codex and
trust this one.

Prove the hook with a real agent call, not by running the script: ask the agent to read a file
under `.secrets/` (it must be blocked) and to run `bash ~/.agents/skills/secret-handoff/handoff.sh list`
(it must pass).

## Use

```sh
bash ~/.agents/skills/secret-handoff/handoff.sh put  <name> --from <file> [--line N | --key VAR] [--remove-source]
bash ~/.agents/skills/secret-handoff/handoff.sh put  <name> --clipboard
bash ~/.agents/skills/secret-handoff/handoff.sh take <name> --into <secret file> [--key VAR]
bash ~/.agents/skills/secret-handoff/handoff.sh drop <name>
bash ~/.agents/skills/secret-handoff/handoff.sh list
```

Between two sessions: the sender `put`s and messages the receiver the parcel's name and what it
is; the receiver `take`s it into its own secret store and confirms by name; the sender passes
`--remove-source` if it no longer needs its copy. [SKILL.md](SKILL.md) has the whole protocol.

**You put a secret yourself.** Copy it, then in the agent's prompt:

```
! py -3 $HOME/.agents/skills/secret-handoff/handoff.py put <name> --clipboard      (Windows)
! python3 ~/.agents/skills/secret-handoff/handoff.py put <name> --clipboard        (macOS, Linux)
```

Never type the value into a `!` command: the whole line lands in the transcript. The clipboard does
not. The answer names the parcel and its length; the clipboard is cleared if it still holds the
secret. A clipboard history (Windows Win+V, macOS, a Linux clipboard manager) may keep a copy —
clear it there.

## What it guarantees, and what it does not

- `take` writes only into a file the guard guards — checked both as written and once links are
  resolved, so a link out of `.secrets/` is refused — never into the box, never into a file that is
  itself a symlink or a hard link, never over an existing file (with `--key`, never over an
  existing variable). Every file is created empty and locked (owner, SYSTEM and Administrators on
  Windows; `0600`/`0700` elsewhere) before the value is written.
- A parcel is claimed by an atomic rename, so two `take`s cannot both get it; one that fails puts
  it back without overwriting a newer parcel of the same name.
- The box must be an absolute folder named `.agents-secrets` outside any git worktree, and is
  re-locked on every call.

The guard is a **seatbelt against an agent's mistake, not a wall against an agent set on getting
through**. A path built at run time (`.sec''rets`, a glob, a variable, a script that joins the
name) is not seen; a file swapped by another process between the check and the write is not
caught; a patch's whole text is scanned, so an `apply_patch` to a document that merely mentions
`.env` is refused. And it **fails open**: with no Python, or a hook input it cannot parse, it lets
the call through rather than lock the agent out — check that Python resolves where the hook runs.

## How it was tested

`tests/guard_cases.py` feeds 37 tool calls to the guard script, in both its Claude and its Codex
mode — secret paths in every part of a path, Grep's glob, commands chained to the handoff call,
launchers outside your home. It tests the script, not your agent's settings: the real-call check
above does that. `tests/handoff_cases.py` runs the box in a temporary sandbox and fails if the
value ever shows in the output or the log; it covers put, take, drop, refusals and the box's
location, not the clipboard (which would touch yours) or two takes racing:

```sh
python3 tests/guard_cases.py            # on Windows: py -3 tests/guard_cases.py "C:/Program Files/Git/bin/bash.exe"
python3 tests/handoff_cases.py
```

Both pieces went through several rounds of review by a second model; its catches included a newline
that let a second command ride on an allowed call, a look-alike launcher path, a symlink out of
`.secrets/`, and `icacls /grant:r` leaving an old grant to Everyone in place. An earlier version of
the guard checked only the last part of a path, so `cat .secrets/key.txt` passed: the test set
above is what caught it.

## License

MIT
