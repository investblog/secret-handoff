---
name: secret-handoff
description: Move a secret (API key, token, password) from one project or agent session to another without anyone seeing it - a locked box outside every repository, `put` by the sender, `take` by the receiver, only the parcel's name in messages. Use whenever a secret has to cross a project or session boundary.
---

# secret-handoff

A secret that one project made and another needs (an API key issued by a script, a token for a
second service) used to cross by hand: the owner opened one secret file and pasted into another.
Agents cannot do it: `secrets-guard` (`guard/secrets-guard.sh`) blocks the tool calls it matches that name a secret file, and a
message between sessions is a transcript - never a place for a value. This skill is the one sanctioned way
through: the value moves file to file, and the sessions say only its name.

## The box
`~/.agents-secrets/` (`AGENTS_SECRETS_HOME` overrides): `inbox/<name>` holds a parcel, `log` records
who put or took what, when - names, never values. Outside every repository; on Windows readable by
the user, SYSTEM and Administrators only (by SID), on POSIX `0700`/`0600`. `secrets-guard` treats
the folder as secret, so a tool call naming it is blocked unless it is this skill's. The guard is a
seatbelt, not a wall: it sees only the tools its matcher names, misses a path built at run time,
and lets calls through when Python is missing - never try to get past it.

## Commands
Run with the Bash tool (Git Bash on Windows), from the project's root, one call alone on the line -
`secrets-guard` lets exactly that through, and nothing chained to it:

```
bash ~/.agents/skills/secret-handoff/handoff.sh put  <name> --from <file> [--line N | --key VAR] [--remove-source]
bash ~/.agents/skills/secret-handoff/handoff.sh put  <name> --clipboard
bash ~/.agents/skills/secret-handoff/handoff.sh take <name> --into <secret file> [--key VAR]
bash ~/.agents/skills/secret-handoff/handoff.sh drop <name>
bash ~/.agents/skills/secret-handoff/handoff.sh list
```

An agent whose shell is PowerShell (bare `bash` there is WSL) runs it through git, from the repo
top: `git -c "alias.handoff=!bash ~/.agents/skills/secret-handoff/handoff.sh" handoff take ...`.

- **put**: `--from` a file; the value is its line N, its `VAR=` line, or the whole file. A name
  already in the box is refused. Names: lowercase letters, digits, `.`, `_`, `-`.
  `--remove-source` (only a guarded secret file, never a link) takes the entry out of the source
  once the parcel is in the box: with `--line` or `--key` that line goes, and the file goes too if
  nothing but blanks and comments is left; without them the whole file goes.
  `--clipboard` instead of `--from`: the value is the clipboard's text; the clipboard is cleared
  after if it still holds that value (see *The owner puts a secret*).
- **take**: `--into` must be a file `secrets-guard` guards (under `.secrets/`, `.env*` but not
  `*.example/.sample/.template`, `.dev.vars`, `*.pem`) - so the value never lands where an agent may
  read it. Without `--key` it makes a new file (an existing one is refused); with `--key VAR` it
  appends `VAR=value` to an env file (a VAR already there is refused). The parcel is then deleted.
- **drop**: delete a parcel unread - one put by mistake, or one no one will take.
- **list**: the names waiting and when they came.

## The owner puts a secret (`!` in an agent's prompt)
A secret the owner holds (a token from a dashboard, a password from a manager) goes into the box
without passing through the chat. The value is never typed: a `!` command is shown in the
transcript, the clipboard is not.

1. Copy the secret to the clipboard.
2. In the agent's prompt, run the line for the machine (`$HOME` works in PowerShell and Git Bash
   alike):
   - Windows: `! py -3 $HOME/.agents/skills/secret-handoff/handoff.py put <name> --clipboard`
   - macOS / Linux: `! python3 ~/.agents/skills/secret-handoff/handoff.py put <name> --clipboard`
3. The answer names the parcel and its length, never the value, and says what became of the
   clipboard: cleared if it still held the secret, left alone if something else was copied
   meanwhile, or not cleared if the system tool failed (then clear it yourself). A clipboard history or manager may still hold the copy - Windows (Win+V), macOS
   clipboard history, a Linux clipboard manager: clear it there.
4. Tell the agent what the parcel is and where it goes; the agent `take`s it into the project's
   secret file and confirms by name.

An empty clipboard, or more than 16 KB in it, is refused. Pick a name that says what it is and for
whom: `cloudflare-token-blog`, `stripe-key-shop`.

## The protocol between sessions
1. The sender `put`s, then messages the receiver: the parcel's name, what it is (service, account,
   scopes, expiry), and where the receiver's project keeps such a secret if the sender knows.
   Never the value, never a prefix longer than the service shows in its own lists.
2. The receiver `take`s it into its own secret store, following its project's convention, and
   confirms by name.
3. The sender keeps no copy it does not need: `put --remove-source` when the source file held only
   this secret and the receiver is now its only user.

A parcel left in the box is a secret lying around: `list` in the closing check of a session that
put one.
