#!/usr/bin/env python3
"""secret-handoff: move a secret from one project (or agent session) to another; no one sees it.

    handoff.sh put  <name> --from <file> [--line N | --key VAR] [--remove-source]
    handoff.sh put  <name> --clipboard
    handoff.sh take <name> --into <secret file> [--key VAR]
    handoff.sh drop <name>
    handoff.sh list

The box is ~/.agents-secrets (AGENTS_SECRETS_HOME may move it, to a folder of that same name, which
secrets-guard guards wherever it is): outside every repository, readable by the user, SYSTEM and
Administrators only; secrets-guard blocks any other tool call that names it. `put` copies a value
from a file into the box; `take` writes it into the receiver's own secret file and removes it from
the box. The value is never printed and never on a command line: sessions tell each other only the
parcel's name. `take` writes only where secrets-guard guards (a `.secrets` folder, `.env*`,
`.dev.vars`, `*.pem`), resolved through links, never into the box itself; every file is locked
before the value is written into it.
"""
import datetime
import getpass
import os
import re
import subprocess
import uuid
import sys

BOX_GIVEN = os.path.expanduser(os.environ.get("AGENTS_SECRETS_HOME") or "~/.agents-secrets")
BOX = os.path.realpath(BOX_GIVEN)
NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
VAR = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
SAFE = ("example", "sample", "template")
USAGE = __doc__.split("\n\n")[1]


def fail(msg, code=1):
    print(f"handoff: {msg}", file=sys.stderr)
    sys.exit(code)


def part(p):
    if p in (".secrets", ".agents-secrets", ".dev.vars", ".env") or p.endswith(".pem") or p.startswith(("id_rsa", "id_ed25519")):
        return True
    return p.startswith(".env.") and p.rsplit(".", 1)[-1] not in SAFE


def guarded(path):
    """The same test as hooks/secrets-guard: a path the agents' tools may not touch."""
    return any(part(p.lower()) for p in re.split(r"[/\\]+", path) if p)


def linked(path):
    """A link or junction (the path is not where it leads)."""
    return os.path.islink(path) or (hasattr(os.path, "isjunction") and os.path.isjunction(path))


def lock(path, folder=False):
    """Owner-only: chmod on POSIX; on Windows no inherited entries, full control for the user,
    SYSTEM and Administrators (by SID, as names are localized), inherited by what a folder holds."""
    if os.name != "nt":
        os.chmod(path, 0o700 if folder else 0o600)
        return
    me = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True).stdout.strip().split(",")[-1].strip('"')
    allowed = (me, "S-1-5-18", "S-1-5-32-544")
    inherit = "(OI)(CI)" if folder else ""

    def icacls(*args):
        r = subprocess.run(["icacls", path, *args], capture_output=True, text=True)
        if r.returncode != 0:
            raise OSError(f"could not lock {path}: {r.stdout.strip()} {r.stderr.strip()}")

    # Narrowing only, never a wider moment: no inheritance and the three grants first, then every
    # other explicit entry (an old grant to Everyone survives /grant:r) removed by its SID.
    icacls("/inheritance:r", "/grant:r", *[f"*{sid}:{inherit}F" for sid in allowed])
    env = {k: v for k, v in os.environ.items() if k.lower() != "psmodulepath"}
    quoted = path.replace("'", "''")
    sids = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         f"(Get-Acl -LiteralPath '{quoted}').Access | ForEach-Object {{ $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }}"],
        capture_output=True, text=True, env=env,
    )
    if sids.returncode != 0:
        raise OSError(f"could not read the ACL of {path}: {sids.stderr.strip()}")
    for sid in {s.strip() for s in sids.stdout.split()} - set(allowed):
        icacls("/remove:g", f"*{sid}", "/remove:d", f"*{sid}")


def new_locked(path):
    """An empty file made only by this call, locked before anything is written into it."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    try:
        lock(path)
    except Exception:
        os.remove(path)
        raise


def write(path, text, mode):
    with open(path, mode, encoding="utf-8", newline="\n") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())


def box():
    """The inbox, locked on every call: a box made before, or left half-made, is locked again."""
    if not os.path.isabs(BOX_GIVEN) or os.path.basename(BOX) != ".agents-secrets":
        fail(f"the box must be an absolute folder named .agents-secrets (secrets-guard guards that name): {BOX_GIVEN}")
    d = BOX  # the box itself too: it must not be a repository either
    while True:
        if os.path.exists(os.path.join(d, ".git")):
            fail(f"the box must be outside every repository: {BOX} is in {d}")
        if os.path.dirname(d) == d:
            break
        d = os.path.dirname(d)
    inbox = os.path.join(BOX, "inbox")
    for p in (BOX_GIVEN, inbox):
        if linked(p):
            fail(f"{p} is a link: refused")
    os.makedirs(inbox, exist_ok=True)
    lock(BOX, folder=True)
    lock(inbox, folder=True)
    return inbox


def log(line):
    path = os.path.join(BOX, "log")
    if linked(path):
        fail(f"{path} is a link: refused")
    if not os.path.exists(path):
        new_locked(path)
    write(path, f"{datetime.datetime.now().isoformat(timespec='seconds')} {getpass.getuser()} {os.getcwd()} {line}\n", "a")


def opts(args, allowed):
    out = {}
    if len(args) % 2:
        fail(USAGE, 2)
    for flag, value in zip(args[::2], args[1::2]):
        if flag not in allowed or flag in out or not value or value.startswith("--"):
            fail(USAGE, 2)
        out[flag] = value
    return out


def read_value(path, line=None, key=None):
    if not os.path.isfile(path):
        fail(f"no file {path}")
    with open(path, encoding="utf-8") as f:
        text = f.read()
    lines = text.splitlines()
    if line is not None:
        if not line.isdigit() or not 1 <= int(line) <= len(lines):
            fail(f"{path} has no line {line}")
        value = lines[int(line) - 1].strip()
    elif key is not None:
        found = [l.split("=", 1)[1].strip() for l in lines if "=" in l and l.split("=", 1)[0].strip() == key]
        if len(found) != 1:
            fail(f"{path} has {len(found)} lines {key}=..., not one")
        value = found[0]
    else:
        value = text.rstrip("\r\n")
    if not value:
        fail(f"the value taken from {path} is empty")
    return value


def clipboard(clear=False, quiet=False):
    """The clipboard's text (or, with clear, an empty clipboard), through the system's own tool.
    Its answer is captured here and never shown. Clearing empties the current clipboard only: a
    clipboard history or manager (Windows Win+V, macOS, Linux managers) may keep a copy."""
    if os.name == "nt":
        env = {k: v for k, v in os.environ.items() if k.lower() != "psmodulepath"}
        script = "Set-Clipboard -Value $null" if clear else "[Console]::OutputEncoding = [Text.Encoding]::UTF8; Get-Clipboard -Raw"
        cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Sta", "-Command", script]
    elif sys.platform == "darwin":
        cmd, env = (["pbcopy"] if clear else ["pbpaste"]), None
    elif os.environ.get("WAYLAND_DISPLAY"):
        cmd, env = (["wl-copy", "--clear"] if clear else ["wl-paste", "--no-newline"]), None
    else:
        cmd, env = ["xclip", "-selection", "clipboard"] + (["-i", "/dev/null"] if clear else ["-o"]), None
    try:
        r = subprocess.run(cmd, capture_output=True, input=b"" if clear else None, env=env)
    except FileNotFoundError:
        if clear or quiet:
            return False if clear else None
        fail(f"no clipboard tool ({cmd[0]})")
    if r.returncode != 0:
        if clear or quiet:
            return False if clear else None
        fail(f"could not read the clipboard ({cmd[0]} exited {r.returncode})")
    return True if clear else r.stdout.decode("utf-8", "replace").strip("\r\n")


def put(name, args):
    if "--clipboard" in args:
        # The owner's way in (`! ... put <name> --clipboard` in an agent's prompt): the value is
        # copied, never typed, so it is neither on the command line nor in the transcript.
        if args != ["--clipboard"]:
            fail(USAGE, 2)
        value, src = clipboard(), "the clipboard"
        if not value.strip():
            fail("the clipboard holds no text: copy the secret first")
        if len(value.encode("utf-8")) > 16384:
            fail("the clipboard holds more than 16 KB: not a single secret, refused")
        o, remove = {}, False
    else:
        remove = "--remove-source" in args
        args = [a for a in args if a != "--remove-source"]
        o = opts(args, ("--from", "--line", "--key"))
        if "--from" not in o or ("--line" in o and "--key" in o):
            fail(USAGE, 2)
        src = o["--from"]
        if remove and (linked(src) or not guarded(os.path.realpath(src)) or (os.path.exists(src) and os.stat(src).st_nlink > 1)):
            fail(f"--remove-source changes only a guarded secret file, not a link: {src}")
        value = read_value(o["--from"], o.get("--line"), o.get("--key"))
    parcel = os.path.join(box(), name)
    try:
        new_locked(parcel)
    except FileExistsError:
        fail(f"a parcel {name} is already in the box: take it, or pick another name")
    try:
        write(parcel, value, "w")
    except Exception:
        os.remove(parcel)
        raise
    done = ""
    if remove:
        # Only the entry taken goes; the file goes too when nothing but blanks and comments is left.
        with open(src, encoding="utf-8", newline="") as f:
            lines = f.read().splitlines(keepends=True)
        if "--line" in o:
            del lines[int(o["--line"]) - 1]
        elif "--key" in o:
            lines = [l for l in lines if not ("=" in l and l.split("=", 1)[0].strip() == o["--key"])]
        else:
            lines = []
        if all(not l.strip() or l.lstrip().startswith("#") for l in lines):
            os.remove(src)
            done = f"; {src} removed"
        else:
            write(src, "".join(lines), "w")
            done = f"; the entry removed from {src}"
    if src == "the clipboard" and clipboard(quiet=True) != value:
        # Something else was copied meanwhile: it is not ours to erase.
        done = "; the clipboard changed meanwhile and was left as it is - clear the secret from its history if it keeps one"
    elif src == "the clipboard":
        done = (
            "; the current clipboard cleared - a clipboard history or manager (Windows Win+V, macOS clipboard history, a Linux clipboard manager) may still keep a copy: clear it there"
            if clipboard(clear=True)
            else "; the clipboard could NOT be cleared: clear it yourself, and its history"
        )
    log(f"put {name} from {src}{done}")
    print(f"put {name} ({len(value)} characters) into the box{done}; tell the receiver the name only")


def check_dest(dest):
    """Where take may write: a guarded path, also once links are resolved; not the box; no link."""
    real = os.path.realpath(dest)
    if not guarded(os.path.abspath(dest)) or not guarded(real):
        fail(f"{dest} is not a guarded secret file (.secrets/..., .env*, .dev.vars, *.pem), or leads out of one: refused")
    try:
        inside = os.path.commonpath([os.path.normcase(real), os.path.normcase(BOX)]) == os.path.normcase(BOX)
    except ValueError:
        inside = False  # another drive
    if inside:
        fail(f"{dest} is inside the box: refused")
    if linked(dest) or (os.path.exists(dest) and os.stat(dest).st_nlink > 1):
        fail(f"{dest} is a link: refused")


def take(name, args):
    o = opts(args, ("--into", "--key"))
    dest, key = o.get("--into"), o.get("--key")
    if not dest:
        fail(USAGE, 2)
    if key is not None and not VAR.match(key):
        fail(f"{key} is not a variable name")
    base = os.path.basename(dest).lower()
    if key is not None and not (base.startswith(".env") or base.endswith(".env") or base == ".dev.vars"):
        fail(f"--key writes VAR=value into an env file (.env*, *.env, .dev.vars), not into {dest}")
    check_dest(dest)
    inbox = box()
    parcel = os.path.join(inbox, name)
    # Claimed by an atomic rename: two takes at once cannot both have it. A claim left by a take
    # that died stays visible in list.
    tag = uuid.uuid4().hex[:8]
    claimed = os.path.join(inbox, f".taking-{tag}-{name}")
    try:
        os.rename(parcel, claimed)
    except FileNotFoundError:
        fail(f"no parcel {name} in the box (handoff.sh list)")
    try:
        with open(claimed, encoding="utf-8") as f:
            value = f.read()
        if "\n" in value and key is not None:
            fail(f"{name} holds several lines: take it into a file of its own, without --key")
        os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
        if key is None:
            try:
                new_locked(dest)
            except FileExistsError:
                fail(f"{dest} exists: take into a new file, or into it with --key VAR")
            try:
                write(dest, value + "\n", "w")
            except Exception:
                os.remove(dest)
                raise
        else:
            made = not os.path.exists(dest)
            if made:
                new_locked(dest)
                old = ""
            else:
                lock(dest)
                with open(dest, encoding="utf-8", newline="") as f:
                    old = f.read()
                if any("=" in l and l.split("=", 1)[0].strip() == key for l in old.splitlines()):
                    fail(f"{dest} already has {key}: remove it first to replace it")
            size = os.path.getsize(dest)
            try:
                write(dest, ("" if not old or old.endswith("\n") else "\n") + f"{key}={value}\n", "a")
            except BaseException:
                # Undo a part-written line: the file as it was, or no file.
                if made:
                    os.remove(dest)
                else:
                    os.truncate(dest, size)
                raise
    except BaseException:
        # Nothing written, or the write undone: the parcel goes back for another take - without
        # replacing a parcel of the same name put meanwhile (a hard link cannot replace a file).
        if os.path.exists(claimed):
            try:
                os.link(claimed, parcel)
            except FileExistsError:
                back = f"{name[:44]}-returned-{tag}"
                os.link(claimed, os.path.join(inbox, back))
                print(f"handoff: a new parcel {name} came meanwhile; this one is back as {back}", file=sys.stderr)
            os.remove(claimed)
        raise
    os.remove(claimed)
    log(f"take {name} into {os.path.abspath(dest)}{' as ' + key if key else ''}")
    print(f"took {name} into {dest}{' as ' + key if key else ''}; the box no longer holds it")


def show():
    inbox = box()
    names = sorted(os.listdir(inbox))
    for n in names:
        if n.startswith(".taking-"):
            print(f"{n}\tclaimed by a take that did not finish: the owner renames it to its name (after the tag) by hand to take it again")
            continue
        st = os.stat(os.path.join(inbox, n))
        print(f"{n}\t{datetime.datetime.fromtimestamp(st.st_mtime).isoformat(timespec='minutes')}")
    if not names:
        print("the box is empty")


def drop(name, args):
    """A parcel deleted unread: one put by mistake, or one no one will take."""
    if args:
        fail(USAGE, 2)
    parcel = os.path.join(box(), name)
    try:
        os.remove(parcel)
    except FileNotFoundError:
        fail(f"no parcel {name} in the box (handoff.sh list)")
    log(f"drop {name}")
    print(f"dropped {name}: deleted unread")


def main(argv):
    try:
        if argv[:1] == ["list"] and len(argv) == 1:
            return show()
        if len(argv) < 2 or argv[0] not in ("put", "take", "drop") or not NAME.match(argv[1]):
            fail(USAGE, 2)
        if argv[0] == "drop":
            return drop(argv[1], argv[2:])
        (put if argv[0] == "put" else take)(argv[1], argv[2:])
    except OSError as e:
        # The message names a path and the reason, never a value.
        fail(f"{type(e).__name__}: {e.strerror or e} ({e.filename or ''})")


if __name__ == "__main__":
    main(sys.argv[1:])
