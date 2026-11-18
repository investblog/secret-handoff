"""Runs handoff.py in a sandbox (a box and two fake projects in a temporary folder) and checks
what it does and what it says: the value must never appear in its output or its log.

    python tests/handoff_cases.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

HANDOFF = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "handoff.py")
root = tempfile.mkdtemp(prefix="handoff-test-")
S = ".sec" + "rets"
BOX = os.path.join(root, ".agents-secrets")
sender, receiver = os.path.join(root, "sender"), os.path.join(root, "receiver")
os.makedirs(os.path.join(sender, S))
os.makedirs(receiver)
VALUE = "tok_SANDBOX-VALUE-123"
with open(os.path.join(sender, S, "key.txt"), "w", encoding="utf-8") as f:
    f.write(f"{VALUE}\n# a comment line\n")
with open(os.path.join(sender, S, "app.env"), "w", encoding="utf-8") as f:
    f.write(f"OTHER=1\nAPI_KEY={VALUE}\n")
with open(os.path.join(sender, "plain.txt"), "w", encoding="utf-8") as f:
    f.write("not a secret\n")
env = {**os.environ, "AGENTS_SECRETS_HOME": BOX}
bad = 0


def run(cwd, *args, want=0):
    global bad
    r = subprocess.run([sys.executable, HANDOFF, *args], cwd=cwd, env=env, capture_output=True, text=True)
    leaked = VALUE in r.stdout or VALUE in r.stderr
    ok = r.returncode == want and not leaked
    bad += not ok
    print(("ok  " if ok else "BAD ") + f"{' '.join(args)} -> {r.returncode}{' LEAKED' if leaked else ''}: {(r.stdout + r.stderr).strip()[:140]}")


def check(label, cond):
    global bad
    bad += not cond
    print(("ok  " if cond else "BAD ") + label)


inbox = os.path.join(BOX, "inbox")
try:
    run(sender, "put", "k1", "--from", f"{S}/key.txt", "--line", "1")
    run(sender, "put", "k1", "--from", f"{S}/key.txt", "--line", "1", want=1)  # already in the box
    run(sender, "put", "k2", "--from", f"{S}/app.env", "--key", "API_KEY")
    run(sender, "put", "k3", "--from", f"{S}/key.txt", "--line", "9", want=1)
    run(sender, "put", "K_bad", "--from", f"{S}/key.txt", want=2)
    run(sender, "put", "k4", "--from", f"{S}/key.txt", "--line", want=2)
    run(sender, "put", "k5", "--from", "plain.txt", "--remove-source", want=1)  # not a secret file
    with open(os.path.join(sender, S, "multi.env"), "w", encoding="utf-8") as f:
        f.write("KEEP=1\nMOVE=two\n")
    run(sender, "put", "k6", "--from", f"{S}/multi.env", "--key", "MOVE", "--remove-source")
    with open(os.path.join(sender, S, "multi.env"), encoding="utf-8") as f:
        check("--remove-source with --key removes only that entry", f.read() == "KEEP=1\n")
    run(sender, "list")
    run(receiver, "take", "k1", "--into", "notes.txt", want=1)  # not a guarded file
    run(receiver, "take", "k1", "--into", f"{S}/key.txt")
    run(receiver, "take", "k1", "--into", f"{S}/again.txt", want=1)  # gone from the box
    run(receiver, "take", "k2", "--into", os.path.join(BOX, "log"), "--key", "T", want=1)  # into the box
    run(receiver, "take", "k2", "--into", f"{S}/key.txt", want=1)  # exists: refused...
    check("...and the refused parcel is back in the box", sorted(os.listdir(inbox)) == ["k2", "k6"])
    run(receiver, "take", "k6", "--into", f"{S}/cert.pem", "--key", "MOVE", want=1)  # --key into a non-env file
    outside = os.path.join(root, "plain")
    os.makedirs(outside)
    try:
        os.symlink(outside, os.path.join(receiver, S, "via"), target_is_directory=True)
        run(receiver, "take", "k2", "--into", f"{S}/via/leak.txt", want=1)  # a link out of the guarded folder
        check("nothing written through the link", os.listdir(outside) == [])
    except OSError:
        print("--  symlink case skipped (no right to make links here)")
    run(receiver, "take", "k2", "--into", ".env", "--key", "API_KEY")
    run(receiver, "drop", "k6")
    run(receiver, "drop", "k6", want=1)
    with open(os.path.join(receiver, S, "key.txt"), encoding="utf-8") as f:
        check("take into a file holds the value", f.read() == VALUE + "\n")
    with open(os.path.join(receiver, ".env"), encoding="utf-8") as f:
        check("take --key appends VAR=value", f.read() == f"API_KEY={VALUE}\n")
    check("the box is empty", os.listdir(inbox) == [])
    with open(os.path.join(BOX, "log"), encoding="utf-8") as f:
        log = f.read()
    check("the log names parcels, never the value", "put k1" in log and "drop k6" in log and VALUE not in log)
    if os.name == "nt":
        # By SID, not by name: group names are localized.
        me = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True).stdout.strip().split(",")[-1].strip('"')
        psenv = {k: v for k, v in os.environ.items() if k.lower() != "psmodulepath"}
        sids = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f"(Get-Acl -LiteralPath '{BOX}').Access | ForEach-Object {{ $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }}"],
            capture_output=True, text=True, env=psenv,
        ).stdout.split()
        check("the box is locked (only the user, SYSTEM and Administrators)", bool(sids) and set(sids) <= {me, "S-1-5-18", "S-1-5-32-544"})
    env["AGENTS_SECRETS_HOME"] = ".agents-secrets"
    run(receiver, "list", want=1)  # a relative box
    os.makedirs(os.path.join(root, "repo", ".git"))
    env["AGENTS_SECRETS_HOME"] = os.path.join(root, "repo", "x", ".agents-secrets")
    run(receiver, "list", want=1)  # a box inside a repository
finally:
    shutil.rmtree(root, ignore_errors=True)
print("all as expected" if not bad else f"{bad} unexpected")
sys.exit(1 if bad else 0)
