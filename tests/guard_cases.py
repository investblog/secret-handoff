"""Feeds tool calls to guard/secrets-guard.sh and checks each verdict (exit 2 = blocked).

    python tests/guard_cases.py [path to bash]

On Windows pass Git Bash's path (a bare "bash" from Windows Python starts WSL's launcher, where the
guard finds no Python and lets everything through):
    py -3 tests/guard_cases.py "C:/Program Files/Git/bin/bash.exe"
"""
import json
import os
import shutil
import subprocess
import sys

GUARD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "guard", "secrets-guard.sh")
BASH = sys.argv[1] if len(sys.argv) > 1 else shutil.which("bash")
HOME = os.path.expanduser("~").replace("\\", "/")
H = "~/.agents/skills/secret-handoff/handoff.sh"
S = ".sec" + "rets"  # kept apart so no tool that runs this file trips on it
E = ".e" + "nv"
cases = [
    # Secret paths, in every part of a path and every spelling.
    ("deny", {"file_path": f"{S}/user-x.txt"}),
    ("deny", {"file_path": f"C:\\projects\\x\\{S}\\a.txt"}),
    ("deny", {"command": f"cat {S}/a.txt"}),
    ("deny", {"command": "ls ~/.agents-secrets/inbox"}),
    ("deny", {"file_path": f"{HOME}/.agents-secrets/inbox/k"}),
    ("deny", {"command": f"cat {E}"}),
    ("deny", {"file_path": f"{E}.local"}),
    ("deny", {"file_path": f"{E}/key"}),
    ("deny", {"file_path": "certs/a.pem/x"}),
    ("deny", {"file_path": ".dev.vars"}),
    ("deny", {"file_path": "/home/u/.ssh/id_ed25519"}),
    ("deny", {"pattern": "KEY", "glob": E}),  # Grep reads contents: its glob counts
    ("deny", {"pattern": "KEY", "path": S}),
    # The handoff exception: nothing chained to it, only the launcher in this user's home.
    ("deny", {"command": f"bash {H} take k --into {S}/k.txt; cat {S}/k.txt"}),
    ("deny", {"command": f"bash {H} take k --into {S}/k.txt && cat x"}),
    ("deny", {"command": f"bash {H} put k --from $(cat {S}/a)"}),
    ("deny", {"command": f"bash {H} put k --from {S}/a.txt\ncat {S}/a.txt"}),
    ("deny", {"command": f"bash {H} list\ncat {E}"}),
    ("deny", {"command": f"bash {H} list\r\ncat {E}"}),
    ("deny", {"command": f"bash {H} put k --from {S}/a.txt > out.txt"}),
    ("deny", {"command": f"bash {H} drop k && cat {S}/a.txt"}),
    ("deny", {"command": f"bash /tmp/evil/handoff.sh put k --from {S}/a.txt"}),
    ("deny", {"command": f"bash evil.agents/skills/secret-handoff/handoff.sh put k --from {E}"}),
    ("deny", {"command": f"bash /tmp/x/.agents/skills/secret-handoff/handoff.sh put k --from {S}/a.txt"}),
    ("deny", {"command": f"bash ~/x/.agents/skills/secret-handoff/handoff.sh put k --from {S}/a.txt"}),
    ("deny", {"command": f"bash C:/Users/Public/.agents/skills/secret-handoff/handoff.sh put k --from {S}/a.txt"}),
    ("allow", {"command": f"bash {H} put api-key --from {S}/key-a.txt --line 1"}),
    ("allow", {"command": f"bash {H} take api-key --into {S}/app.env --key API_KEY"}),
    ("allow", {"command": f"bash {H} list"}),
    ("allow", {"command": f"bash {H} drop api-key"}),
    ("allow", {"command": f"bash \"{HOME}/.agents/skills/secret-handoff/handoff.sh\" list"}),
    ("allow", {"command": f"git -c \"alias.handoff=!bash {H}\" handoff take k --into {S}/k.txt"}),
    # Ordinary work goes on.
    ("allow", {"file_path": f"{E}.example"}),
    ("allow", {"file_path": f"{E}.sample"}),
    ("allow", {"pattern": "TODO", "glob": "*.md"}),
    ("allow", {"command": "node scripts/build.mjs"}),
    ("allow", {"file_path": "docs/notes.md"}),
]
bad = 0
for want, ti in cases:
    tool = "Bash" if "command" in ti else "Grep" if "pattern" in ti else "Read"
    r = subprocess.run([BASH, GUARD, "--claude"], input=json.dumps({"tool_name": tool, "tool_input": ti}), capture_output=True, text=True)
    got = "deny" if r.returncode == 2 else "allow"
    # The Codex mode answers the same, as JSON on stdout.
    c = subprocess.run([BASH, GUARD, "--codex"], input=json.dumps({"tool_name": tool, "tool_input": ti}), capture_output=True, text=True)
    if ('"permissionDecision":"deny"' in c.stdout) != (got == "deny"):
        got = "mismatch between --claude and --codex"
    bad += got != want
    print(("ok  " if got == want else "BAD ") + f"{want:5} {list(ti.values())[0]!r}")
print(f"{len(cases) - bad}/{len(cases)} as expected")
sys.exit(1 if bad else 0)
