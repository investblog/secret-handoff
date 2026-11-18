#!/usr/bin/env bash
# secrets-guard — PreToolUse hook: block a tool call that reads/writes a secret file.
# Mode: --claude (exit 2 + stderr) | --codex (JSON permissionDecision deny).
# Reads the tool-call JSON on stdin; checks file paths AND shell commands (cross-agent,
# catches e.g. `cat .env`). *.example/.sample/.template are allowed (templates).
# Python absent -> fail-open (allow); resolve AGENTS_PYTHON/python3/python/py -3.
[ -n "${AGENTS_DEBUG:-}" ] && set -x   # opt-in trace: AGENTS_DEBUG=1
run_python() {
  if [ -n "${AGENTS_PYTHON:-}" ]; then "$AGENTS_PYTHON" "$@"; return $?; fi
  if command -v python3 >/dev/null 2>&1; then python3 "$@"; return $?; fi
  if command -v python >/dev/null 2>&1; then python "$@"; return $?; fi
  if command -v py >/dev/null 2>&1; then py -3 "$@"; return $?; fi
  return 127
}
mode="${1:---claude}"
# The Python body below sits in single quotes: a single quote anywhere in it (even in a comment)
# ends the string, and the guard then blocks or passes everything (2026-11-18). None in it.
verdict="$(run_python -c '
import sys,json,re
try:
    d=json.load(sys.stdin)
except Exception:
    print("ALLOW"); sys.exit(0)
ti=d.get("tool_input") or d.get("input") or {}
ti=ti if isinstance(ti,dict) else {}
text=" ".join(str(ti.get(k,"")) for k in ("file_path","path","filePath","glob","command","patch","patch_text"))
cmd=str(ti.get("command","")) if not any(ti.get(k) for k in ("file_path","path","filePath","glob","patch","patch_text")) else ""
SAFE=("example","sample","template")
def part(p):
    if p in (".secrets",".agents-secrets",".dev.vars",".env"): return True
    if p.endswith(".pem"): return True
    if p.startswith(("id_rsa","id_ed25519")): return True
    return p.startswith(".env.") and p.rsplit(".",1)[-1] not in SAFE
def secret(name):
    # Every part of the path, not only the last: .secrets/key.txt is as secret as .secrets.
    return any(part(p.lower()) for p in re.split(r"[/\\]+",name) if p)
# The one way through: a single call of the secret-handoff skill (it moves a value without printing
# it) from the library in the home folder, on one line, with no ; | & ` $ < > ( ) that could chain
# another command to it.
import os
def norm(p):
    # Resolved through links; letter case folded only where the file system folds it (Windows).
    if os.name=="nt":
        m=re.match(r"/([A-Za-z])/",p)
        p=m.group(1)+":/"+p[3:] if m else p
    return os.path.normcase(os.path.realpath(p))
LAUNCHER=norm(os.path.join(os.path.expanduser("~"),".agents/skills/secret-handoff/handoff.sh"))
H=r"\"?(?P<{0}>[^\s\";|&`$<>()]+)\"?"
HANDOFF=re.compile(r"[ \t]*(?:bash[ \t]+"+H.format("a")+r"|git[ \t]+-c[ \t]+\"alias\.handoff=!bash[ \t]+"+H.format("b")+r"\"[ \t]+handoff)[ \t]+(?:put|take|drop|list)(?:[ \t]+[^;|&`$<>()\r\n]*)?")
m=HANDOFF.fullmatch(cmd) if cmd and "\n" not in cmd and "\r" not in cmd else None
# Only the library in the home of the user running this: "~/..." or that home spelled out.
if m and norm(re.sub(r"^~",os.path.expanduser("~").replace("\\","/"),m.group("a") or m.group("b")))==LAUNCHER: print("ALLOW"); sys.exit(0)
print("DENY" if any(secret(t) for t in re.findall(r"[\w./\\-]+",text)) else "ALLOW")
' 2>/dev/null)"
[ "$verdict" = DENY ] || exit 0
msg="secrets-guard: blocked access to a secret file (.env/.dev.vars/.secrets/key). Use a value through a script, never read it; move it with secret-handoff."
case "$mode" in
  --codex) printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' "$msg" ;;
  *)       printf '%s\n' "$msg" >&2; exit 2 ;;
esac
exit 0
