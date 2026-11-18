#!/usr/bin/env python3
"""The agent hook that blocks (architecture/0029, #194): before an agent edits a file, runs a shell command or calls an
MCP tool, it asks ArchBeagle's MCP tool `authorize` whether that may go ahead, and denies the call when ArchBeagle says
`deny`.

    python3 arch_hook.py --client claude|codex|cursor|text [--url URL] [--managed [--on-unreachable deny|allow]]
    python3 arch_hook.py --client claude|codex --event session_start [--url URL]

It reads the hook's JSON on stdin:

* `claude`: Claude Code's `PreToolUse` for Edit, Write, MultiEdit, Read, Grep, Bash and `mcp__*` tools;
* `codex`: Codex's `PreToolUse` for `apply_patch` (the patch in `tool_input.command`), Bash and `mcp__*` tools;
* `cursor`: Cursor's `preToolUse` (Write), `beforeReadFile`, `beforeShellExecution` and `beforeMCPExecution`;
* `text`: any of those, answered as plain text, for trying it by hand.

**What it sends:** the repository, the action (`edit` with the paths it writes and the imports it adds, found here
from the edit's new and old text; `read` with the path a read tool opens, judged against the account's list of paths
agents never read, architecture/0083; or `tool` with the tool's name), and the session's ID when the client gives one.
Never a file's contents or a prompt. A shell command's text only when ArchBeagle asks for it (architecture/0083,
question 6): while the account lists commands agents never run, a shell call's answer says `needs_command`, and the hook
asks again with the text, at most 8,000 characters; ArchBeagle matches it in memory and keeps only its SHA-256. Codex
has no read tool (it reads through the shell), so a read there is never asked about.

**What it does with the answer:**
* `deny`: the call is denied, with the rule, the reason and who may approve it once (Claude Code and Codex:
  `permissionDecision: "deny"`; Cursor: `permission: "deny"`);
* `allow` with a warning (a rule in `warn` mode): the call goes ahead through the client's normal permission flow,
  and the warning is shown; a plain `allow` prints nothing. The hook never grants a permission.
The deny and warning texts are ArchBeagle's, and cover every rule `authorize` judges: TASK-1, ARCH-DEP-3, ARCH-INF-1,
and another agent's lease, LEASE-1 and LEASE-2 (architecture/0036). The session's ID is what makes an edit the lease
holder's own; a subagent's event carries its parent's.

**Its cache:** an `allow` is kept for the answer's `cache_seconds` (five minutes; 30 seconds while LEASE-1 blocks,
and not at all for an answer with a lease finding) in a file of the person's own
(`ARCH_HOOK_CACHE`, by default `~/.cache/archbeagle/hook-cache.json`), keyed by a digest of the endpoint, the token and
the request; a `deny` is never kept, so an override takes effect on the next try.

**When ArchBeagle can't answer** (no network, a timeout, a server error, `429`, an answer it can't read): it fails open,
saying "ArchBeagle unreachable: not checked" with why in brackets to the person and the model, and appends a line to
`~/.archbeagle/hook.log`. When ArchBeagle answers and won't judge (a repository of another account, #1298), it says so
in ArchBeagle's words, "ArchBeagle refused to judge this: …", with what to do for another account's repository, the log
line `refused`. With `ARCHBEAGLE_HOOK_ON_FAILURE=block`, a repository's choice, it denies instead. Not configured (no
token or no URL): it does nothing. Its whole run is bounded by `ARCH_HOOK_TIMEOUT` seconds (default 2, at most 10).

**Managed** (`--managed`, architecture/0083, step 3): the mode of the install an organisation places with device
management (Settings → Agent policy builds it), which a developer can't remove. With no token it denies, saying how to
make one; when ArchBeagle can't answer it denies, unless the package says `--on-unreachable allow`, and no environment
variable loosens that; every request says `managed`, so Settings counts the sessions that ran it. Session start still
never blocks. Claude Code's and Cursor's managed configs also block when the hook itself fails (`onFailure: "block"`,
`failClosed: true`). Codex has no managed install yet.

**Its local test check** (architecture/0049, #583), run on the machine before nothing else is sent: an edit to a test
file that adds a skip (`pytest.mark.skip`, `xfail`, `it.skip`, `.only`, `t.Skip()` …) or removes assertions, or a shell
command or patch that deletes a test file, adds a warning naming `TEST-SKIP-1`, `TEST-ASSERT-1` or `TEST-DEL-1` to
whatever ArchBeagle answers. Nothing of the edit or the command leaves the machine for it, and it never denies: the pull
request's check judges the change.

**At session start** (`--event session_start`, architecture/0034, step 6; Claude Code's and Codex's `SessionStart`): one
call of the MCP tool `agent_instructions` for the repository, with the client's session ID as `session_key` (so
ArchBeagle records on the session the revision it served) and the client's files (`claude` for Claude Code, `agents_md`
for Codex). It reads the ArchBeagle markers of those files in the checkout (the same parser as the sync script in
`agents/sync/`, kept the same by tests/agents/test_hooks.py) and prints:
* every file current: one line, `ArchBeagle: architecture files current (revision N).`;
* a file stale, edited inside ArchBeagle's part, malformed or absent: the reason and ArchBeagle's `session_context`, at
  most 8,000 characters, as `hookSpecificOutput.additionalContext`, which the client adds to the session;
* ArchBeagle unreachable within the deadline (2 seconds): `ArchBeagle unreachable: architecture context not loaded`. It
  always exits 0: nothing blocks a session start, whatever `ARCHBEAGLE_HOOK_ON_FAILURE` says.

Settings, from the environment:
* ARCH_MCP_TOKEN: the agent's token (agents/README.md). Without it, the hook does nothing.
* ARCH_MCP_URL: the MCP endpoint, unless `--url` gives it. Never read from the repository being edited, so a
  repository can't send your token somewhere else.
* ARCH_REPO: `owner/name`, when the checkout's `origin` remote doesn't say it.
* ARCH_HOOK_TIMEOUT, ARCH_HOOK_CACHE, ARCHBEAGLE_HOOK_ON_FAILURE (`open`, the default, or `block`).

Standard library only; Python 3.10 or newer.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any

MAX_ITEMS = 100  # authorize takes at most 100 paths and 100 imports per call
MAX_COMMAND = 8_000  # the most of a shell command's text sent, and only when ArchBeagle asks for it (architecture/0083)
MAX_BYTES = 1_000_000  # an edit larger than this isn't read
FROM_IMPORT = re.compile(r"^\s*from\s+([A-Za-z_][\w.]*)\s+import\b", re.MULTILINE)
PLAIN_IMPORT = re.compile(r"^\s*import\s+([A-Za-z_][\w.]*(?:\s+as\s+\w+)?(?:\s*,\s*[A-Za-z_][\w.]*(?:\s+as\s+\w+)?)*)")
GITHUB = re.compile(r"github\.com[:/]+([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?$")
STDLIB = frozenset(getattr(sys, "stdlib_module_names", ())) | {"__future__"}
EDIT_TOOLS = {"Edit", "Write", "MultiEdit", "apply_patch"}
#: Claude Code's tools that open a file the agent names (architecture/0083): Read's `file_path`, Grep's `path`. A Grep
#: over a folder is asked about the folder only, never the files inside it.
READ_TOOLS = {"Read", "Grep"}
#: The name a shell command is judged under in a task's `allowed_tools`, whichever client runs it.
SHELL = "Bash"
#: ArchBeagle's own MCP tools (the server is named `archbeagle` in the kit's client configs) aren't judged: reporting
#: work and asking the architecture are never blocked.
ARGUS = ("mcp__archbeagle__", "archbeagle")
UNREACHABLE = (
    "ArchBeagle unreachable: not checked. The repository's own check and the PR's TASK-1 still judge this change."
)
#: ArchBeagle answered, and wouldn't judge the edit (#1298): its own words, then what still judges the change.
REFUSED = (
    "ArchBeagle refused to judge this: {why}. Not checked: the repository's own check and the PR's TASK-1 still "
    "judge it."
)
#: What to do when the repository isn't the token's account's (#1298): a token of another account knows nothing of it.
OTHER_ACCOUNT = "isn't a repository of this token's account"
OTHER_ACCOUNT_HINT = ' Use a token of the account that holds this repository (agents/README.md, "Your token").'
BLOCKED_UNREACHABLE = (
    "ArchBeagle unreachable, and this repository fails closed (ARCHBEAGLE_HOOK_ON_FAILURE=block): denied."
)
#: Under a managed install (architecture/0083): what a missing token and an unreachable ArchBeagle deny with.
MANAGED_NO_TOKEN = (
    "ArchBeagle: your organisation's agents ask ArchBeagle first, and this machine has no agent token "
    "(ARCH_MCP_TOKEN): denied. Make your own in ArchBeagle, Settings → Connect an agent ({where}), and put it in "
    "your shell's profile."
)
MANAGED_UNREACHABLE = "ArchBeagle unreachable, and your organisation's managed install fails closed: denied."
#: At session start (architecture/0034): each client's files, and what the hook prints.
SESSION_TARGETS = {"claude": ["claude"], "codex": ["agents_md"]}
SESSION_CONTEXT_MAX = 8_000
SESSION_CURRENT = "ArchBeagle: architecture files current (revision {revision})."
SESSION_UNREACHABLE = "ArchBeagle unreachable: architecture context not loaded"


class Deadline:
    def __init__(self, seconds: float) -> None:
        self.end = time.monotonic() + seconds

    def left(self) -> float:
        remaining = self.end - time.monotonic()
        if remaining <= 0.05:
            raise TimeoutError("the hook's time is up")
        return remaining


class Unreachable(Exception):
    """ArchBeagle gave no answer the hook can use."""


# ── what the call does ───────────────────────────────────────────────────────


def imports(text: str) -> set[str]:
    """The absolute modules a piece of Python imports, outside the standard library. Relative imports are left out."""
    found = set(FROM_IMPORT.findall(text))
    for line in text.splitlines():
        m = PLAIN_IMPORT.match(line)
        if m:
            found.update(part.split()[0] for part in m.group(1).split(","))
    return {m for m in found if m.split(".")[0] not in STDLIB}


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")[:MAX_BYTES] if path.is_file() else ""
    except (OSError, UnicodeDecodeError):
        return ""


def _absolute(path: str, cwd: str) -> Path:
    p = Path(path)
    return p if p.is_absolute() else Path(cwd or ".") / p


def _patch_text(command: Any) -> str:
    if isinstance(command, list):
        command = next((c for c in command if isinstance(c, str) and "*** Begin Patch" in c), "")
    return command if isinstance(command, str) else ""


def patch_edits(patch: str, cwd: str) -> list[tuple[Path, str, str]]:
    """(file, added lines, removed lines) per file of an `apply_patch` patch: `*** Add File:`, `*** Update File:` (and
    its `*** Move to:`), `*** Delete File:` (a write too)."""
    files: dict[str, tuple[list[str], list[str]]] = {}
    current: str | None = None
    for line in patch.splitlines():
        if line.startswith(("*** Add File: ", "*** Update File: ", "*** Delete File: ")):
            current = line.split(": ", 1)[1].strip()
            files.setdefault(current, ([], []))
            if line.startswith("*** Delete File: "):
                current = None
        elif line.startswith("*** Move to: ") and current is not None:
            moved = line.split(": ", 1)[1].strip()
            files[moved] = files.pop(current)
            current = moved
        elif line.startswith("*** End Patch"):
            current = None
        elif current is not None and line.startswith("+"):
            files[current][0].append(line[1:])
        elif current is not None and line.startswith("-"):
            files[current][1].append(line[1:])
    return [(_absolute(p, cwd), "\n".join(add), "\n".join(rem)) for p, (add, rem) in files.items()]


def edits(tool: str, inp: dict[str, Any], cwd: str) -> list[tuple[Path, str, str]]:
    """(file, new text, old text) for an edit tool, from any client: the new and old text only find the imports the
    edit adds; neither is sent."""
    if tool == "apply_patch":
        return patch_edits(_patch_text(inp.get("command") or inp.get("patch") or inp.get("input")), cwd)
    path = next((inp[k] for k in ("file_path", "path", "target_file") if isinstance(inp.get(k), str)), None)
    if path is None:
        return []
    file = _absolute(path, cwd)
    if isinstance(inp.get("edits"), list):
        changes = [e for e in inp["edits"] if isinstance(e, dict)]
        new = "\n".join(str(e.get("new_string") or "") for e in changes)
        return [(file, new, "\n".join(str(e.get("old_string") or "") for e in changes))]
    if tool == "Write" or "content" in inp or "contents" in inp:
        return [(file, str(inp.get("content") or inp.get("contents") or ""), _read(file))]
    return [(file, str(inp.get("new_string") or ""), str(inp.get("old_string") or ""))]


def action_of(
    event: dict[str, Any], client: str, kind: str | None = None
) -> tuple[str, str, list[tuple[Path, str, str]]] | None:
    """What the call does: ("edit", tool, edits), ("read", tool, [(file, "", "")]), ("tool", tool name, []), or None
    for a call the hook doesn't judge. Cursor's read, shell and MCP hooks are named by `kind` (`--event`, from the
    config) or the event's `hook_event_name`; everything else by `tool_name`. A read's contents are never read here."""
    raw = event.get("tool_input")
    inp: dict[str, Any] = raw if isinstance(raw, dict) else {}
    cwd = str(event.get("cwd") or "")
    hook = kind or {"beforeShellExecution": "shell", "beforeMCPExecution": "mcp", "beforeReadFile": "read"}.get(
        str(event.get("hook_event_name") or ""), "tool"
    )
    if client == "cursor" and hook == "read":
        opened = event.get("file_path")
        return ("read", "Read", [(_absolute(opened, cwd), "", "")]) if isinstance(opened, str) and opened else None
    if client == "cursor" and hook == "shell":
        return "tool", SHELL, []
    if client == "cursor" and hook == "mcp":
        # Cursor names it `mcp_server_name` (its hooks page, read 2026-11-17); the others are kept for older builds
        server = str(event.get("mcp_server_name") or event.get("server") or event.get("server_name") or "").strip()
        name = str(event.get("tool_name") or "").strip()
        if not name or server.lower() in ARGUS:
            return None
        return "tool", f"mcp__{server}__{name}" if server else f"mcp__{name}", []
    tool = str(event.get("tool_name") or "")
    if tool.startswith(ARGUS[0]):
        return None
    if tool in READ_TOOLS:
        opened = inp.get("file_path") or inp.get("path")
        return ("read", tool, [(_absolute(opened, cwd), "", "")]) if isinstance(opened, str) and opened else None
    if tool in EDIT_TOOLS or (client == "codex" and tool in ("Edit", "Write")):
        found = edits(tool, inp, cwd)
        return ("edit", tool, found) if found else None
    if tool in ("Bash", "Shell", "shell"):
        return "tool", SHELL, []
    if tool.startswith("mcp__"):
        return "tool", tool, []
    return None


# ── the local test check (architecture/0049, #583) ────────────────────────────

#: A test file, by name or folder: the same rule as the contracts' `review.is_test_path` (tests/agents keep them equal).
TEST_NAME = re.compile(
    r"(^test_.*\.py$|.*_test\.py$|.*_test\.go$|.*\.(test|spec)\.(js|jsx|ts|tsx|mjs|cjs|mts|cts)$|^conftest\.py$)"
)
TEST_FOLDERS = ("tests", "test", "__tests__", "spec")
SKIP_MARK = re.compile(
    r"(@pytest\.mark\.(skip|skipif|xfail)\b|@unittest\.(skip|skipIf|skipUnless|expectedFailure)\b"
    r"|\b(it|test|describe)\.(skip|only|todo)\s*\(|\b(xit|xtest|xdescribe|fit|fdescribe)\s*\(|\bt\.Skip(f|Now)?\s*\()"
)
ASSERTION = re.compile(
    r"^\s*(assert\b|self\.assert\w*\(|expect\(|assert\.\w+\(|require\.\w+\(|t\.(Error|Errorf|Fatal|Fatalf)\()",
    re.MULTILINE,
)
DELETE = re.compile(r"(?:^|[;&|]\s*)(?:git\s+rm|rm|unlink)\s+([^;&|\n]+)")
NOT_JUDGED = "The PR's check judges it; on an agent's pull request it needs a person's approval."


def is_test_path(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return bool(parts) and (bool(TEST_NAME.match(parts[-1])) or any(p in TEST_FOLDERS for p in parts[:-1]))


def _relative(file: Path, cwd: str) -> str:
    try:
        return file.resolve().relative_to(Path(cwd or ".").resolve()).as_posix()
    except (OSError, ValueError):
        return file.name


def _command(event: dict[str, Any]) -> str:
    raw = event.get("tool_input")
    inp: dict[str, Any] = raw if isinstance(raw, dict) else {}
    command = inp.get("command", event.get("command"))
    if isinstance(command, list):
        command = " ".join(str(c) for c in command)
    return command if isinstance(command, str) else ""


def local_test_findings(event: dict[str, Any], client: str, kind: str | None = None) -> list[tuple[str, Path, str]]:
    """The local test check's findings for one hook event, each (rule ID, file, warning). Reads only the event and the
    files it edits; ArchBeagle is sent the rule ID and the path alone (`authorize`'s `local`)."""
    cwd = str(event.get("cwd") or "")
    out: list[tuple[str, Path, str]] = []
    found = action_of(event, client, kind)
    if found is not None and found[0] == "edit":
        for file, new, old in found[2]:
            rel = _relative(file, cwd)
            if not is_test_path(rel):
                continue
            if len(SKIP_MARK.findall(new[:MAX_BYTES])) > len(SKIP_MARK.findall(old[:MAX_BYTES])):
                said = f"ArchBeagle (TEST-SKIP-1): this edit skips a test, or adds .only, in {rel}. {NOT_JUDGED}"
                out.append(("TEST-SKIP-1", file, said))
            if len(ASSERTION.findall(old[:MAX_BYTES])) > len(ASSERTION.findall(new[:MAX_BYTES])):
                said = f"ArchBeagle (TEST-ASSERT-1): this edit removes assertions from {rel}. {NOT_JUDGED}"
                out.append(("TEST-ASSERT-1", file, said))
    deleted: list[str] = []
    for match in DELETE.finditer(_command(event)):
        deleted += [w for w in match.group(1).split() if not w.startswith("-")]
    patch = _patch_text(
        (event.get("tool_input") or {}).get("command") if isinstance(event.get("tool_input"), dict) else ""
    )
    deleted += [line.split(": ", 1)[1].strip() for line in patch.splitlines() if line.startswith("*** Delete File: ")]
    for path in deleted:
        file = _absolute(path.strip("'\""), cwd)
        rel = _relative(file, cwd)
        if is_test_path(rel):
            out.append(("TEST-DEL-1", file, f"ArchBeagle (TEST-DEL-1): this deletes the test file {rel}. {NOT_JUDGED}"))
    return out[:10]


def local_test_warnings(event: dict[str, Any], client: str, kind: str | None = None) -> list[str]:
    """The local test check's warnings for one hook event."""
    return [text for _, _, text in local_test_findings(event, client, kind)]


# ── the repository ───────────────────────────────────────────────────────────


def _git(args: list[str], where: Path, deadline: Deadline) -> str | None:
    try:
        done = subprocess.run(
            ["git", "-C", str(where), *args],
            capture_output=True,
            text=True,
            timeout=min(deadline.left(), 1.0),
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.strip() if done.returncode == 0 else None


def _existing(path: Path) -> Path:
    for parent in (path, *path.parents):
        if parent.is_dir():
            return parent
    return Path(".")


def locate(where: Path, cwd: str, deadline: Deadline) -> tuple[str | None, Path]:
    """The repository (`owner/name`) a place is in, and its root."""
    place = _existing(where)
    root = _git(["rev-parse", "--show-toplevel"], place, deadline)
    repo = os.environ.get("ARCH_REPO") or None
    if repo is None and root:
        remote = _git(["remote", "get-url", "origin"], place, deadline) or ""
        m = GITHUB.search(remote)
        repo = m.group(1) if m else None
    return repo, Path(root) if root else Path(cwd or ".")


def _with_local(
    out: list[dict[str, Any]], local: list[tuple[str, Path, str]], cwd: str, deadline: Deadline
) -> list[dict[str, Any]]:
    """Each local test finding as `{rule_id, path}` on the request for its repository, its path from that root."""
    by_repo = {entry["repo"]: entry for entry in out}
    for rule, file, _ in local:
        repo, root = locate(file.parent, cwd, deadline)
        if repo not in by_repo:
            continue
        try:
            rel = file.resolve().relative_to(root.resolve()).as_posix()
        except (OSError, ValueError):
            continue
        by_repo[repo].setdefault("local", []).append({"rule_id": rule, "path": rel})
    return out


def requests(
    event: dict[str, Any], client: str, deadline: Deadline, kind: str | None = None,
    local: list[tuple[str, Path, str]] | None = None,
) -> list[dict[str, Any]]:  # fmt: skip
    """The `authorize` calls a hook event makes: one per repository an edit writes in or a read opens, or one for a
    tool, each with the local test check's findings in its repository."""
    found = action_of(event, client, kind)
    if found is None:
        return []
    kind, tool, changes = found
    cwd = str(event.get("cwd") or "")
    session = event.get("session_id") or event.get("conversation_id")
    extra = {"session_key": str(session)[:200]} if isinstance(session, str) and session else {}
    if kind == "tool":
        repo, _ = locate(Path(cwd or "."), cwd, deadline)
        asked = [{"repo": repo, "action": "tool", "tool": tool, **extra}] if repo else []
        return _with_local(asked, local or [], cwd, deadline)
    by_repo: dict[str, dict[str, Any]] = {}
    for file, new, old in changes:
        repo, root = locate(file.parent, cwd, deadline)
        if not repo:
            continue
        try:
            rel = file.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            rel = file.as_posix()
        entry = by_repo.setdefault(repo, {"repo": repo, "action": kind, "paths": [], "imports": [], **extra})
        if rel not in entry["paths"]:
            entry["paths"].append(rel)
        if file.suffix == ".py":
            added = sorted(imports(new[:MAX_BYTES]) - imports(old[:MAX_BYTES]))
            entry["imports"] += [{"from_path": rel, "module": m} for m in added]
    out = []
    for entry in by_repo.values():
        entry["paths"], entry["imports"] = entry["paths"][:MAX_ITEMS], entry["imports"][:MAX_ITEMS]
        if not entry["imports"]:
            del entry["imports"]
        out.append(entry)
    return _with_local(out, local or [], cwd, deadline) if kind == "edit" else out


# ── the markers: a copy of the sync script's parser (agents/sync/), kept the same by tests/agents/test_hooks.py ──

MARKER_VERSION = 1
MARKER_TARGETS = ("agents_md", "claude", "cursor", "copilot", "import_linter", "dependency_cruiser", "go_arch_lint")
_FIELDS = (
    r"v=(?P<v>\d+) target=(?P<target>[a-z_]+) repo=(?P<repo>[A-Za-z0-9._-]+/[A-Za-z0-9._-]+) "
    r"revision=(?P<revision>\d+) renderer=(?P<renderer>\d+) digest=(?P<digest>sha256:[0-9a-f]{64})"
)
BEGIN = re.compile(rf"^<!-- argus:begin {_FIELDS} -->$")
END = re.compile(r"^<!-- argus:end -->$")
FILE = re.compile(rf"^<!-- argus:file {_FIELDS} -->$")
_ANY = re.compile(r"<!--\s*argus:(begin|end|file)\b")
BOM = "﻿"


def _lf(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def body_digest(body: str) -> str:
    return "sha256:" + hashlib.sha256(_lf(body).encode("utf-8")).hexdigest()


def _front_matter_end(lines: list[str]) -> int:
    if not lines or lines[0].rstrip("\n") != "---":
        return 0
    for i in range(1, len(lines)):
        if lines[i].rstrip("\n") == "---":
            return i + 1
    return 0


def _marker(line: str, kind: str) -> re.Match[str] | None:
    found = {"begin": BEGIN, "end": END, "file": FILE}[kind].match(line.strip())
    if found is None or kind == "end":
        return found
    return found if int(found["v"]) == MARKER_VERSION and found["target"] in MARKER_TARGETS else None


def parse_markers(text: str) -> dict[str, Any]:
    """`state` (`ok`, `absent` or `malformed`), the marker's `revision`, `digest` and `renderer`, and the found body's
    `body_digest`."""
    lines = _lf(text.removeprefix(BOM)).splitlines(keepends=True)

    def observed(state: str, marker: re.Match[str] | None = None, body: str | None = None) -> dict[str, Any]:
        return {
            "state": state,
            "revision": int(marker["revision"]) if marker else None,
            "digest": marker["digest"] if marker else None,
            "body_digest": body_digest(body) if body is not None else None,
            "renderer": int(marker["renderer"]) if marker else None,
        }

    marked = [(i, m[1]) for i, line in enumerate(lines) if (m := _ANY.search(line))]
    if not marked:
        return observed("absent")
    parsed = {i: _marker(lines[i], kind) for i, kind in marked}
    first = next((parsed[i] for i, kind in marked if kind != "end" and parsed[i]), None)
    kinds = [kind for _, kind in marked]
    start = _front_matter_end(lines)
    if kinds == ["file"] and marked[0][0] == start and (header := parsed[start]):
        return observed("ok", header, "".join(lines[start + 1 :]))
    if kinds == ["begin", "end"] and (begin := parsed[marked[0][0]]) and parsed[marked[1][0]]:
        b, e = marked[0][0], marked[1][0]
        return observed("ok", begin, "".join(lines[b + 1 : e]))
    return observed("malformed", first)


# ── ArchBeagle ────────────────────────────────────────────────────────────────────


class Refused(Exception):
    """ArchBeagle answered, and refused the call (a repository not in the model, no approved revision yet)."""


def tool_result(url: str, token: str, tool: str, arguments: dict[str, Any], deadline: Deadline) -> dict[str, Any]:
    """One `tools/call` over Streamable HTTP, and the tool's structured answer. The server is stateless and answers in
    JSON, so no `initialize` is needed. Raises `Refused` for a tool error, `Unreachable` for anything else."""
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}
    ).encode()
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": "arch-hook/2",
        },
    )
    try:
        # The URL is the person's own (--url or ARCH_MCP_URL), never the repository's
        with urllib.request.urlopen(request, timeout=deadline.left()) as response:
            raw = response.read(MAX_BYTES).decode("utf-8", "replace")
        if raw.lstrip().startswith(("event:", "data:")):
            raw = "\n".join(line[5:].strip() for line in raw.splitlines() if line.startswith("data:"))
        message = json.loads(raw)
    except (OSError, ValueError, TimeoutError) as exc:  # URLError and HTTPError are OSErrors
        raise Unreachable(str(exc)[:200]) from exc
    result = message.get("result") if isinstance(message, dict) else None
    if not isinstance(result, dict):
        raise Unreachable(f"{tool} gave no answer")
    if result.get("isError"):  # the tool's own words, which say why (#1298)
        said = " ".join(str(p.get("text") or "") for p in result.get("content") or [] if isinstance(p, dict))
        raise Refused(said.strip()[:300] or f"{tool} refused")
    structured = result.get("structuredContent")
    if isinstance(structured, dict):
        return structured
    for part in result.get("content") or []:
        if isinstance(part, dict) and part.get("type") == "text":
            with contextlib.suppress(ValueError):
                parsed = json.loads(part.get("text") or "null")
                if isinstance(parsed, dict):
                    return parsed
    raise Unreachable(f"{tool}'s answer couldn't be read")


def call(url: str, token: str, tool: str, arguments: dict[str, Any], deadline: Deadline) -> dict[str, Any]:
    """An `authorize` answer: raises `Refused` with ArchBeagle's words when it wouldn't judge (#1298), and `Unreachable`
    for anything else but a decision."""
    answer = tool_result(url, token, tool, arguments, deadline)
    if answer.get("decision") not in ("allow", "deny"):
        raise Unreachable("authorize's answer had no decision")
    return answer


def _cache_file() -> Path:
    return Path(os.environ.get("ARCH_HOOK_CACHE") or Path.home() / ".cache" / "archbeagle" / "hook-cache.json")


def _key(url: str, token: str, request: dict[str, Any]) -> str:
    raw = json.dumps({"url": url, "token": hashlib.sha256(token.encode()).hexdigest(), "request": request},
                     sort_keys=True)  # fmt: skip
    return hashlib.sha256(raw.encode()).hexdigest()


def cached(key: str) -> dict[str, Any] | None:
    with contextlib.suppress(OSError, ValueError):
        found = json.loads(_cache_file().read_text(encoding="utf-8")).get(key)
        if isinstance(found, dict) and found.get("until", 0) > time.time():
            answer = found.get("answer")
            return answer if isinstance(answer, dict) and answer.get("decision") == "allow" else None
    return None


def remember(key: str, answer: dict[str, Any]) -> None:
    """Keeps an `allow` for its `cache_seconds`; a `deny` is never kept. Expired entries are dropped on the way."""
    seconds = int(answer.get("cache_seconds") or 0)
    if answer.get("decision") != "allow" or seconds <= 0:
        return
    with contextlib.suppress(OSError, ValueError):
        path = _cache_file()
        try:
            entries = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            entries = {}
        now = time.time()
        entries = {k: v for k, v in entries.items() if isinstance(v, dict) and v.get("until", 0) > now}
        entries[key] = {"until": now + min(seconds, 300), "answer": answer}
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(entries), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(path)


def log_failure(why: str, what: str = "unreachable") -> None:
    with contextlib.suppress(OSError):
        path = Path(os.environ.get("ARCH_HOOK_LOG") or Path.home() / ".archbeagle" / "hook.log")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {what}: {why}\n")


def unreachable_text(why: str) -> str:
    """The person's and the model's line when ArchBeagle can't answer, with why (#1298: a 502 from the server, a
    time-out within the hook's deadline and a refused handshake all read the same before), cut to one line."""
    return f"{UNREACHABLE} ({why.splitlines()[0][:120] if why else 'no answer'})"


def refused_text(why: str) -> str:
    """The line when ArchBeagle answered and wouldn't judge (#1298), in its words; for a repository of another account,
    what to do."""
    hint = OTHER_ACCOUNT_HINT if OTHER_ACCOUNT in why else ""
    return REFUSED.format(why=why.rstrip(".")) + hint


# ── the answer, as each client takes it ──────────────────────────────────────


def output(client: str, decision: str, text: str, read: bool = False) -> tuple[str, int]:
    """The hook's stdout and exit code. `deny` denies; `allow` with a message only shows it: no permission is ever
    granted, so the client's own approval flow applies. Cursor's `beforeReadFile` is the exception: it takes only
    `permission` and `user_message`, and blocks the read on any other answer, so a read's allow says `allow`."""
    if client in ("claude", "codex"):
        if decision == "deny":
            out = {
                "systemMessage": text,
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": text,
                },
            }
        else:
            out = {
                "systemMessage": text,
                "hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": text},
            }
        return json.dumps(out), 0
    if client == "cursor" and read:
        found = {"permission": "deny", "user_message": text} if decision == "deny" else {"permission": "allow"}
        return json.dumps(found), 0
    if client == "cursor":
        if decision == "deny":
            return json.dumps({"permission": "deny", "user_message": text, "agent_message": text}), 0
        return json.dumps({"agent_message": text} if text else {}), 0
    return text, 2 if decision == "deny" else 0


def decide(
    event: dict[str, Any],
    client: str,
    url: str,
    token: str,
    deadline: Deadline,
    kind: str | None = None,
    managed: bool = False,
    local: list[tuple[str, Path, str]] | None = None,
) -> tuple[str, str]:
    """("deny" or "allow", the message): every repository's answer, the first deny winning."""
    messages: list[str] = []
    for found in requests(event, client, deadline, kind, local):
        request = {**found, "managed": True} if managed else found
        key = _key(url, token, request)
        answer = cached(key)
        if answer is None:
            answer = call(url, token, "authorize", request, deadline)
            remember(key, answer)
        text = _command(event)[:MAX_COMMAND] if answer.get("needs_command") and request.get("tool") == SHELL else ""
        if (
            text
        ):  # architecture/0083: the account lists commands; ArchBeagle judges this one in memory and keeps its hash
            asked_again = {**request, "command": text}
            key = _key(url, token, asked_again)
            answer = cached(key)
            if answer is None:
                answer = call(url, token, "authorize", asked_again, deadline)
                remember(key, answer)
        message = str(answer.get("message") or answer.get("reason") or "")
        if answer["decision"] == "deny":
            return "deny", message or "Denied by ArchBeagle."
        if answer.get("plan_downgraded") or answer.get("outcome") == "warned":
            messages.append(message)
    return "allow", "\n".join(m for m in messages if m)


# ── at session start (architecture/0034, step 6) ─────────────────────────────


def local_state(root: Path, f: dict[str, Any]) -> tuple[str, int | None]:
    """A file ArchBeagle served, as the checkout has it: `current`, `stale`, `edited` (inside ArchBeagle's block or
    file), `malformed` or `absent`, and the revision its marker names."""
    path = str(f.get("path") or "")
    place = root / path
    if not path or path.startswith("/") or ".." in path.split("/") or not place.is_file():
        return "absent", None
    try:
        text = place.read_bytes()[:MAX_BYTES].decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return "malformed", None
    marks = parse_markers(text)
    if marks["state"] == "malformed":
        return "malformed", marks["revision"]
    if marks["state"] == "absent":
        # AGENTS.md without ArchBeagle's block hasn't adopted it; a file in ArchBeagle's place without its header was
        # replaced.
        return ("absent" if f.get("ownership") == "block" else "edited"), None
    if marks["body_digest"] != marks["digest"]:
        return "edited", marks["revision"]
    return ("current" if marks["digest"] == f.get("digest") else "stale"), marks["revision"]


def _reason(states: dict[str, tuple[str, int | None]], revision: int) -> str:
    """Why the committed files aren't enough, in a sentence."""
    by: dict[str, list[str]] = {}
    for path, (state, _) in sorted(states.items()):
        by.setdefault(state, []).append(path)
    seen = sorted({r for state, r in states.values() if state == "stale" and r is not None})
    parts = []
    if "stale" in by:
        at = "revision " + ", ".join(str(r) for r in seen) if seen else "an older revision"
        parts.append(f"this repository's committed architecture files are at {at}; revision {revision} is approved")
    if "edited" in by:
        verb = "was" if len(by["edited"]) == 1 else "were"
        parts.append(f"{', '.join(by['edited'])} {verb} edited inside ArchBeagle's part")
    if "malformed" in by:
        parts.append(f"ArchBeagle's markers in {', '.join(by['malformed'])} can't be read")
    if "absent" in by:
        verb = "has" if len(by["absent"]) == 1 else "have"
        parts.append(f"{', '.join(by['absent'])} {verb} no ArchBeagle architecture section")
    return "ArchBeagle: " + "; ".join(parts) + ". Use this instead:"


def session_start(event: dict[str, Any], client: str, url: str, token: str, deadline: Deadline) -> str:
    """What the hook prints at session start: the "current" line, or the reason and ArchBeagle's session context as the
    client's `additionalContext`; nothing outside a repository ArchBeagle answers for."""
    cwd = str(event.get("cwd") or "")
    repo, root = locate(Path(cwd or "."), cwd, deadline)
    if not repo:
        return ""
    arguments: dict[str, Any] = {"repo": repo, "targets": SESSION_TARGETS[client], "via": "session_start"}
    session = event.get("session_id") or event.get("conversation_id")
    if isinstance(session, str) and session.strip():
        arguments["session_key"] = session.strip()[:200]
    try:
        found = tool_result(url, token, "agent_instructions", arguments, deadline)
    except Refused:
        return ""  # not a repository of ArchBeagle's model, or no approved revision yet: nothing to load
    try:
        revision = int(found["revision"])
        files = [f for f in found["files"] if isinstance(f, dict)]
        context = str(found.get("session_context") or "")
    except (KeyError, TypeError, ValueError) as exc:
        raise Unreachable("agent_instructions' answer couldn't be read") from exc
    states = {str(f.get("path")): local_state(root, f) for f in files}
    if files and all(state == "current" for state, _ in states.values()):
        return SESSION_CURRENT.format(revision=revision)
    text = f"{_reason(states, revision)}\n\n{context}" if states else context
    if len(text) > SESSION_CONTEXT_MAX:
        text = text[: SESSION_CONTEXT_MAX - 1] + "…"
    return json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": text}})


def managed_no_token(client: str, kind: str | None, url: str, raw: str) -> int:
    """A managed install with no token (architecture/0083): every judged call is denied, saying where to make one.
    A call the hook never judges (ArchBeagle's own tools, a plain read in Codex) still goes ahead."""
    try:
        event = json.loads(raw or "{}")
    except ValueError:
        event = {}
    if not isinstance(event, dict) or action_of(event, client, kind) is None:
        return 0
    log_failure("no ARCH_MCP_TOKEN", "no-token")
    where = url.removesuffix("/mcp").rstrip("/") + "/settings/tokens"
    read = client == "cursor" and (kind == "read" or event.get("hook_event_name") == "beforeReadFile")
    out, code = output(client, "deny", MANAGED_NO_TOKEN.format(where=where), read)
    sys.stdout.write(out + "\n")
    return code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="The architecture hook for coding agents: it asks ArchBeagle first.")
    parser.add_argument("--client", choices=("claude", "codex", "cursor", "text"), default="text")
    parser.add_argument("--url", help="the MCP endpoint; else ARCH_MCP_URL")
    parser.add_argument(
        "--event",
        choices=("tool", "read", "shell", "mcp", "session_start"),
        help="Cursor: which hook runs it; Claude Code and Codex: session_start at the start of a session",
    )
    parser.add_argument("--managed", action="store_true", help="a managed install: no token or no answer denies")
    parser.add_argument(
        "--on-unreachable", choices=("deny", "allow"), default="deny", help="managed: when ArchBeagle can't answer"
    )
    args = parser.parse_args(argv)
    token = os.environ.get("ARCH_MCP_TOKEN", "").strip()
    url = (args.url or os.environ.get("ARCH_MCP_URL") or "").strip()
    if args.managed and args.event != "session_start" and url.startswith(("https://", "http://")) and not token:
        return managed_no_token(args.client, args.event, url, sys.stdin.read(MAX_BYTES * 2))
    if not token or not url.startswith(("https://", "http://")):
        return 0  # not configured: nothing to ask
    try:
        seconds = min(max(float(os.environ.get("ARCH_HOOK_TIMEOUT") or 2), 0.5), 10.0)
    except ValueError:
        seconds = 2.0
    deadline = Deadline(seconds)
    try:
        event = json.loads(sys.stdin.read(MAX_BYTES * 2) or "{}")
    except ValueError:
        return 0
    if not isinstance(event, dict):
        return 0
    if args.event == "session_start":
        if args.client not in SESSION_TARGETS:
            return 0
        try:
            out = session_start(event, args.client, url, token, deadline)
        except (Unreachable, TimeoutError) as exc:
            log_failure(str(exc))
            out = SESSION_UNREACHABLE  # fail open: a session always starts (architecture/0034, as 0029)
        if out:
            sys.stdout.write(out + "\n")
        return 0
    # architecture/0083: a managed install's choice is its package's, and no environment variable loosens it
    on_failure = os.environ.get("ARCHBEAGLE_HOOK_ON_FAILURE", "open").strip().lower()
    closed = args.on_unreachable != "allow" if args.managed else on_failure == "block"
    blocked = MANAGED_UNREACHABLE if args.managed else BLOCKED_UNREACHABLE
    try:
        local = local_test_findings(event, args.client, args.event)
    except Exception:  # the local check is advice: it never costs the hook its answer
        local = []
    try:
        decision, text = decide(event, args.client, url, token, deadline, args.event, args.managed, local)
    except (
        Refused
    ) as exc:  # ArchBeagle answered and wouldn't judge (#1298): said in its words, open or closed as configured
        log_failure(str(exc), "refused")
        decision, text = ("deny" if closed else "allow"), refused_text(str(exc))
    except (Unreachable, TimeoutError) as exc:
        log_failure(str(exc))
        decision, text = ("deny", blocked) if closed else ("allow", unreachable_text(str(exc)))
    if decision == "allow":  # each local warning once: ArchBeagle's answer may already name its rule
        text = "\n".join(m for m in (text, *(w for rule, _, w in local if rule not in text)) if m)
    read = args.client == "cursor" and (args.event == "read" or event.get("hook_event_name") == "beforeReadFile")
    if decision == "allow" and not text and not read:
        return 0
    out, code = output(args.client, decision, text, read)
    sys.stdout.write(out + "\n")
    return code


if __name__ == "__main__":
    code = 0
    try:
        code = main()
    except Exception as exc:  # noqa: BLE001 (anything else is the hook's own failure: the client's setting decides)
        log_failure(f"hook error: {exc!r}"[:300])
        code = 1
    sys.exit(code)
