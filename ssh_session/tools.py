"""Managed checkouts: once the git key is in the agent, the internal tools that live in private
repositories are cloned, kept up to date and connected.

ssh-session is the public bootstrap: it brings git access. Each managed tool is a private repository
checked out once under the code root (~/code/accur8, or SSH_SESSION_CODE_ROOT), and that checkout is
the tool's single source of truth: its own `install` script links what it provides (a Claude Code
skill, a command on PATH) into the checkout, so a pull is all an update takes. Every ssh-session run
that loads the git key passes over the list:

  - a missing checkout is cloned;
  - a clean checkout on its default branch is fetched and fast-forwarded; one with local changes,
    commits of its own or on another branch is left exactly as it is, with a warning;
  - the tool's `install` runs (it is idempotent).

Nothing here fails the session: a tool that cannot be updated is reported and the rest go on.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass(frozen=True)
class Tool:
    name: str  # the checkout's directory under the code root
    url: str   # where it is cloned from


TOOLS = (
    Tool("ticket-cli", "git@git.accur8.net:a8/ticket-cli.git"),
)


def code_root() -> Path:
    return Path(os.environ.get("SSH_SESSION_CODE_ROOT", str(Path.home() / "code" / "accur8"))).expanduser()


def _git(repo: Path, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=timeout)


def _out(r: subprocess.CompletedProcess) -> str:
    """The last line git printed: its error."""
    lines = (r.stderr or r.stdout or "").strip().splitlines()
    return lines[-1] if lines else f"exit {r.returncode}"


def update(tool: Tool, root: Path) -> str:
    """Clone or fast-forward one tool's checkout. Answers one line saying what happened; raises
    ToolError when the checkout cannot be brought up to date (it is then left untouched)."""
    repo = root / tool.name
    if not (repo / ".git").exists():
        if repo.exists():
            raise ToolError(f"{repo} exists and is not a git checkout")
        root.mkdir(parents=True, exist_ok=True)
        r = subprocess.run(["git", "clone", "--quiet", tool.url, str(repo)], capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            raise ToolError(f"clone of {tool.url} failed: {_out(r)}")
        return f"cloned into {repo}"
    branch = _git(repo, "symbolic-ref", "--quiet", "--short", "HEAD").stdout.strip()
    default = _git(repo, "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD").stdout.strip().removeprefix("origin/") or "master"
    if branch != default:
        raise ToolError(f"on {branch or 'a detached HEAD'}, not {default}: left as it is")
    if _git(repo, "status", "--porcelain", "--untracked-files=no").stdout.strip():
        raise ToolError("has local changes: left as it is")
    r = _git(repo, "fetch", "--quiet", "origin", default, timeout=120)
    if r.returncode != 0:
        raise ToolError(f"fetch failed: {_out(r)}")
    ahead = _git(repo, "rev-list", "--count", f"origin/{default}..HEAD").stdout.strip()
    if ahead not in ("", "0"):
        raise ToolError(f"has {ahead} commit(s) of its own not on origin/{default}: left as it is")
    before = _git(repo, "rev-parse", "--short", "HEAD").stdout.strip()
    r = _git(repo, "merge", "--ff-only", "--quiet", f"origin/{default}")
    if r.returncode != 0:
        raise ToolError(f"fast-forward failed: {_out(r)}")
    after = _git(repo, "rev-parse", "--short", "HEAD").stdout.strip()
    return "up to date" if before == after else f"updated {before} -> {after}"


def install(tool: Tool, root: Path) -> str:
    repo = root / tool.name
    script = repo / "install"
    if not script.exists():
        return "no install script"
    r = subprocess.run([str(script)], capture_output=True, text=True, timeout=120, cwd=str(repo))
    notes = [ln for ln in (r.stdout + r.stderr).splitlines() if not ln.startswith("ok ")]
    if r.returncode != 0:
        raise ToolError("install failed: " + ("; ".join(notes) or f"exit {r.returncode}"))
    return "installed" + (": " + "; ".join(notes) if notes else "")


class ToolError(Exception):
    pass


def sync(root: Path | None = None, tools: tuple[Tool, ...] = TOOLS, echo: Callable[[str], None] = print) -> bool:
    """Every managed tool: update, then install. True when all of them are current and connected."""
    root = root or code_root()
    ok = True
    for tool in tools:
        try:
            what = update(tool, root)
        except (ToolError, subprocess.TimeoutExpired, OSError) as e:
            ok = False
            what = f"not updated: {e}"
        if not (root / tool.name / ".git").exists():
            echo(f"tool {tool.name}: {what}")
            continue
        # installed whether or not the update went through: the links point at the checkout as it is
        try:
            echo(f"tool {tool.name}: {what}; {install(tool, root)}")
        except (ToolError, subprocess.TimeoutExpired, OSError) as e:
            ok = False
            echo(f"tool {tool.name}: {what}; {e}")
    return ok
