"""Managed checkouts against throwaway local repositories: clone, fast-forward, the cases that leave a
checkout alone, and the install script."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from ssh_session import tools as t


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def remote(tmp_path: Path) -> tuple[Path, Path]:
    """A bare 'origin' and a working clone to push new commits from."""
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--quiet", "--bare", "--initial-branch=master", str(origin)], check=True)
    work = tmp_path / "work"
    subprocess.run(["git", "clone", "--quiet", str(origin), str(work)], check=True, capture_output=True)
    git(work, "config", "user.email", "t@example.com")
    git(work, "config", "user.name", "t")
    (work / "install").write_text("#!/bin/sh\necho \"ok    linked\"\necho \"link  new\" \n")
    (work / "install").chmod(0o755)
    git(work, "add", "install")
    git(work, "commit", "--quiet", "-m", "one")
    git(work, "push", "--quiet", "origin", "HEAD:master")
    return origin, work


def tool_for(origin: Path) -> t.Tool:
    return t.Tool("tool", str(origin))


def test_clones_a_missing_checkout_and_installs(remote, tmp_path):
    origin, _ = remote
    root = tmp_path / "code"
    lines: list[str] = []
    assert t.sync(root, (tool_for(origin),), echo=lines.append)
    assert (root / "tool" / ".git").exists()
    assert "cloned into" in lines[0] and "installed: link  new" in lines[0]
    assert "ok    linked" not in lines[0]  # an install's ok lines are quiet


def test_fast_forwards_a_clean_checkout(remote, tmp_path):
    origin, work = remote
    root = tmp_path / "code"
    t.sync(root, (tool_for(origin),), echo=lambda _: None)
    (work / "f").write_text("x")
    git(work, "add", "f")
    git(work, "commit", "--quiet", "-m", "two")
    git(work, "push", "--quiet", "origin", "HEAD:master")
    lines: list[str] = []
    assert t.sync(root, (tool_for(origin),), echo=lines.append)
    assert "updated" in lines[0]
    assert (root / "tool" / "f").exists()


def test_up_to_date_says_so(remote, tmp_path):
    origin, _ = remote
    root = tmp_path / "code"
    t.sync(root, (tool_for(origin),), echo=lambda _: None)
    lines: list[str] = []
    assert t.sync(root, (tool_for(origin),), echo=lines.append)
    assert "up to date" in lines[0]


def test_local_changes_are_left_alone_but_still_installed(remote, tmp_path):
    origin, _ = remote
    root = tmp_path / "code"
    t.sync(root, (tool_for(origin),), echo=lambda _: None)
    (root / "tool" / "install").write_text("#!/bin/sh\necho \"link  edited\"\n")
    lines: list[str] = []
    assert not t.sync(root, (tool_for(origin),), echo=lines.append)
    assert "has local changes: left as it is" in lines[0]
    assert "link  edited" in lines[0]
    assert "edited" in (root / "tool" / "install").read_text()


def test_own_commits_are_left_alone(remote, tmp_path):
    origin, _ = remote
    root = tmp_path / "code"
    t.sync(root, (tool_for(origin),), echo=lambda _: None)
    repo = root / "tool"
    git(repo, "config", "user.email", "t@example.com")
    git(repo, "config", "user.name", "t")
    (repo / "mine").write_text("x")
    git(repo, "add", "mine")
    git(repo, "commit", "--quiet", "-m", "mine")
    lines: list[str] = []
    assert not t.sync(root, (tool_for(origin),), echo=lines.append)
    assert "commit(s) of its own" in lines[0]


def test_another_branch_is_left_alone(remote, tmp_path):
    origin, _ = remote
    root = tmp_path / "code"
    t.sync(root, (tool_for(origin),), echo=lambda _: None)
    git(root / "tool", "checkout", "--quiet", "-b", "wip")
    lines: list[str] = []
    assert not t.sync(root, (tool_for(origin),), echo=lines.append)
    assert "on wip, not master" in lines[0]


def test_a_directory_that_is_not_a_checkout_is_reported(tmp_path):
    root = tmp_path / "code"
    (root / "tool").mkdir(parents=True)
    lines: list[str] = []
    assert not t.sync(root, (t.Tool("tool", "unused"),), echo=lines.append)
    assert "is not a git checkout" in lines[0]


def test_a_failing_install_is_reported(remote, tmp_path):
    origin, work = remote
    (work / "install").write_text("#!/bin/sh\necho \"SKIP  in the way\" >&2\nexit 1\n")
    git(work, "commit", "--quiet", "-am", "bad install")
    git(work, "push", "--quiet", "origin", "HEAD:master")
    root = tmp_path / "code"
    lines: list[str] = []
    assert not t.sync(root, (tool_for(origin),), echo=lines.append)
    assert "install failed: SKIP  in the way" in lines[0]
