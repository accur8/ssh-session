"""The git-hosting key: a passphrase-protected ed25519 key file for gitea and
github (and commit signing), unlocked into the ssh-agent for the day by
the same ssh-session run that gets the session certificate, whichever signer
that run used.

Why a file and not the YubiKey: pushes fire from inside scripts all day, and a
hardware touch belongs to deliberate acts. Why it is still
not the old static key: it reaches gitea and github only, never a fleet host,
and its passphrase is 256 random bits the user never types, held in the login
Keychain. Outside the agent's window the file is inert.

`ssh-add -t` is the expiry: when the session dies, the git key goes with it.
"""
from __future__ import annotations

import base64
import os
import secrets
import stat
import subprocess
from pathlib import Path
from typing import Protocol

DEFAULT_KEY = Path.home() / ".ssh" / "id_ed25519_git"
SERVICE = "accur8-gitkey"


class GitKeyError(Exception):
    pass


class SecretStore(Protocol):
    def get(self, account: str) -> str | None: ...
    def set(self, account: str, secret: str) -> None: ...


class KeychainStore:
    """The macOS login Keychain, through the security(1) tool."""

    def get(self, account: str) -> str | None:
        r = self._security(["find-generic-password", "-s", SERVICE, "-a", account, "-w"])
        return r.stdout.strip() if r.returncode == 0 else None

    def set(self, account: str, secret: str) -> None:
        r = self._security(["add-generic-password", "-U", "-s", SERVICE, "-a", account,
                            "-l", "accur8 git key passphrase", "-w", secret])
        if r.returncode != 0:
            raise GitKeyError(f"the Keychain refused the passphrase: {r.stderr.strip()}")

    @staticmethod
    def _security(args: list[str]) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(["security", *args], capture_output=True, text=True)
        except FileNotFoundError as e:
            raise GitKeyError("the git key's passphrase is kept in the macOS login Keychain, "
                              "which this machine does not have") from e


class DictStore:
    """In-memory store for tests."""

    def __init__(self) -> None:
        self.d: dict[str, str] = {}

    def get(self, account: str) -> str | None:
        return self.d.get(account)

    def set(self, account: str, secret: str) -> None:
        self.d[account] = secret


def new_passphrase() -> str:
    return base64.b32encode(secrets.token_bytes(32)).decode().rstrip("=")


def account_for(key: Path) -> str:
    return f"passphrase:{key.resolve()}"


def enroll(key: Path, store: SecretStore, comment: str = "git") -> Path:
    """Generate the key with a fresh random passphrase stored in STORE. Returns
    the public key path. Refuses to overwrite."""
    if key.exists():
        raise GitKeyError(f"{key} exists; refusing to overwrite")
    key.parent.mkdir(parents=True, exist_ok=True)
    pw = new_passphrase()
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-C", comment, "-N", pw, "-f", str(key)],
                   check=True, capture_output=True)
    key.chmod(0o600)
    try:
        store.set(account_for(key), pw)
    except GitKeyError:
        # A key whose passphrase was never kept can never be loaded: leave none behind.
        key.unlink(missing_ok=True)
        key.with_suffix(".pub").unlink(missing_ok=True)
        raise
    return key.with_suffix(".pub")


def _askpass_script(state_dir: Path) -> Path:
    """A tiny helper ssh-add calls for the passphrase; it prints the value of an
    environment variable, so the passphrase itself is never written to disk."""
    state_dir.mkdir(parents=True, exist_ok=True)
    state_dir.chmod(0o700)
    p = state_dir / "gitkey-askpass"
    body = '#!/bin/sh\nprintf "%s" "$SSH_SESSION_GITKEY_PASSPHRASE"\n'
    if not p.exists() or p.read_text() != body:
        p.write_text(body)
        p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


def load(key: Path, hours: int, store: SecretStore, state_dir: Path) -> None:
    """Add the key to the agent for HOURS, supplying its passphrase from STORE."""
    if not key.exists():
        raise GitKeyError(f"no git key at {key}; run ssh-session gitkey enroll")
    pw = store.get(account_for(key))
    if pw is None:
        raise GitKeyError(f"no passphrase for {key} in the Keychain; run ssh-session gitkey enroll on this machine")
    env = dict(os.environ)
    env.update({
        "SSH_ASKPASS": str(_askpass_script(state_dir)),
        "SSH_ASKPASS_REQUIRE": "force",
        "DISPLAY": env.get("DISPLAY", ":0"),
        "SSH_SESSION_GITKEY_PASSPHRASE": pw,
    })
    r = subprocess.run(["ssh-add", "-q", "-t", f"{hours}H", str(key)], env=env, capture_output=True, text=True)
    if r.returncode != 0:
        raise GitKeyError(f"ssh-add failed: {r.stderr.strip()}")


def loaded(key: Path) -> bool:
    """Is this key's public half in the agent right now?"""
    pub = key.with_suffix(".pub")
    if not pub.exists():
        return False
    want = " ".join(pub.read_text().split()[:2])
    r = subprocess.run(["ssh-add", "-L"], capture_output=True, text=True)
    return r.returncode == 0 and any(" ".join(l.split()[:2]) == want for l in r.stdout.splitlines())
