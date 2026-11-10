"""A session certificate from the account CA service: the signer ssh-session
uses when no enrolled YubiKey is plugged in.

A developer has one ssh key (the first of ~/.ssh/id_ed25519, id_ecdsa,
id_rsa that exists), enrolled once by an admin on the service (sign@ca.intra: a line there names the principals that key may be
issued). The service certifies that key for some hours; the certificate is
written beside the key (<key>-cert.pub, where ssh finds it) and key and
certificate go into the ssh-agent until the certificate expires.
"""
from __future__ import annotations

import datetime as dt
import subprocess
from pathlib import Path

from .session import Certificate, SessionError, keygen_listing

SERVICE = "sign@ca.intra"
# The developer's key: the first of these that exists, the order ssh itself tries.
KEY_NAMES = ("id_ed25519", "id_ecdsa", "id_rsa")
DEFAULT_HOURS = 12
MAX_HOURS = 24


def default_key(ssh_dir: Path | None = None) -> Path:
    """The developer's key: the first of KEY_NAMES with both halves in
    ~/.ssh, else ~/.ssh/id_ed25519 (which a refusal then names)."""
    ssh_dir = ssh_dir or Path.home() / ".ssh"
    for name in KEY_NAMES:
        key = ssh_dir / name
        if key.exists() and key.with_name(name + ".pub").exists():
            return key
    return ssh_dir / KEY_NAMES[0]


def certificate_line(output: str) -> str:
    """The certificate in what the service printed, "" when there is none."""
    for line in output.splitlines():
        if "-cert-v01@openssh.com " in line:
            return line.strip()
    return ""


def mint(key: Path | None = None, *, hours: int = DEFAULT_HOURS, service: str = SERVICE) -> Certificate:
    """Have SERVICE certify KEY (default: default_key()) for HOURS, write the
    certificate beside the key and load both into the agent until it expires."""
    key = key or default_key()
    if not 1 <= hours <= MAX_HOURS:
        raise SessionError(f"--hours must be 1-{MAX_HOURS} for a certificate from {service}")
    pub = key.with_name(key.name + ".pub")
    if not pub.exists() or not key.exists():
        raise SessionError(
            f"no enrolled YubiKey is plugged in, and there is no key ({', '.join(KEY_NAMES)}) in {key.parent} "
            f"for {service} to certify: plug in your YubiKey, or make a key with `ssh-keygen -t ed25519` "
            f"and have an admin enrol it on {service}")
    # The key being certified is the one that authenticates: its line on the
    # service names the principals. A refusal ("no principals on this line;
    # ask an admin") comes back on stderr.
    try:
        r = subprocess.run(["ssh", "-o", "IdentitiesOnly=yes", "-i", str(key), service, f"{hours}h"],
                           input=pub.read_text(), capture_output=True, text=True)
    except FileNotFoundError as e:
        raise SessionError(f"ssh not found on PATH: {e}") from e
    line = certificate_line(r.stdout)
    if r.returncode != 0 or not line:
        why = r.stderr.strip() or f"ssh exit {r.returncode}"
        raise SessionError(f"{service} did not issue a certificate: {why}")
    cert_path = key.with_name(key.name + "-cert.pub")
    cert_path.write_text(line + "\n")
    cert_path.chmod(0o644)
    cert = Certificate.parse(keygen_listing(cert_path))
    # ssh-add loads <key>-cert.pub beside the key on its own; -t bounds the
    # agent's copy to the certificate's remaining life.
    remaining = max(60, int((cert.valid_to - dt.datetime.now()).total_seconds()))
    a = subprocess.run(["ssh-add", "-q", "-t", str(remaining), str(key)])
    if a.returncode != 0:
        raise SessionError(f"the certificate is at {cert_path}, but ssh-add could not load {key} into the agent")
    print(f"session loaded: {','.join(cert.principals)} until {cert.valid_to.isoformat()}, from {service}", flush=True)
    return cert
