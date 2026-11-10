"""The account CA signer and the choice between it and the YubiKey.

The account CA service is played by a stub `ssh` on PATH that signs what it is
sent with a throwaway software CA, the way sign@ca.intra answers.
"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from ssh_session import accountca, cli
from ssh_session import session as s

needs_openssh = pytest.mark.skipif(shutil.which("ssh-keygen") is None or shutil.which("ssh-agent") is None,
                                   reason="openssh not on PATH")


@pytest.fixture
def agent(monkeypatch):
    """A private ssh-agent. A short socket path: unix sockets cap around 104 bytes."""
    sock_dir = Path(tempfile.mkdtemp(prefix="ss", dir="/tmp"))
    out = subprocess.run(["ssh-agent", "-a", str(sock_dir / "s")], capture_output=True, text=True, check=True).stdout
    pid = [l for l in out.splitlines() if "SSH_AGENT_PID" in l][0].split("=")[1].split(";")[0]
    monkeypatch.setenv("SSH_AUTH_SOCK", str(sock_dir / "s"))
    yield
    subprocess.run(["kill", pid], check=False)
    shutil.rmtree(sock_dir, ignore_errors=True)


@pytest.fixture
def service(tmp_path, monkeypatch):
    """A stub `ssh` first on PATH that answers as the account CA: it signs the
    public key on stdin for the hours asked, principal tester-dev."""
    ca = tmp_path / "account-ca"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(ca)], check=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "ssh"
    stub.write_text(f"""#!/bin/sh
# the last argument is the window, as sign@ca.intra takes it: 12h
for a; do window=$a; done
d=$(mktemp -d)
cat > "$d/k.pub"
if [ -f "{tmp_path}/refuse" ]; then echo "no principals on this line; ask an admin" >&2; exit 1; fi
ssh-keygen -q -s "{ca}" -I "tester account-ca" -n tester-dev -V "+$window" "$d/k.pub" || exit 1
cat "$d/k-cert.pub"
rm -rf "$d"
""")
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return tmp_path


def make_key(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)], check=True)
    return path


@needs_openssh
def test_account_ca_certifies_the_key_and_loads_it(service, agent, tmp_path):
    key = make_key(tmp_path / "home" / ".ssh" / "id_ed25519")
    cert = accountca.mint(key, hours=3)
    assert cert.principals == ("tester-dev",)
    assert 170 <= cert.minutes_left() <= 181
    assert (key.parent / "id_ed25519-cert.pub").exists()
    held = s.agent_certificates()
    assert [c.principals for c in held] == [("tester-dev",)]
    assert "tester-dev" in s.status_lines(held)[0]


@needs_openssh
def test_a_refusal_from_the_service_is_reported_and_loads_nothing(service, agent, tmp_path):
    key = make_key(tmp_path / "home" / ".ssh" / "id_ed25519")
    (service / "refuse").write_text("")
    with pytest.raises(s.SessionError, match="ask an admin"):
        accountca.mint(key, hours=3)
    assert s.agent_certificates() == []
    assert not (key.parent / "id_ed25519-cert.pub").exists()


def test_no_yubikey_and_no_key_says_both_ways_forward(tmp_path):
    with pytest.raises(s.SessionError) as e:
        accountca.mint(tmp_path / "id_ed25519")
    assert "plug in your YubiKey" in str(e.value) and "have an admin enrol it" in str(e.value)


def test_hours_are_bounded_for_the_account_ca(tmp_path):
    with pytest.raises(s.SessionError, match="1-24"):
        accountca.mint(tmp_path / "id_ed25519", hours=48)


# --- which signer -----------------------------------------------------------

def plugged(monkeypatch, handles: dict, serials: list):
    monkeypatch.setattr(s, "ca_handles", lambda: handles)
    monkeypatch.setattr(s, "plugged_serials", lambda: serials)


def test_an_enrolled_yubikey_plugged_in_signs(monkeypatch, tmp_path):
    plugged(monkeypatch, {"111": tmp_path / "ca111"}, ["111"])
    assert cli.yubikey_ca(None) == tmp_path / "ca111"


def test_no_yubikey_or_an_unenrolled_one_means_the_account_ca(monkeypatch, tmp_path):
    plugged(monkeypatch, {"111": tmp_path / "ca111"}, [])
    assert cli.yubikey_ca(None) is None
    plugged(monkeypatch, {"111": tmp_path / "ca111"}, ["999"])
    assert cli.yubikey_ca(None) is None


def test_two_enrolled_yubikeys_is_an_error(monkeypatch, tmp_path):
    plugged(monkeypatch, {"111": tmp_path / "a", "222": tmp_path / "b"}, ["111", "222"])
    with pytest.raises(s.SessionError, match="more than one"):
        cli.yubikey_ca(None)


def test_role_without_a_yubikey_is_refused(monkeypatch):
    plugged(monkeypatch, {}, [])
    r = CliRunner().invoke(cli.main, ["--role", "root"])
    assert r.exit_code == 1 and "need the admin CA on a YubiKey" in r.output


@needs_openssh
def test_the_command_without_a_yubikey_gets_an_account_ca_session(service, agent, tmp_path, monkeypatch):
    plugged(monkeypatch, {}, [])
    key = make_key(tmp_path / "home" / ".ssh" / "id_ed25519")
    monkeypatch.setattr(accountca, "DEFAULT_KEY", key)
    monkeypatch.setattr(accountca.mint, "__defaults__", (key,))
    monkeypatch.setattr(cli.gk, "DEFAULT_KEY", tmp_path / "no-git-key")
    r = CliRunner().invoke(cli.main, [])
    assert r.exit_code == 0, r.output
    assert "session loaded: tester-dev" in r.output and "sign@ca.intra" in r.output
    st = CliRunner().invoke(cli.main, ["status"])
    assert st.exit_code == 0 and "tester-dev" in st.output and "git key: not loaded" in st.output


def test_gitkey_enroll_is_a_subcommand():
    r = CliRunner().invoke(cli.main, ["gitkey", "--help"])
    assert r.exit_code == 0 and "enroll" in r.output
