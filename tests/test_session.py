"""Unit tests: principals, certificate parsing, status. The integration test
mints against a throwaway software CA in a private agent when openssh is on
PATH (it is inside `nix develop`)."""
from __future__ import annotations

import datetime as dt
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from ssh_session import session as s

LISTING = '''/x/cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Public key: ED25519-CERT SHA256:abc
        Signing CA: ED25519 SHA256:def (using ssh-ed25519)
        Key ID: "ada@box 2026-10-20T10:08:15Z root"
        Serial: 1792452941
        Valid: from 2026-10-20T06:07:00 to 2026-10-20T10:08:15
        Principals: 
                ada-root
                ada-prod
                ada-dev
        Critical Options: (none)
        Extensions: 
                permit-pty
'''


def test_principals_nest_by_default_and_never_imply_root():
    assert s.principals_for("ada", "dev", False) == "ada-dev"
    assert s.principals_for("ada", "prod", False) == "ada-prod,ada-dev"
    assert s.principals_for("ada", "root", False) == "ada-root,ada-prod,ada-dev"


def test_principals_strict_is_the_one_role():
    assert s.principals_for("ada", "root", True) == "ada-root"
    assert s.principals_for("ada", "prod", True) == "ada-prod"


def test_unknown_role_is_an_error():
    with pytest.raises(s.SessionError):
        s.principals_for("ada", "admin", False)


def test_certificate_parse():
    c = s.Certificate.parse(LISTING)
    assert c.key_id == "ada@box 2026-10-20T10:08:15Z root"
    assert c.principals == ("ada-root", "ada-prod", "ada-dev")
    assert c.valid_to == dt.datetime(2026, 10, 20, 10, 8, 15)


def test_status_lines_thresholds():
    c = s.Certificate.parse(LISTING)
    at = lambda m: dt.datetime(2026, 10, 20, 10, 8, 15) - dt.timedelta(minutes=m)
    assert s.status_lines([c], at(125))[0].startswith("ok ") and "2h05m" in s.status_lines([c], at(125))[0]
    assert s.status_lines([c], at(30))[0].startswith("WARNING")
    assert s.status_lines([c], at(-1))[0].startswith("EXPIRED")
    assert s.status_lines([]) == ["no session certificate in the agent"]


needs_openssh = pytest.mark.skipif(shutil.which("ssh-keygen") is None or shutil.which("ssh-agent") is None,
                                   reason="openssh not on PATH")


@needs_openssh
def test_mint_local_against_a_software_ca(tmp_path, monkeypatch):
    # A short socket path: unix sockets cap around 104 bytes.
    sock_dir = Path(tempfile.mkdtemp(prefix="t0", dir="/tmp"))
    try:
        ca = tmp_path / "ca"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(ca)], check=True)
        agent = subprocess.run(["ssh-agent", "-a", str(sock_dir / "s")], capture_output=True, text=True, check=True).stdout
        pid = [l for l in agent.splitlines() if "SSH_AGENT_PID" in l][0].split("=")[1].split(";")[0]
        monkeypatch.setenv("SSH_AUTH_SOCK", str(sock_dir / "s"))
        monkeypatch.setenv("USER", "tester")
        try:
            minted = s.mint_local(["prod", "root"], hours=1, strict=False, ca=ca, user="tester", state_dir=tmp_path / "state", ssh_dir=tmp_path / "dotssh")
            assert [c.principals for c in minted] == [("tester-prod", "tester-dev"), ("tester-root", "tester-prod", "tester-dev")]
            strict = s.mint_local(["root"], hours=1, strict=True, ca=ca, user="tester", state_dir=tmp_path / "state", ssh_dir=tmp_path / "dotssh")
            assert (tmp_path / "dotssh" / "session-root.pub").exists() and (tmp_path / "dotssh" / "session-root-cert.pub").exists()
            assert not (tmp_path / "dotssh" / "session-root").exists()  # never a private key
            assert (tmp_path / "dotssh" / "session.pub").exists() and (tmp_path / "dotssh" / "session-cert.pub").exists()
            assert strict[0].principals == ("tester-root",)
            held = s.agent_certificates()
            # root covers the prod session minted with it, so prod was retired; the strict one stays
            assert sorted(c.principals for c in held) == [("tester-root",), ("tester-root", "tester-prod", "tester-dev")]
            assert all(len(l) > 0 for l in s.status_lines(held))
            # no key material left behind
            assert list((tmp_path / "state").glob("mint.*")) == []
        finally:
            subprocess.run(["kill", pid], check=False)
    finally:
        shutil.rmtree(sock_dir, ignore_errors=True)


# --- git-hosting key -------------------------------------------------------

from ssh_session import gitkey as gk


def test_passphrase_is_long_and_random():
    a, b = gk.new_passphrase(), gk.new_passphrase()
    assert a != b and len(a) >= 50 and a.isupper() or a.isalnum()


@needs_openssh
def test_enroll_and_load_into_a_private_agent(tmp_path, monkeypatch):
    sock_dir = Path(tempfile.mkdtemp(prefix="t0g", dir="/tmp"))
    try:
        store = gk.DictStore()
        key = tmp_path / "id_ed25519_git"
        pub = gk.enroll(key, store, "tester git")
        assert pub.exists() and store.get(gk.account_for(key))
        # the private key is really passphrase-protected: no-passphrase read fails
        r = subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", str(key)], capture_output=True)
        assert r.returncode != 0
        agent = subprocess.run(["ssh-agent", "-a", str(sock_dir / "s")], capture_output=True, text=True, check=True).stdout
        pid = [l for l in agent.splitlines() if "SSH_AGENT_PID" in l][0].split("=")[1].split(";")[0]
        monkeypatch.setenv("SSH_AUTH_SOCK", str(sock_dir / "s"))
        try:
            assert not gk.loaded(key)
            gk.load(key, 1, store, tmp_path / "state")
            assert gk.loaded(key)
            # the askpass helper contains no secret
            assert "SSH_SESSION_GITKEY_PASSPHRASE" in (tmp_path / "state" / "gitkey-askpass").read_text()
            assert store.get(gk.account_for(key)) not in (tmp_path / "state" / "gitkey-askpass").read_text()
        finally:
            subprocess.run(["kill", pid], check=False)
    finally:
        shutil.rmtree(sock_dir, ignore_errors=True)


def test_load_without_passphrase_is_an_error(tmp_path):
    key = tmp_path / "k"; key.write_text("x")
    with pytest.raises(gk.GitKeyError):
        gk.load(key, 1, gk.DictStore(), tmp_path / "state")


def test_choose_ca_picks_the_plugged_in_enrolled_key(tmp_path):
    (tmp_path / "id_ed25519_sk_accur8.pub").write_text("sk-ssh-ed25519@openssh.com AAAA ada@yubikey-11111111\n")
    (tmp_path / "id_ed25519_sk_accur8_backup.pub").write_text("sk-ssh-ed25519@openssh.com BBBB ada-yubikey-22222222\n")
    (tmp_path / "id_ed25519_sk_accur8.pub.touch-only").write_text("ignored\n")
    h = s.ca_handles(tmp_path)
    assert h == {"11111111": tmp_path / "id_ed25519_sk_accur8", "22222222": tmp_path / "id_ed25519_sk_accur8_backup"}
    assert s.choose_ca(h, ["22222222"]) == tmp_path / "id_ed25519_sk_accur8_backup"
    assert s.choose_ca(h, ["11111111", "99999999"]) == tmp_path / "id_ed25519_sk_accur8"
    for serials, msg in (([], "no YubiKey"), (["99999999"], "not an enrolled"), (["11111111", "22222222"], "more than one")):
        with pytest.raises(s.SessionError, match=msg):
            s.choose_ca(h, serials)


@needs_openssh
def test_a_new_session_retires_the_ones_it_covers(tmp_path, monkeypatch):
    sock_dir = Path(tempfile.mkdtemp(prefix="t0r", dir="/tmp"))
    try:
        ca = tmp_path / "ca"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(ca)], check=True)
        other = tmp_path / "other"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "ada git", "-f", str(other)], check=True)
        agent = subprocess.run(["ssh-agent", "-a", str(sock_dir / "s")], capture_output=True, text=True, check=True).stdout
        pid = [l for l in agent.splitlines() if "SSH_AGENT_PID" in l][0].split("=")[1].split(";")[0]
        monkeypatch.setenv("SSH_AUTH_SOCK", str(sock_dir / "s"))
        monkeypatch.setattr(s, "_me", lambda: "tester@box")
        try:
            subprocess.run(["ssh-add", "-q", str(other)], check=True)
            s.mint_local(["dev"], hours=1, strict=False, ca=ca, user="tester", state_dir=tmp_path / "st", ssh_dir=tmp_path / "dotssh")
            s.mint_local(["prod"], hours=1, strict=False, ca=ca, user="tester", state_dir=tmp_path / "st", ssh_dir=tmp_path / "dotssh")
            # prod covers dev: one session left, plus the unrelated key
            held = subprocess.run(["ssh-add", "-L"], capture_output=True, text=True).stdout.splitlines()
            assert len(held) == 3, held
            assert [c.principals for c in s.agent_certificates()] == [("tester-prod", "tester-dev")]
            # a strict dev session does NOT retire the prod one
            s.mint_local(["dev"], hours=1, strict=True, ca=ca, user="tester", state_dir=tmp_path / "st", ssh_dir=tmp_path / "dotssh")
            assert sorted(c.principals for c in s.agent_certificates()) == [("tester-dev",), ("tester-prod", "tester-dev")]
            assert any("ada git" in l for l in subprocess.run(["ssh-add", "-L"], capture_output=True, text=True).stdout.splitlines())
        finally:
            subprocess.run(["kill", pid], check=False)
    finally:
        shutil.rmtree(sock_dir, ignore_errors=True)


def test_covered_roles_follow_nesting():
    assert s.covered_roles("root") == ["prod", "dev"]
    assert s.covered_roles("prod") == ["dev"]
    assert s.covered_roles("dev") == []


def test_a_locked_keychain_says_how_to_unlock(monkeypatch):
    locked = subprocess.CompletedProcess([], 51, "", "security: SecKeychainItemCreateFromContent (<default>): User interaction is not allowed.\n")
    monkeypatch.setattr(gk.KeychainStore, "_security", staticmethod(lambda args: locked))
    for call in (lambda: gk.KeychainStore().set("a", "b"), lambda: gk.KeychainStore().get("a")):
        with pytest.raises(gk.GitKeyError, match="security unlock-keychain"):
            call()
