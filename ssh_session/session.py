"""Short-lived ssh session certificates signed by the admin CA on a YubiKey:
the signer ssh-session uses when an enrolled YubiKey is plugged in. Without
one, accountca.py asks the account CA service instead.

Roles are dev, prod and root. A certificate's principals are USER-ROLE for the
role and, unless strict, for every role below it; host authorized_keys lines
are always strict (one account class, one principal), so nesting is purely the
client's choice. Root is never implied: dev is the default.

Three destinations:
  local   a fresh key pair into the ssh-agent with its certificate, for N hours;
          the private half exists on disk only between generation and ssh-add.
  remote  another machine's own key pair (made there on first use) gets the
          certificate as a file beside the key, over the ssh session you have.
  remote agent
          a machine that opted in with the marker file AGENT_MARKER makes a
          fresh key pair and loads the key and certificate into its own agent;
          the private half never leaves that machine and no key file remains.
"""
from __future__ import annotations

import datetime as dt
import os
import re
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

ROLES: tuple[str, ...] = ("dev", "prod", "root")
BELOW: dict[str, tuple[str, ...]] = {"dev": (), "prod": ("dev",), "root": ("prod", "dev")}
DEFAULT_CA = Path.home() / ".ssh" / "id_ed25519_sk_accur8"
# Relative to the target account's home. The file's presence is the target's
# consent to receive pushed sessions in its agent; its contents are not read.
AGENT_MARKER = ".config/ssh-session/agent-target"
# A forwarded agent on the target would receive the session meant for the
# target's own agent, so a push never forwards anything.
NO_FORWARDING = ("-T", "-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "ClearAllForwardings=yes",
                 "-o", "ConnectTimeout=10")
# Runs on the target under bash, passed through the login shell (often fish) in
# single quotes, so this text holds no single quote and no backslash. One ssh
# connection spans the signing: when the connection ends for any reason, the
# read fails and the trap removes the private half.
PUSH_SCRIPT = """set -eu
stamp=$1; hours=$2; role=$3; via=$4
export SSH_AUTH_SOCK="$HOME/.ssh/agent.sock"
rc=0; ssh-add -l >/dev/null 2>&1 </dev/null || rc=$?
if [ "$rc" -ge 2 ]; then echo "no ssh-agent answers on $SSH_AUTH_SOCK" >&2; exit 3; fi
d=$(mktemp -d "$HOME/.ssh/.session-push.XXXXXX")
cleanup() { rm -rf "$d"; }
trap cleanup EXIT
trap "exit 1" HUP INT TERM PIPE
me="$(id -un)@$(hostname | cut -d. -f1)"
ssh-keygen -q -t ed25519 -N "" -C "session $me $stamp $role via $via" -f "$d/key" </dev/null
echo "$me"
cat "$d/key.pub"
ssh-add -L 2>/dev/null </dev/null | grep -E "^(ssh|ecdsa|sk)-" || true
echo END
IFS= read -r cert
echo "$cert" > "$d/key-cert.pub"
ssh-add -q -t "${hours}H" "$d/key" </dev/null
while IFS= read -r old; do
  [ "$old" = END ] && break
  echo "$old" > "$d/old.pub"
  ssh-add -q -d "$d/old.pub" </dev/null >/dev/null 2>&1 || true
done
for stem in "session-$role" session; do
  for ext in .pub -cert.pub; do
    cp "$d/key$ext" "$HOME/.ssh/$stem$ext.tmp"
    chmod 644 "$HOME/.ssh/$stem$ext.tmp"
    mv "$HOME/.ssh/$stem$ext.tmp" "$HOME/.ssh/$stem$ext"
  done
done
echo LOADED
"""


def ca_handles(ssh_dir: Path = Path.home() / ".ssh") -> dict[str, Path]:
    """Admin CA handles by YubiKey serial, read from each handle's public key
    comment (<user>-yubikey-<serial>, written by the enrolment ceremony)."""
    out: dict[str, Path] = {}
    for pub in sorted(ssh_dir.glob("id_ed25519_sk_accur8*.pub")):
        m = re.search(r"yubikey-(\d+)", " ".join(pub.read_text().split()[2:]))
        if m:
            out[m.group(1)] = pub.with_suffix("")
    return out


def plugged_serials(run=subprocess.run) -> list[str]:
    try:
        r = run(["ykman", "list", "--serials"], capture_output=True, text=True)
    except FileNotFoundError:
        return []
    return r.stdout.split() if r.returncode == 0 else []


def choose_ca(handles: dict[str, Path], serials: list[str]) -> Path:
    """The CA handle of the one plugged-in YubiKey that is an admin CA.
    Convention, no flag needed: whichever enrolled key is in the port signs."""
    present = [handles[s] for s in serials if s in handles]
    if len(present) == 1:
        return present[0]
    if not serials:
        raise SessionError("no YubiKey is plugged in")
    if not present:
        raise SessionError(f"the plugged-in YubiKey ({', '.join(serials)}) is not an enrolled admin CA "
                           f"(enrolled: {', '.join(sorted(handles)) or 'none'})")
    raise SessionError("more than one enrolled YubiKey is plugged in; unplug one or pass --ca")


class SessionError(Exception):
    pass


def principals_for(user: str, role: str, strict: bool) -> str:
    """The certificate's principal list for ROLE: the role alone when strict,
    else the role followed by every role below it."""
    if role not in ROLES:
        raise SessionError(f"unknown role {role!r} (dev, prod, root)")
    names = (role,) + (() if strict else BELOW[role])
    return ",".join(f"{user}-{r}" for r in names)


@dataclass(frozen=True)
class Certificate:
    key_id: str
    principals: tuple[str, ...]
    valid_to: dt.datetime  # naive, local time as ssh-keygen prints it

    @classmethod
    def parse(cls, listing: str) -> "Certificate":
        """Parse `ssh-keygen -L` output for one certificate."""
        m_id = re.search(r'Key ID: "(.*)"', listing)
        m_valid = re.search(r"Valid: from \S+ to (\S+)", listing)
        if not (m_id and m_valid):
            raise SessionError("not a certificate listing")
        principals: list[str] = []
        in_principals = False
        for line in listing.splitlines():
            if line.strip().startswith("Principals:"):
                in_principals = True
                continue
            if in_principals:
                if line.startswith(" " * 16) and line.strip():
                    principals.append(line.strip())
                else:
                    break
        valid_to = dt.datetime.strptime(m_valid.group(1), "%Y-%m-%dT%H:%M:%S")
        return cls(m_id.group(1), tuple(principals), valid_to)

    def minutes_left(self, now: dt.datetime | None = None) -> int:
        now = now or dt.datetime.now()
        return int((self.valid_to - now).total_seconds() // 60)


def _run(cmd: Sequence[str], *, input: bytes | None = None, capture: bool = True) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(list(cmd), input=input, check=True, capture_output=capture)
    except FileNotFoundError as e:
        raise SessionError(f"{cmd[0]} not found on PATH: {e}") from e
    except subprocess.CalledProcessError as e:
        err = (e.stderr or b"").decode(errors="replace").strip()
        raise SessionError(f"{' '.join(cmd[:2])} failed: {err or e}") from e


def keygen_listing(cert_path: Path) -> str:
    return _run(["ssh-keygen", "-Lf", str(cert_path)]).stdout.decode()


def sign(ca: Path, pub: Path, key_id: str, principals: str, hours: int) -> Path:
    """Sign PUB with the admin CA (PIN and touch happen here). Returns the
    certificate path ssh-keygen wrote beside PUB."""
    if not ca.exists():
        raise SessionError(f"no admin CA handle at {ca} (run the YubiKey ceremony, or --ca PATH)")
    _run(
        ["ssh-keygen", "-q", "-s", str(ca), "-I", key_id, "-n", principals,
         "-V", f"+{hours}h", "-z", str(int(time.time())), str(pub)],
        capture=False,
    )
    return pub.with_name(pub.name[: -len(".pub")] + "-cert.pub")


def _stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _me() -> str:
    return f"{os.environ.get('USER', 'unknown')}@{socket.gethostname().split('.')[0]}"


def covered_roles(role: str) -> list[str]:
    """The roles a non-strict certificate for ROLE also carries."""
    return [r for r in principals_for("x", role, False).replace("x-", "").split(",") if r != role]


def publish_session(role: str, pub: Path, cert: Path, ssh_dir: Path) -> Path:
    """Write the session's PUBLIC key and certificate to stable paths,
    ~/.ssh/session-<role>.pub and ~/.ssh/session-<role>-cert.pub. A host
    stanza with `IdentityFile ~/.ssh/session-<role>` and `IdentitiesOnly yes`
    then offers exactly this session (ssh matches the private half in the
    agent and loads the certificate beside it), so the agent's other keys never
    count against a server's MaxAuthTries. No private key is written."""
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    stem = ssh_dir / (f"session-{role}" if role else "session")
    for src, dst in ((pub, Path(f"{stem}.pub")), (cert, Path(f"{stem}-cert.pub"))):
        tmp = dst.with_name(dst.name + ".tmp")
        shutil.copyfile(src, tmp)
        tmp.chmod(0o644)
        tmp.replace(dst)
    return stem


def mint_local(roles: Iterable[str], *, hours: int, strict: bool, ca: Path, user: str, state_dir: Path,
               ssh_dir: Path = Path.home() / ".ssh") -> list[Certificate]:
    """One certificate per role into the agent. The key file lives only inside
    this call, in a 0700 directory, and is removed before returning."""
    state_dir.mkdir(parents=True, exist_ok=True)
    state_dir.chmod(0o700)
    minted: list[Certificate] = []
    tmp = Path(tempfile.mkdtemp(prefix="mint.", dir=state_dir))
    try:
        for role in roles:
            principals = principals_for(user, role, strict)
            stamp = _stamp()
            key = tmp / role
            _run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"session {_me()} {stamp} {role}", "-f", str(key)])
            print(f"signing {role} ({principals}) for {hours}h with the admin CA: enter the YubiKey PIN, then touch it", flush=True)
            cert = sign(ca, key.with_suffix(".pub"), f"{_me()} {stamp} {role}", principals, hours)
            gone = retire_covered_sessions(principals.split(","), _me())
            if gone:
                print(f"retired {gone} earlier session(s) this one covers", flush=True)
            _run(["ssh-add", "-q", "-t", f"{hours}H", str(key)], capture=False)
            # session-<role> for stanzas that need one role (the backdoor630
            # jump wants root), and plain `session` for the latest mint, which
            # the fleet stanza names: one file, so ssh never offers a duplicate.
            publish_session(role, key.with_suffix(".pub"), cert, ssh_dir)
            publish_session("", key.with_suffix(".pub"), cert, ssh_dir)
            c = Certificate.parse(keygen_listing(cert))
            print(f"session loaded: {principals} until {c.valid_to.isoformat()}", flush=True)
            minted.append(c)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return minted


def mint_remote(host: str, remote_user: str, key: str, role: str, *, hours: int, strict: bool, ca: Path, user: str, state_dir: Path) -> Certificate:
    """Sign HOST's own key pair (made there on first use) and install the
    certificate beside it. The private half never leaves HOST."""
    principals = principals_for(user, role, strict)
    state_dir.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="remote.", dir=state_dir))
    try:
        target = f"{remote_user}@{host}"
        fetch = (f"test -f '{key}' || ssh-keygen -q -t ed25519 -N '' -C '{target} accur8 session key' -f '{key}'; "
                 f"cat '{key}.pub'")
        pub = tmp / "remote.pub"
        pub.write_bytes(_run(["ssh", target, fetch]).stdout)
        _run(["ssh-keygen", "-lf", str(pub)])
        stamp = _stamp()
        print(f"signing {role} ({principals}) for {target}, {hours}h, with the admin CA: enter the YubiKey PIN, then touch it", flush=True)
        cert = sign(ca, pub, f"{target} {stamp} {role} via {_me()}", principals, hours)
        _run(["ssh", target, f"cat > '{key}-cert.pub'"], input=cert.read_bytes())
        c = Certificate.parse(keygen_listing(cert))
        print(f"installed on {host} as {key}-cert.pub: {principals} until {c.valid_to.isoformat()}", flush=True)
        return c
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def target_takes_agent(host: str, remote_user: str) -> bool:
    """Whether HOST's account opted in to pushed sessions (AGENT_MARKER)."""
    out = _run(["ssh", *NO_FORWARDING, f"{remote_user}@{host}",
                f"test -f {AGENT_MARKER} && echo agent || echo file"]).stdout.decode().split()
    return bool(out) and out[-1] == "agent"


def mint_remote_agent(host: str, remote_user: str, role: str, *, hours: int, strict: bool, ca: Path, user: str, state_dir: Path) -> Certificate:
    """Sign a key pair HOST makes for this push and load both halves into HOST's
    own agent. A dead agent on HOST is an error before the YubiKey is asked."""
    principals = principals_for(user, role, strict)
    state_dir.mkdir(parents=True, exist_ok=True)
    target = f"{remote_user}@{host}"
    stamp = _stamp()
    command = " ".join(["bash -c", shlex.quote(PUSH_SCRIPT), "ssh-session",
                        shlex.quote(stamp), str(hours), shlex.quote(role), shlex.quote(_me())])
    tmp = Path(tempfile.mkdtemp(prefix="remote.", dir=state_dir))
    with tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(["ssh", *NO_FORWARDING, target, command],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err)
        assert proc.stdin is not None and proc.stdout is not None

        def failure(what: str) -> SessionError:
            proc.wait()
            err.seek(0)
            return SessionError(f"{what} on {target}: {err.read().decode(errors='replace').strip() or 'no detail'}")

        try:
            lines: list[str] = []
            while True:
                raw = proc.stdout.readline()
                if not raw:
                    raise failure("could not start the push")
                line = raw.decode().strip()
                if line == "END":
                    break
                lines.append(line)
            if len(lines) < 2:
                raise failure("unexpected reply")
            target_me, pub_line, held = lines[0], lines[1], lines[2:]
            pub = tmp / "remote.pub"
            pub.write_text(pub_line + "\n")
            _run(["ssh-keygen", "-lf", str(pub)])
            print(f"signing {role} ({principals}) for {target}'s agent, {hours}h, with the admin CA: enter the YubiKey PIN, then touch it", flush=True)
            cert = sign(ca, pub, f"{target_me} {stamp} {role} via {_me()}", principals, hours)
            retired = covered_session_pairs(held, principals.split(","), target_me)
            reply = cert.read_text().strip() + "\n" + "".join(l + "\n" for pair in retired for l in pair) + "END\n"
            try:
                proc.stdin.write(reply.encode())
                proc.stdin.close()
            except BrokenPipeError:
                raise failure("the connection ended before the certificate arrived") from None
            done = proc.stdout.read().decode()
            if proc.wait() != 0 or "LOADED" not in done.split():
                raise failure("could not load the session")
            c = Certificate.parse(keygen_listing(cert))
            if retired:
                print(f"retired {len(retired)} earlier session(s) on {host} this one covers", flush=True)
            print(f"session loaded into {host}'s agent: {principals} until {c.valid_to.isoformat()}", flush=True)
            return c
        finally:
            if proc.poll() is None:
                try:
                    proc.stdin.close()
                except OSError:
                    pass
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            shutil.rmtree(tmp, ignore_errors=True)


def agent_certificates() -> list[Certificate]:
    """Every certificate the agent holds."""
    out = subprocess.run(["ssh-add", "-L"], capture_output=True, text=True)
    certs: list[Certificate] = []
    if out.returncode != 0:
        return certs
    with tempfile.TemporaryDirectory() as d:
        for line in out.stdout.splitlines():
            if "-cert-v01@openssh.com" not in line:
                continue
            p = Path(d) / "cert.pub"
            p.write_text(line + "\n")
            certs.append(Certificate.parse(keygen_listing(p)))
    return certs


def retire_covered_sessions(principals: Iterable[str], me: str) -> int:
    """Remove from the agent every earlier session of ME whose principals the
    new certificate covers (a root session covers dev and prod ones). A session
    is a plain key plus its certificate, both with a comment starting
    "session <me> "; each extra pair is two more keys ssh offers before the one
    that works, and hosts disconnect after MaxAuthTries (6 by default). Keys
    that are not sessions (the git key, anything else) are never touched."""
    out = subprocess.run(["ssh-add", "-L"], capture_output=True, text=True)
    if out.returncode != 0:
        return 0
    pairs = covered_session_pairs(out.stdout.splitlines(), principals, me)
    with tempfile.TemporaryDirectory() as d:
        for pair in pairs:
            for i, pub in enumerate(pair):
                f = Path(d) / f"del{i}.pub"
                f.write_text(pub + "\n")
                subprocess.run(["ssh-add", "-q", "-d", str(f)], capture_output=True)
    return len(pairs)


def covered_session_pairs(lines: Sequence[str], principals: Iterable[str], me: str) -> list[list[str]]:
    """From an agent listing, each earlier session of ME whose principals are
    covered: its certificate line and, when present, its plain key line."""
    want = set(principals)
    pairs: list[list[str]] = []
    with tempfile.TemporaryDirectory() as d:
        for line in lines:
            parts = line.split(None, 2)
            if len(parts) < 3 or "-cert-v01@openssh.com" not in parts[0] or not parts[2].startswith(f"session {me} "):
                continue
            cp = Path(d) / "c.pub"
            cp.write_text(line + "\n")
            if not set(Certificate.parse(keygen_listing(cp)).principals) <= want:
                continue
            # the plain key: same comment, a plain key type
            plain = next((l for l in lines if l.split(None, 2)[2:] == [parts[2]] and "-cert-v01@" not in l.split()[0]), None)
            pairs.append([x for x in (line, plain) if x])
    return pairs


def status_lines(certs: Iterable[Certificate], now: dt.datetime | None = None) -> list[str]:
    lines = []
    for c in certs:
        left = c.minutes_left(now)
        who = f"{c.key_id}  [{','.join(c.principals)}]"
        if left <= 0:
            lines.append(f"EXPIRED  {who}")
        elif left < 60:
            lines.append(f"WARNING  {who}  {left} min left; start a new session before a long run")
        else:
            lines.append(f"ok       {who}  {left // 60}h{left % 60:02d}m left")
    return lines or ["no session certificate in the agent"]
