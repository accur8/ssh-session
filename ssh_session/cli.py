"""ssh-session: one command for the day's ssh session.

\b
    ssh-session                  today's session certificate and the git key, into the agent
    ssh-session --role root      a root session (YubiKey)
    ssh-session status           what the agent holds, and until when
    ssh-session gitkey load      the git key alone into the agent (no YubiKey)
    ssh-session gitkey enroll    make this machine's git key, once
    ssh-session --host H         a certificate for another machine's own key (YubiKey)

Who signs is decided by what is present. An enrolled YubiKey plugged in signs a
fresh key pair with the admin CA on it (PIN and touch); the private half is on
disk only until ssh-add. Otherwise the account CA service certifies your own
key (~/.ssh/id_ed25519, id_ecdsa or id_rsa, the first that exists). Either way
the git key is loaded for the same hours.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import click

from . import accountca
from . import gitkey as gk
from . import session as s

STATE_DIR = Path.home() / ".local" / "state" / "ssh-session"
HELP = {"help_option_names": ["-h", "--help"]}


def yubikey_ca(ca: Path | None) -> Path | None:
    """The admin CA handle to sign with, or None when no enrolled YubiKey is
    plugged in. Two enrolled keys plugged in at once is an error."""
    if ca:
        return ca
    handles, serials = s.ca_handles(), s.plugged_serials()
    if not [n for n in serials if n in handles]:
        return None
    return s.choose_ca(handles, serials)


def signer_line() -> str:
    """Who would sign a session started now."""
    handles, serials = s.ca_handles(), s.plugged_serials()
    enrolled = [n for n in serials if n in handles]
    if enrolled:
        return f"signer:  the admin CA on YubiKey {', '.join(enrolled)}"
    if serials:
        return (f"signer:  the account CA service ({accountca.SERVICE}); YubiKey {', '.join(serials)} "
                f"is plugged in but is not an enrolled admin CA")
    return f"signer:  the account CA service ({accountca.SERVICE}); no YubiKey is plugged in"


def load_git_key(hours: int, no_git: bool) -> None:
    if no_git or not gk.DEFAULT_KEY.exists():
        return
    gk.load(gk.DEFAULT_KEY, hours, gk.KeychainStore(), STATE_DIR)
    click.echo(f"git key loaded for {hours}h")


@click.group(invoke_without_command=True, context_settings=HELP, help=__doc__)
@click.option("--role", "roles", multiple=True, type=click.Choice(list(s.ROLES)),
              help="YubiKey: which role certificate to mint: dev (default), prod, root. Repeatable; root is never implied.")
@click.option("--hours", type=int, default=None,
              help="Lifetime in hours (default 4 with a YubiKey, 2 for --host, 12 from the account CA).")
@click.option("--strict", is_flag=True, help="YubiKey: the one role only; by default a certificate also carries the roles below it.")
@click.option("--ca", type=click.Path(path_type=Path), default=None,
              help="YubiKey: the admin CA handle (default: the one whose YubiKey is plugged in).")
@click.option("--host", default=None, help="YubiKey: mint for another machine: its own key pair gets the certificate as a file.")
@click.option("--user", "remote_user", default=os.environ.get("USER", "unknown"), show_default="you", help="Account on --host.")
@click.option("--key", default=".ssh/id_accur8", show_default=True, help="Key path on --host, relative to the account's home.")
@click.option("--no-git", is_flag=True, help="Do not load the git key into the agent alongside the session.")
@click.pass_context
def main(ctx, roles, hours, strict, ca, host, remote_user, key, no_git):
    if ctx.invoked_subcommand is not None:
        return
    try:
        ca = yubikey_ca(ca)
        if ca is None:
            if roles or strict or host:
                raise s.SessionError("--role, --strict and --host need the admin CA on a YubiKey, and no enrolled one is plugged in")
            h = hours or accountca.DEFAULT_HOURS
            accountca.mint(hours=h)
            load_git_key(h, no_git)
            return
        roles = list(roles) or ["dev"]
        user = os.environ.get("USER", "unknown")
        if host:
            if len(roles) != 1:
                raise s.SessionError("one --role per remote machine (its certificate is one file)")
            s.mint_remote(host, remote_user, key, roles[0], hours=hours or 2, strict=strict, ca=ca, user=user, state_dir=STATE_DIR)
            return
        h = hours or 4
        s.mint_local(roles, hours=h, strict=strict, ca=ca, user=user, state_dir=STATE_DIR)
        load_git_key(h, no_git)
    except (s.SessionError, gk.GitKeyError) as e:
        click.echo(f"ssh-session: {e}", err=True)
        sys.exit(1)


@main.command(context_settings=HELP)
def status():
    """What the agent holds: each session certificate with its principals and
    time left, whether the git key is loaded, and who would sign a session
    started now."""
    try:
        for line in s.status_lines(s.agent_certificates()):
            click.echo(line)
    except s.SessionError as e:
        click.echo(f"ssh-session: {e}", err=True)
        sys.exit(1)
    click.echo(f"git key: {'loaded' if gk.loaded(gk.DEFAULT_KEY) else 'not loaded'}")
    click.echo(signer_line())


@main.group(context_settings=HELP)
def gitkey():
    """The git key: a passphrase-protected key file for gitea and github, loaded
    into the agent by every ssh-session run. Its passphrase is random, kept in
    the login Keychain, and never typed."""


@gitkey.command(context_settings=HELP)
@click.option("--comment", default=f"{os.environ.get('USER', 'user')} git", show_default=True)
def enroll(comment):
    """Make this machine's git key, once. Prints the public key to add to gitea and github."""
    try:
        pub = gk.enroll(gk.DEFAULT_KEY, gk.KeychainStore(), comment)
    except (gk.GitKeyError, subprocess.CalledProcessError) as e:
        click.echo(f"ssh-session: {e}", err=True)
        sys.exit(1)
    click.echo(f"git key made at {gk.DEFAULT_KEY}; add this public key to gitea and github:")
    click.echo(pub.read_text().strip())


@gitkey.command(context_settings=HELP)
@click.option("--hours", type=int, default=4, show_default=True)
def load(hours):
    """Load the git key alone into the agent for HOURS: its passphrase comes
    from the Keychain, so there is no PIN and no touch. Every ssh-session run
    does this already; this is for when only the git key has lapsed."""
    try:
        gk.load(gk.DEFAULT_KEY, hours, gk.KeychainStore(), STATE_DIR)
    except gk.GitKeyError as e:
        click.echo(f"ssh-session: {e}", err=True)
        sys.exit(1)
    click.echo(f"git key loaded for {hours}h")
