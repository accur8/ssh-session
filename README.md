# ssh-session

One command for the day's ssh session: a short-lived session certificate and
the git key, loaded into the ssh-agent.

    ssh-session                  today's session certificate and the git key, into the agent
    ssh-session --role root      a root session (YubiKey)
    ssh-session status           what the agent holds, and until when
    ssh-session gitkey load      the git key alone into the agent (no YubiKey)
    ssh-session gitkey enroll    make this machine's git key, once
    ssh-session --host H         a certificate for another machine's own key (YubiKey)

## Getting started

You need [nix](https://nixos.org/download) with flakes. On Windows, everything
below runs inside WSL, not in PowerShell.

**1. Install.** In a terminal:

    curl -fsSL https://raw.githubusercontent.com/accur8/ssh-session/main/install.sh | bash

It links `~/bin/ssh-session` and ends with a report of what it found. If it
says `~/bin` is not on your PATH, add it in your shell's startup file and open
a new terminal. Run it again any time to update.

**2. Which kind are you?** Run `ssh-session status`. Its last line says who
would sign your session:

- `signer: the admin CA on YubiKey NNNN`: you are an **admin**. Go to 3a.
- `signer: the account CA service`: you are a **developer**. Go to 3b.

You never choose: an admin is someone whose YubiKey was enrolled as an admin CA
in a ceremony with another admin, which left `~/.ssh/id_ed25519_sk_accur8*`
files on their machine. Everyone else is a developer.

**3a. Admin, once:**

- On a Mac, make your git key: `ssh-session gitkey enroll`. Add the public key
  it prints to gitea and GitHub.

**3b. Developer, once:**

- You need an ssh key. If `~/.ssh/id_ed25519.pub` (or `id_ecdsa.pub`, or
  `id_rsa.pub`) does not exist, make one: `ssh-keygen -t ed25519`. Give it a
  passphrase.
- Send the **public** key (the `.pub` file, never the other one) to an admin.
  They enrol it on the account CA with the principals you may be issued.
- You must be on the accur8 network (the VPN) to reach `ca.intra`.

**4. Every morning:**

    ssh-session                 # developer: 12 hours
    ssh-session --role root     # admin: PIN, then touch the YubiKey; 4 hours

That loads a short-lived certificate (and, on a Mac with one, the git key) into
your ssh-agent. When it expires, run it again. `ssh-session status` shows what
you hold and for how long.

### Windows (WSL)

- WSL cannot see a USB device until Windows hands it over. For a YubiKey,
  install [usbipd-win](https://github.com/dorssel/usbipd-win), then in an
  administrator PowerShell: `usbipd list`, find the YubiKey's BUSID, and
  `usbipd bind --busid BUSID` (once) and `usbipd attach --wsl --busid BUSID`
  (after each replug or reboot). Without that, ssh-session acts as for a
  developer.
- WSL gets no git key from ssh-session: its passphrase is kept in the macOS
  Keychain.

### For admins: enrolling a developer

The developer's public key goes on `sign@ca.intra` as a forced command naming
their principals, through ssh-key-custodian:

    key_options: ['command="account-ca-sign NAME-dev"', 'restrict']

Push it as any other custodian change. From then on `ssh-session` on their
machine is all they run.

## Who signs

Decided by what is present; there is no flag for it.

- **An enrolled YubiKey is plugged in.** A fresh key pair is signed by the
  admin CA on the YubiKey (PIN and touch) and loaded into the agent for 4
  hours. The private half is on disk only between generation and `ssh-add`.
  `--role dev|prod|root` picks the role; a certificate also carries the roles
  below it unless `--strict`. Root is never implied.
- **Otherwise.** The account CA service (`sign@ca.intra`) certifies your own
  key, a key an admin enrolled there once: the first of `~/.ssh/id_ed25519`,
  `id_ecdsa`, `id_rsa` that exists, the order ssh itself tries. The certificate is
  written beside the key and both are loaded into the agent until it expires
  (12 hours). The service decides the principals.

Either way the git key (`~/.ssh/id_ed25519_git`, when this machine has one) is
loaded for the same hours.

## The git key

A passphrase-protected key file for git hosting. Its passphrase is 256 random
bits nobody types, kept in the macOS login Keychain; outside the agent's
window the file is inert. `ssh-session gitkey enroll` makes it and prints the
public key to add to the git hosts. `ssh-session gitkey load` loads it on its
own; `ssh-add` on the file cannot work, because nobody knows the passphrase.

## Use from another flake

    inputs.ssh-session.url = "github:accur8/ssh-session";
    # with your own nixpkgs:
    pkgs.callPackage inputs.ssh-session.lib.package { }

## Tests

They run in the package build (`nix build`): minting against a throwaway
software CA and a stub account CA service, into a private ssh-agent.
