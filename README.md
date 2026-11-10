# ssh-session

One command for the day's ssh session: a short-lived session certificate and
the git key, loaded into the ssh-agent.

    ssh-session                  today's session certificate and the git key, into the agent
    ssh-session --role root      a root session (YubiKey)
    ssh-session status           what the agent holds, and until when
    ssh-session gitkey enroll    make this machine's git key, once
    ssh-session --host H         a certificate for another machine's own key (YubiKey)

On a machine with nothing but nix:

    nix run github:accur8/ssh-session

## Who signs

Decided by what is present; there is no flag for it.

- **An enrolled YubiKey is plugged in.** A fresh key pair is signed by the
  admin CA on the YubiKey (PIN and touch) and loaded into the agent for 4
  hours. The private half is on disk only between generation and `ssh-add`.
  `--role dev|prod|root` picks the role; a certificate also carries the roles
  below it unless `--strict`. Root is never implied.
- **Otherwise.** The account CA service (`sign@ca.intra`) certifies
  `~/.ssh/id_ed25519`, a key an admin enrolled there once. The certificate is
  written beside the key and both are loaded into the agent until it expires
  (12 hours). The service decides the principals.

Either way the git key (`~/.ssh/id_ed25519_git`, when this machine has one) is
loaded for the same hours.

## The git key

A passphrase-protected key file for git hosting. Its passphrase is 256 random
bits nobody types, kept in the macOS login Keychain; outside the agent's
window the file is inert. `ssh-session gitkey enroll` makes it and prints the
public key to add to the git hosts.

## Use from another flake

    inputs.ssh-session.url = "github:accur8/ssh-session";
    # with your own nixpkgs:
    pkgs.callPackage inputs.ssh-session.lib.package { }

## Tests

They run in the package build (`nix build`): minting against a throwaway
software CA and a stub account CA service, into a private ssh-agent.
